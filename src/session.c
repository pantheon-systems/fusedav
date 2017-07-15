/***
  This file is part of fusedav.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

#include <curl/curl.h>
#include <netdb.h>

// Included to eventually use res_query() for lookups and failover.
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <uriparser/Uri.h>

#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "session.h"
#include "fusedav-statsd.h"

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

pthread_mutex_t saint_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static state_t saint_state = STATE_HEALTHY;

pthread_mutex_t request_outstanding = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static int request_outstanding_lock_count = 0;

const int time_limit = 30 * 1000; // 30 seconds

void (*const state_table [NUM_STATES][NUM_EVENTS]) (void) = {
    { action_s1_e1, action_s1_e2, action_s1_e3 }, /* procedures for state 1 */
    { action_s2_e1, action_s2_e2, action_s2_e3 }, /* procedures for state 2 */
    { action_s3_e1, action_s3_e2, action_s3_e3 }  /* procedures for state 3 */
};

// The string we pass to curl is domain:port:ip:address, so leave room
#define IPSTR_SZ 128
// Maximum number of A records (bzw IP addresses) our domain can resolve to
#define MAX_NODES 32

// Grab the node address out of the curl message and keep track for later logging
#define LOGSTRSZ 80
static __thread char nodeaddr[LOGSTRSZ];

// Capture errors and make them available
static __thread char curl_errbuf[CURL_ERROR_SIZE];

// status of a node in a cluster
static const unsigned int HEALTHY = 0;
static const unsigned int RECOVERING = 1;
static const unsigned int UNHEALTHY = 2;

// We track connection health thread-by-thread. Ultimately all threads 
// should have a similar view of the health of the system. We optimize 
// for short outages, reducing the opportunities for fusedav to think 
// a healthy node is unhealthy. We don't want to take a node out of 
// rotation for long periods of time, so we enter them back into
// rotation frequently. If a node stays degraded for long periods of time, 
// it will get accessed, and if it fails will fall out of rotation again. 
// Since we have a retry mechanism, the operation should succeed on following 
// iterations, so there should be only slight degradation of customer 
// experience. The amount of traffic sent to a degraded node remains small.

// -- We set a node's score to 2 when it fails. All other nodes in a degraded 
// state will have their score decremented. This helps ensure that the node 
// that failed most recently won't find itself at the top of the list for 
// the next iteration.
// -- The resolve slist is updated every 2 minutes. When we do, we mark 
// degraded nodes as ready for rotation.
// -- When we detect a bad connection, we create a new resolve slist and 
// bounce the handle. We sort the list so that healthy connections are at the top
struct health_status_s {
    char curladdr[IPSTR_SZ]; // Keep track of complete string we pass to curl
    unsigned int score;
    time_t timestamp;
    // Did we see this entry on this call to getaddrinfo (or have we deleted a node?)
    bool current; 
};

// This will be the list of randomized addresses we pass to curl 
// (resolve_slist) and the hashtable of health status. Make it thread-local 
// so each session gets its own.

// Assuming that session==thread, but that's what we assume for 
// session_tsd_key above
// Using __thread in preference to pthread_once mechanism; seems simpler and less error-prone
struct node_status_s {
    struct curl_slist *resolve_slist;
    // hashtable containing a health_status_s for each node
    GHashTable *node_hash_table;
};

static __thread struct node_status_s node_status;

struct addr_score_s {
    char addr[IPSTR_SZ];
    unsigned int score;
};

// It needs some value to start, but will be adjusted in call to getaddrinfo
// If one node is unresponsive, we will rescramble the resolve list and
// expect a different node to try the second time. This will clear the thread
// of continuing to target a bad node.
int num_filesystem_server_nodes = 3;
// Keep track of the config parameter grace so we can better manage saint mode
static bool config_grace;

static __thread time_t session_start_time;

static char *ca_certificate = NULL;
static char *client_certificate = NULL;
static char *base_url = NULL;
static char *filesystem_domain = NULL;
static char *filesystem_port = NULL;
static char *filesystem_cluster = NULL;

const char *get_base_url(void) {
    return base_url;
}

const char *get_filesystem_cluster(void) {
    return filesystem_cluster;
}

const char *get_nodeaddr(void) {
    return nodeaddr;
}

int session_config_init(char *base, char *ca_cert, char *client_cert, bool grace) {
    size_t base_len;
    UriParserStateA state;
    UriUriA uri;
    char *firstdot = NULL;

    assert(base);

    if (curl_global_init(CURL_GLOBAL_ALL)) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_config_init: Failed to initialize libcurl.");
        return -1;
    }
    config_grace = grace;

    // Ensure the base URL has no trailing slash.
    base_len = strlen(base);
    base_url = strdup(base);
    if (base[base_len - 1] == '/')
        base_url[base_len - 1] = '\0';

    if (ca_cert != NULL)
        ca_certificate = strdup(ca_cert);

    if (client_cert != NULL) {
        client_certificate = strdup(client_cert);

        // Repair p12 to point to pem for now.
        if (strcmp(client_certificate + strlen(client_certificate) - 4, ".p12") == 0) {
            log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_config_init: Remapping deprecated certificate path: %s", client_certificate);
            strncpy(client_certificate + strlen(client_certificate) - 4, ".pem", 4);
        }

        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_config_init: Using client certificate at path: %s", client_certificate);
    }

    state.uri = &uri;
    if (uriParseUriA(&state, base) != URI_SUCCESS) {
        /* Failure */
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_config_init: error on uriParse on: %s", base);
        uriFreeUriMembersA(&uri);
        return -1;
    }

    filesystem_domain = strndup(uri.hostText.first, uri.hostText.afterLast - uri.hostText.first);
    filesystem_port = strndup(uri.portText.first, uri.portText.afterLast - uri.portText.first);
    firstdot = strchr(uri.hostText.first, '.');
    if (firstdot) {
        filesystem_cluster = strndup(uri.hostText.first, firstdot - uri.hostText.first);
    }
    else {
        /* Failure */
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_config_init: error on uriParse finding cluster name: %s", base);
        asprintf(&filesystem_cluster, "unknown");
    }
    uriFreeUriMembersA(&uri);

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "session_config_init: host (%s) :: port (%s) :: cluster (%s)",
        filesystem_domain, filesystem_port, filesystem_cluster);

    return 0;
}

void session_config_free(void) {
    free(base_url);
    free(ca_certificate);
    free(client_certificate);
}

// Keep a session count for stats gauge
static void update_session_count(bool add) {
    static int current_session_count = 0;

    if (add) __sync_fetch_and_add(&current_session_count, 1);
    else __sync_fetch_and_sub(&current_session_count, 1);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "update_session_count: %d", current_session_count);
    // We atomically update current_session_count, but don't atomically get its value for the stat.
    // That should be ok, it will always at least be a valid value for some point in recent time.
    stats_timer_cluster("sessions", current_session_count);
}

static void print_errors(const int iter, const char *type_str, const char *fcn_name, 
        const CURLcode res, const long response_code, const long elapsed_time, const char *path) {
    char *error_str = NULL;
    bool slow_request = false;

    if (res != CURLE_OK) {
        asprintf(&error_str, "%s :: %s", curl_easy_strerror(res), "no rc");
    } else if (response_code >= 500) {
        asprintf(&error_str, "%s :: %lu", "no curl error", response_code);
    } else if (elapsed_time >= 0) {
        asprintf(&error_str, "%s :: %lu", "slow_request", elapsed_time);
        slow_request = true;
    }

    // Stats log for all errors
    // Distinguish curl from 500-status failures from slow requests
    stats_counter(type_str, 1);
    log_print(LOG_ERR, SECTION_SESSION_DEFAULT,
        "%s: curl iter %d on path %s; %s -- fusedav.%s.server-%s.%s",
        fcn_name, iter, path, error_str, filesystem_cluster, nodeaddr, type_str);

    // Don't treat slow requests as 'failures'; it messes up the failure/recovery stats
    if (!slow_request) {
        char *failure_str = NULL;
        asprintf(&failure_str, "%d_failures", iter + 1);

        // Is this the first, second, or third failure for this request?
        stats_counter(failure_str, 1);

        free(failure_str);

        // Total failures
        stats_counter("failures", 1);
    }

    free(error_str);
}

static struct health_status_s *get_health_status(char *addr) {
    return g_hash_table_lookup(node_status.node_hash_table, addr);
}

/*  return can be:
 *  0 = all healthy
 *  2 = all unhealthy
 *  1 = mismatch, some healthy, some unhealthy
 */
static unsigned int health_status_all_nodes(void) {
    static const char *funcname = "health_status_all_nodes";
    GHashTableIter iter;
    gpointer key, value;
    int idx = 0;
    unsigned int score = HEALTHY;

    g_hash_table_iter_init (&iter, node_status.node_hash_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        struct health_status_s *healthstatus = (struct health_status_s *)value;
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: hash_table [%p], iter [%p], score [%d]",
            funcname, node_status.node_hash_table, iter, healthstatus->score);
        // If this is the first iteration, seed score
        if (idx == 0) {
            score = healthstatus->score;
            ++idx;
        }
        // If we see nodes in different states, return RECOVERING as a marker
        else if (healthstatus->score != score) {
            return RECOVERING;
        }
    }
    return score;
}

static void update_health_status_all_nodes(void) {
    static const char *funcname = "update_health_status_all_nodes";
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, node_status.node_hash_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        struct health_status_s *healthstatus = (struct health_status_s *)value;
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: hash_table [%p], score [%d]",
            funcname, node_status.node_hash_table, healthstatus->score);
        if (healthstatus->score != HEALTHY) {
            --healthstatus->score;
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: addr [%s], score [%d]",
                funcname, healthstatus->curladdr, healthstatus->score);
        }
    }
}

static void increment_node_success(char *addr) {
    struct health_status_s *healthstatus = get_health_status(addr);
    if (!healthstatus) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "increment_node_success: healthstatus null for %s", addr);
        return;
    }
    if (healthstatus->score > HEALTHY) {
        --healthstatus->score;
        healthstatus->timestamp = time(NULL); // Reset since we just used it
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "increment_node_success: %s addr score set to %u",
            addr, healthstatus->score);
    }
}

// Call session_cleanup when reinitializing a handle, or called from session_destroy when thread exits
static void session_cleanup(void *s) {
    CURL *session = s;

    if (!session) return;

    stats_timer_cluster("session-duration", time(NULL) - session_start_time);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Destroying cURL handle");

    curl_easy_cleanup(session);
    session = NULL;
    pthread_setspecific(session_tsd_key, session);
    update_session_count(false);

    // REVIEW: clear list before or after?
    // Free the resolve_slist before exiting the session
    if (node_status.resolve_slist) {
        curl_slist_free_all(node_status.resolve_slist);
        node_status.resolve_slist = NULL;
    }
}

// When a thread exits, we also want to free its hashtable. We don't want to free the hashtable if we are just
// reinitializing the thread, since we want to keep the health status that causes those reinitializations
static void session_destroy(void *s) {
    pthread_mutex_lock(&saint_state_mutex);
    try_release_request_outstanding();
    pthread_mutex_unlock(&saint_state_mutex);
    session_cleanup(s);
    g_hash_table_destroy(node_status.node_hash_table);
}

static void session_tsd_key_init(void) {
    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "session_tsd_key_init()");
    pthread_key_create(&session_tsd_key, session_destroy);
}

// Modify string in place. Replace dot and colon with underscore for logging stats and graphs
// Caller must guarantee that the string is just an ipv4 or ipv6 address. If a curl addr (<fileserver>:<port>:<addr>) is sent in,
// those colons will get wacked. Bad things will happen.
static char * logstr(char *addr) {
    char *scanner;
    for (scanner = addr; *scanner != '\0'; scanner++) {
        if (*scanner == '.' || *scanner == ':') *scanner = '_';
    }
    return addr;
}

/* We want to use the logging facility key=value to keep track of the
 * node ip address we use when we use the filesystem domain. This
 * will help us know that we are accessing the nodes in a balanced way.
 * (We access the filesystem nodes via a domain which resolves to many
 * A records or IP addrs; our mechanism chooses one of those A records (IP addr).
 * We know the address used because we capture the libcurl message
 * "Trying <ip addr>...". Kind of clunky since the message can change. Do
 * we have a better way?
 */
static void print_ipaddr_pair(char *msg) {
    // nodeaddr is global so it can be reused in later logging
    char *end;
    // msg+9 takes us past "  Trying ". We assume the ip addr starts there.
    strncpy(nodeaddr, msg + 9, LOGSTRSZ);
    nodeaddr[LOGSTRSZ - 1] = '\0'; // Just make sure it's null terminated
    // end finds the first two dots after the ip addr. We put a zero there
    // to turn the original string into just the IP addr.
    end = strstr(nodeaddr, "..");
    end[0] = '\0';
    // Change dots in addr to underscore for logging
    logstr(nodeaddr);
    // We print the key=value pair.
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Using filesystem_host=%s", nodeaddr);
}

// Return the contents of the error buffer
const char * curl_errorbuffer(CURLcode res) {
    size_t len = strlen(curl_errbuf);
    if(len) {
        return curl_errbuf;
    } else {
        return curl_easy_strerror(res);
    }
}

static int session_debug(__unused CURL *handle, curl_infotype type, char *data, size_t size, __unused void *userp) {
    if (type == CURLINFO_TEXT) {
        char *msg = malloc(size + 1);
        if (msg != NULL) {
            strncpy(msg, data, size);
            msg[size] = '\0';
            if (msg[size - 1] == '\n') msg[size - 1] = '\0';
            // We want to see the "Trying <ip addr> message, but the others only when in some
            // level of debug
            if (strstr(msg, "Trying")) {
                log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "cURL: %s", msg);
                print_ipaddr_pair(msg);
            }
            else {
                log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "cURL: %s", msg);
            }
            free(msg);
        }
    }
    return 0;
}

/* cluster saint mode means:
 * 1. If in cluster saint mode, back off accessing the cluster for a given period of time
 * 2. If in cluster saint mode, where possible, assume local state is correct.
 * Regarding (2), propfinds should succeed, as should GETs (as if 304).
 *
 * We implement a simple state machine to keep track of saint_state. See the diagram at:
 *     documentation/saint_mode_machine_state.png
 */
// cluster_failure_timestamp is the most recent time we detected that all connections to the cluster were in some failed mode
static time_t failure_timestamp = 0;
// record the the first failure_timestamp in this saint_mode experience
static time_t unhealthy_since_timestamp = 0;
// Backoff time; avoid accessing the cluster for this many seconds
const int saint_mode_duration = 10;
// Affter this many seconds (15 minutes), emit a stat for a long-running saintmode event.
const int saint_mode_warning_threshold = 60*15;


void try_release_request_outstanding(void) {
    if (pthread_mutex_trylock(&request_outstanding) == 0) {
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "Release lock for request_outstanding, lock_count: %d", request_outstanding_lock_count);
        for (int i = 0; i < request_outstanding_lock_count; i++) {
            pthread_mutex_unlock(&request_outstanding);
        }
        request_outstanding_lock_count = 0;
        pthread_mutex_unlock(&request_outstanding);
    }
}

void action_s1_e1(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    failure_timestamp = now.tv_sec;
    unhealthy_since_timestamp = now.tv_sec;
    saint_state = STATE_SAINT_MODE;
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Event CLUSTER_FAILURE; transitioned to STATE_SAINT_MODE from STATE_HEALTHY.");
}
void action_s1_e2 (void) {}
void action_s1_e3 (void) {}
void action_s2_e1 (void) {}
void action_s2_e2 (void) {
    saint_state = STATE_ATTEMPTING_TO_EXIT_SAINT_MODE;
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Event SAINT_MODE_DURATION_EXPIRED; transitioned to STATE_ATTEMPTING_TO_EXIT_SAINT_MODE from STATE_SAINT_MODE.");
}
void action_s2_e3 (void) {}
void action_s3_e1 (void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    failure_timestamp = now.tv_sec;
    try_release_request_outstanding();
    saint_state = STATE_SAINT_MODE;
    stats_counter_cluster("saint_mode", 1);
    log_print(LOG_NOTICE, SECTION_ENHANCED, "Setting cluster saint mode for %lu seconds.", saint_mode_duration);
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Event CLUSTER_FAILURE; transitioned to STATE_SAINT_MODE from STATE_ATTEMPTING_TO_EXIT_SAINT_MODE.");
}
void action_s3_e2 (void) {}
void action_s3_e3 (void) {
    try_release_request_outstanding();
    saint_state = STATE_HEALTHY;
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Event CLUSTER_SUCCESS; transitioned to STATE_HEALTHY from STATE_ATTEMPTING_TO_EXIT_SAINT_MODE.");
}

void trigger_saint_mode_expired_if_needed(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (saint_state == STATE_SAINT_MODE && now.tv_sec >= failure_timestamp + saint_mode_duration) {
        state_table[saint_state][SAINT_MODE_DURATION_EXPIRED]();
        // If we've been in saintmode for longer than saint_mode_warning_threshold, emit a stat saying so.
        if (now.tv_sec >= unhealthy_since_timestamp + saint_mode_warning_threshold) {
            stats_counter_cluster("long_running_saint_mode", 1);
            log_print(LOG_INFO, SECTION_ENHANCED, "saint_mode active for %d seconds", now.tv_sec-unhealthy_since_timestamp);
        }
    }
}

void trigger_saint_event(event_t event) {
    if (!config_grace) return;
    pthread_mutex_lock(&saint_state_mutex);
    trigger_saint_mode_expired_if_needed(); // trigger SAINT_MODE_DURATION_EXPIRED if duration has expired.
    state_table[saint_state][event]();
    pthread_mutex_unlock(&saint_state_mutex);
}

state_t get_saint_state(void) {
    pthread_mutex_lock(&saint_state_mutex);
    trigger_saint_mode_expired_if_needed();
    pthread_mutex_unlock(&saint_state_mutex);
    return saint_state;
}

bool use_saint_mode(void) {
    bool sm = false;
    pthread_mutex_lock(&saint_state_mutex);
    trigger_saint_mode_expired_if_needed();

    if (saint_state == STATE_HEALTHY) {
        sm = false;
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "State healthy, not using saint_mode");
    } else if (saint_state == STATE_SAINT_MODE) {
        sm = true;
        log_print(LOG_DEBUG, SECTION_SESSION_SAINTMODE, "State saint mode, using saint_mode");
    } else if (saint_state == STATE_ATTEMPTING_TO_EXIT_SAINT_MODE) {
        if (pthread_mutex_trylock(&request_outstanding) == 0) {
            request_outstanding_lock_count++;
            log_print(LOG_DEBUG, SECTION_SESSION_SAINTMODE, "Aquire lock for request_outstanding, lock_count: %d", request_outstanding_lock_count);
            sm = false;
            log_print(LOG_DEBUG, SECTION_SESSION_SAINTMODE, "State transitional saint mode, not using saint_mode");
        } else {
            log_print(LOG_DEBUG, SECTION_SESSION_SAINTMODE, "State transitional saint mode, failed to aquire request_outstanding, using saint_mode");
            sm = true;
        }
    }

    pthread_mutex_unlock(&saint_state_mutex);
    return sm;
}

void timed_curl_easy_perform(CURL *session, CURLcode *res, long *response_code, long *elapsed_time) {
    static const char *funcname = "timed_curl_easy_perform";
    struct timespec start_time;
    struct timespec now;

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, 
            "%s: calling curl_easy_perform; session: %p", funcname, session);
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    *res = curl_easy_perform(session);
    clock_gettime(CLOCK_MONOTONIC, &now);
    if(*res == CURLE_OK) {
        curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, response_code);
    }
    *elapsed_time = ((now.tv_sec - start_time.tv_sec) * 1000) + 
        ((now.tv_nsec - start_time.tv_nsec) / (1000 * 1000));
    if (*res != CURLE_OK) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, 
                "%s: curl failed: %s : *elapsed_time: %ld\n", 
                funcname, curl_easy_strerror(*res), *elapsed_time);
    }
    else if (*response_code >= 500) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, 
                "%s: rc: %ld : *elapsed_time: %ld\n", 
                funcname, *response_code, *elapsed_time);
    }
}

// Return value should be freed using curl_free().
char *escape_except_slashes(CURL *session, const char *path) {
    size_t path_len = strlen(path);
    char *mutable_path = strndup(path, path_len);
    char *escaped_path = NULL;
    size_t escaped_path_pos;

    if (mutable_path == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "Could not allocate memory in strndup for escape_except_slashes.");
        goto finish;
    }

    // Convert all slashes to the non-escaped "0" character.
    for (size_t i = 0; i < path_len; ++i) {
        if (path[i] == '/') {
            mutable_path[i] = '0';
        }
    }

    escaped_path = curl_easy_escape(session, mutable_path, path_len);

    if (escaped_path == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "Could not allocate memory in curl_easy_escape for escape_except_slashes.");
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "escape_except_slashes: escaped_path: %s", escaped_path);

    // Restore all slashes.
    escaped_path_pos = 0;
    for (size_t i = 0; i < path_len; ++i) {
        if (path[i] == '/') {
            escaped_path[escaped_path_pos] = '/';
        }
        if (escaped_path[escaped_path_pos] == '%') {
            escaped_path_pos += 2;
        }
        ++escaped_path_pos;
    }

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "escape_except_slashes: final escaped_path: %s", escaped_path);

finish:
    free(mutable_path);
    return escaped_path;
}

/*  START SESSION CREATE/DELETE CODE */

/* Arrange the N elements of ARRAY in random order.
   Only effective if N is much smaller than RAND_MAX;
   if this may not be the case, use a better random
   number generator. */
static void randomize(void *array[], int n) {
    struct timespec ts;
    // Randomize!
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand(ts.tv_nsec * ts.tv_sec);

    if (n > 1) {
        for (int idx = 0; idx < n - 1; idx++) {
          int jdx = idx + rand() / (RAND_MAX / (n - idx) + 1);
          void *t = array[jdx];
          array[jdx] = array[idx];
          array[idx] = t;
        }
    }
}

static int compare_node_score(const void *x, const void *y) {
    const struct addr_score_s *a = (const struct addr_score_s *)*(const struct addr_score_s * const *)x;
    const struct addr_score_s *b = (const struct addr_score_s *)*(const struct addr_score_s * const *)y;

    if (a->score > b->score) return 1;
    else if (a->score < b->score) return -1;
    else return 0;
}

static bool set_health_status(char *addr, char *curladdr) {
    static const char *funcname = "set_health_status";
    bool added_entry = false;
    struct health_status_s *healthstatus = NULL;
    healthstatus = g_hash_table_lookup(node_status.node_hash_table, addr);
    if (healthstatus) {
        if (curladdr && healthstatus->curladdr[0] == '\0') {
            strncpy(healthstatus->curladdr, curladdr, LOGSTRSZ);
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, 
                    "%s: existing entry didn't have curladdr %s", funcname, addr);
        }
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: reusing entry for %s", funcname, addr);
        healthstatus->current = true;
    }
    else {
        healthstatus = g_new(struct health_status_s, 1);
        healthstatus->score = HEALTHY;
        healthstatus->timestamp = 0;
        healthstatus->current = true;
        if (curladdr) {
            strncpy(healthstatus->curladdr, curladdr, LOGSTRSZ);
        }
        else {
            log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, 
                    "%s: new entry doesn't have curladdr %s", funcname, addr);
        }
        g_hash_table_replace(node_status.node_hash_table, g_strdup(addr), healthstatus);
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, 
                "%s: creating new entry for %s // %s", funcname, addr, curladdr);
        added_entry = true;
    }
    return added_entry;
}

static void construct_resolve_slist(GHashTable *addr_table) {
    static const char *funcname = "construct_resolve_slist";
    int addr_score_idx = 0;
    GHashTableIter iter;
    gpointer key, value;
    // Did we change the list? Used to decide to print new list
    // We get a new list if we get a new session, or we add or delete a node 
    // from the cluster; or if we update a health score
    struct addr_score_s *addr_score[MAX_NODES + 1] = {NULL};

    // Is there anything in node_hash_table not in addr table,
    // e.g. a deleted addr
    g_hash_table_iter_init (&iter, node_status.node_hash_table);
    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: hash_table [%p], iter [%p]",
        funcname, node_status.node_hash_table, iter);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        // Is this address in addr_table?
        bool exists = g_hash_table_lookup(addr_table, key);
        if (!exists) {
            // delete the node
            g_hash_table_iter_remove(&iter);
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: removed from hash table: %s", 
                    funcname, key);
        }
    }
    // Is there anything in addr_table not in node_hash_table
    // e.g. an added addr
    g_hash_table_iter_init (&iter, addr_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        // Is this address in addr_table?
        bool exists = g_hash_table_lookup(node_status.node_hash_table, key);
        if (!exists) {
            // Add to node_hash_table
            set_health_status(key, value);
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: added to hash table %s :: %s",
                    funcname, key, value);
        }
    }

    // Prepare a sortable array
    g_hash_table_iter_init (&iter, node_status.node_hash_table);

    addr_score_idx = 0;
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        struct health_status_s *healthstatus = (struct health_status_s *)value;

        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: healthstatus->curladdr: %s", funcname, healthstatus->curladdr);

        // We need to sort on health score, but use the addr name.
        addr_score[addr_score_idx] = g_new(struct addr_score_s, 1);

        // Save values into sortable array
        strncpy(addr_score[addr_score_idx]->addr, healthstatus->curladdr, IPSTR_SZ);
        addr_score[addr_score_idx]->score = healthstatus->score;
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: addr_score_idx [%d], addr [%s], score [%d]",
            funcname, addr_score_idx, addr_score[addr_score_idx]->addr, addr_score[addr_score_idx]->score);
        ++addr_score_idx;
    }

    // Randomize first; then sort and expect that the order of items with the same score (think '0') stays randomized
    randomize((void *)addr_score, addr_score_idx);

    // sort the array
    qsort(addr_score, addr_score_idx, sizeof(struct addr_score_s *), compare_node_score);

    if (addr_score[0]->score != 0) {
        // All connections are in some state of bad
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "%s: top entry is non-zero: %s -- %d",
            funcname, addr_score[0]->addr, addr_score[0]->score);
    }

    // addr_score_idx is the number of addresses we processed above
    for (int idx = 0; idx < addr_score_idx; idx++) {
        log_print(LOG_DYNAMIC, SECTION_SESSION_DEFAULT, 
                "%s: inserting into resolve_slist (%p): %s, score %d",
                funcname, node_status.resolve_slist, addr_score[idx]->addr, addr_score[idx]->score);
        node_status.resolve_slist = curl_slist_append(node_status.resolve_slist, addr_score[idx]->addr);
        g_free(addr_score[idx]);
    }
}

/* For reference, keep the different sockaddr structs available for inspection
 *
 * struct addrinfo {
 *     int              ai_flags;
 *     int              ai_family;
 *     int              ai_socktype;
 *     int              ai_protocol;
 *     socklen_t        ai_addrlen;
 *     struct sockaddr *ai_addr;
 *     char            *ai_canonname;
 *     struct addrinfo *ai_next;
 * };
 *
 * // All pointers to socket address structures are often cast to pointers
 * // to this type before use in various functions and system calls:
 *
 * struct sockaddr {
 *     unsigned short    sa_family;    // address family, AF_xxx
 *     char              sa_data[14];  // 14 bytes of protocol address
 * };
 *
 *
 * // IPv4 AF_INET sockets:
 *
 * struct sockaddr_in {
 *     short            sin_family;   // e.g. AF_INET, AF_INET6
 *     unsigned short   sin_port;     // e.g. htons(3490)
 *     struct in_addr   sin_addr;     // see struct in_addr, below
 *     char             sin_zero[8];  // zero this if you want to
 * };
 *
 * struct in_addr {
 *     unsigned long s_addr;          // load with inet_pton()
 * };
 *
 *
 * // IPv6 AF_INET6 sockets:
 *
 * struct sockaddr_in6 {
 *     u_int16_t       sin6_family;   // address family, AF_INET6
 *     u_int16_t       sin6_port;     // port number, Network Byte Order
 *     u_int32_t       sin6_flowinfo; // IPv6 flow information
 *     struct in6_addr sin6_addr;     // IPv6 address
 *     u_int32_t       sin6_scope_id; // Scope ID
 * };
 *
 * struct in6_addr {
 *     unsigned char   s6_addr[16];   // load with inet_pton()
 * };
 *
 */

/* Construct an slist for curl to use with opt CURLOPT_RESOLVE.
 * If our file system has several nodes, and a domain name which resolves
 * to those nodes, we need to present those nodes to distinct invocations
 * of fusedav in a random fashion to ensure load balance.
 * Following its normal path, libcurl calls getaddrinfo, which will sort
 * the IP addresses according to the RFC which governs it. This breaks
 * load balance, since each invocation of fusedav will see the list of
 * IP addresses in the same order, and all will prefer the same one.
 * So we use CURLOPT_RESOLVE to let us pass in the list, which libcurl
 * will then use instead of calling getaddrinfo.
 * We do this by calling getaddrinfo ourselves, then randomizing the list.
 */

/*  create_new_addr creates the table with the current nodes;
 *  construct_resolve_slist uses that information when constructing
 *  its slist 
 */
static GHashTable *create_new_addr_table(void) {
    static const char *funcname = "create_new_addr_table";
    // getaddrinfo will put the linked list here
    const struct addrinfo *ai;
    struct addrinfo *aihead;
    // Restrict getaddrinfo to returning just the types we want. This
    // turns out to be just SOCK_STREAM.
    // REVIEW: is this true?
    struct addrinfo hints;
    int count = 0;
    int res;

    GHashTable *addr_table;

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: node_status = %p", funcname, &node_status);
    if (node_status.node_hash_table == NULL) {
        node_status.node_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }

    // Turn hints off
    memset(&hints, 0, sizeof(struct addrinfo));
    // By setting ai_family to 0, we allow both IPv4 and IPv6
    // By setting ai_protocol to 0, we allow any socket protocol (???)
    // Set hints to ensure SOCK_STREAM. Otherwise we get multiple copies
    // of each IP address back
    hints.ai_socktype = SOCK_STREAM;

    // get list from getaddrinfo
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: calling getaddrinfo with %s %s",
        funcname, filesystem_domain, filesystem_port);
    res = getaddrinfo(filesystem_domain, filesystem_port, &hints, &aihead);
    if(res) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: getaddrinfo returns error: %d (%s)",
            funcname, res, gai_strerror(res));

        // This is an error. We do not set CURLOPT_RESOLVE, so libcurl will
        // do its default thing. If its call to getaddrinfo succeeds, the
        // first IP will be used (breaks load balancing).  If it fails as it does here,
        // it will do its own error processing.
        return NULL;
    }

    addr_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);


    /* getaddrinfo returned a list of addrinfo structs (for our purposes, IP addresses).
     * Some of those structs represent IPv4, others IPv6. We decide which is which
     * by the addrlen which gets returned (16 for IPv4, 26 (28?) for IPv6.
     * The components of the address we need are in an array of chars or ints, so
     * we pull them out one by one and append them to the string we are building.
     * Ultimately, this string, per libcurl's CURLOPT_RESOLVE requirements,
     * will be DOMAIN:PORT:IP-ADDRESS.
     *
     * If timeout has passed, we recreate the list and pass it in again to libcurl.
     * However, if the previous connection is still good, libcurl will continue
     * to use it in spite of the new order of addresses in the list. (This is good.)
     */
    for (ai = aihead; ai != NULL && count < MAX_NODES; ai = ai->ai_next) {
        // Holds the string we are constructing
        char *ipstr;
        char ipaddr[IPSTR_SZ];

        ipstr = calloc(IPSTR_SZ, 1);
        assert(ipstr);

        // The domain comes first, followed by a colon per libcurl's requirement
        strncpy(ipstr, filesystem_domain, IPSTR_SZ);
        strcat(ipstr, ":");

        // The port and colon come next.
        strcat(ipstr, filesystem_port);
        strcat(ipstr, ":");

        // An IPv4 struct
        if (ai->ai_family == AF_INET) {
            if(!inet_ntop(ai->ai_family, &(((struct sockaddr_in *)ai->ai_addr)->sin_addr), ipaddr, IPSTR_SZ)) {
                log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: error on inet_ntop (AF_INET): %d %s",
                    funcname, errno, strerror(errno));
                free(ipstr);
                continue;
            }
        }
        // An IPv6 struct
        else if (ai->ai_family == AF_INET6) {
            if(!inet_ntop(ai->ai_family, &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr), ipaddr, IPSTR_SZ)) {
                log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: error on inet_ntop (AF_INET6): %d %s",
                    funcname, errno, strerror(errno));
                free(ipstr);
                continue;
            }
        }
        else {
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: ai_family not IPv4 nor IVv6 [%d]",
                funcname, ai->ai_family);
            free(ipstr);
            continue;
        }

        strcat(ipstr, ipaddr);

        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, 
                "%s: ipaddr/ipstr is %s // %s", funcname, ipaddr, ipstr);

        g_hash_table_replace(addr_table, g_strdup(logstr(ipaddr)), g_strdup(ipstr));

        free(ipstr);

        ++count;
    }
    freeaddrinfo(aihead);
    return addr_table;
}

/* delete_tmp_session is a slimmed down version of session_cleanup */
void delete_tmp_session(CURL *session) {
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Destroying temporary cURL session.");
    if (session) {
        curl_easy_cleanup(session);
    }
}

static void delete_session(CURL *session, bool tmp_session) {
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "delete_session: destroying old handle and creating a new one");
    if (tmp_session) {
        delete_tmp_session(session);
    }
    else {
        session_cleanup(session);
    }
}

static void increment_node_failure(char *addr, const CURLcode res, const long response_code, const long elapsed_time) {
    const char * funcname = "increment_node_failure";
    struct health_status_s *healthstatus = get_health_status(addr);
    if (!healthstatus) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: healthstatus null for %s", funcname, addr);
        return;
    }
    // Currently treat !CURLE_OK and response_code > 500 the same, but leave in structure if we want to treat them differently.
    if (res != CURLE_OK) {
        healthstatus->score = UNHEALTHY;
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "%s: !CURLE_OK: %s addr score set to %d",
            funcname, addr, healthstatus->score);
    }
    else if (response_code >= 500) {
        healthstatus->score = UNHEALTHY;
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "%s: response_code %lu: %s addr score set to %d",
            funcname, response_code, addr, healthstatus->score);
    }
    else if (elapsed_time > time_limit) {
        healthstatus->score = UNHEALTHY;
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "%s: slow_request %lu: %s addr score set to %d",
            funcname, elapsed_time, addr, healthstatus->score);
    }
    healthstatus->timestamp = time(NULL); // Most recent failure. We don't currently use this value, but it might be interesting
}

void process_status(const char *fcn_name, CURL *session, const CURLcode res, 
        const long response_code, const long elapsed_time, const int iter, 
        const char *path, bool tmp_session) {

    stats_counter("attempts", 1);

    if (res != CURLE_OK) {
        print_errors(iter, "curl_failures", fcn_name, res, response_code, elapsed_time, path);
        increment_node_failure(nodeaddr, res, response_code, elapsed_time);
        delete_session(session, tmp_session);
        return;
    }

    if (response_code >= 500) {
        print_errors(iter, "status500_failures", fcn_name, res, response_code, elapsed_time, path);
        increment_node_failure(nodeaddr, res, response_code, elapsed_time);
        delete_session(session, tmp_session);
        return;
    }

    if (elapsed_time > time_limit) {
        print_errors(iter, "slow_requests", fcn_name, res, response_code, elapsed_time, path);
        increment_node_failure(nodeaddr, res, response_code, elapsed_time);
        if (health_status_all_nodes() == UNHEALTHY) {
            trigger_saint_event(CLUSTER_FAILURE);
            set_dynamic_logging();
        }
        delete_session(session, tmp_session);
        return;
    }

    // If it wasn't an error, and it isn't the 0'th iter, then we must have failed previously and now recovered
    if (iter > 0) {
        stats_counter("recoveries", 1);
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT,
            "%s: curl iter %d on path %s -- fusedav.%s.server-%s.recoveries", fcn_name, iter, path, filesystem_cluster, nodeaddr);
        increment_node_success(nodeaddr);
    }
}

static bool valid_slist(void) {
    if (node_status.resolve_slist) {
        return true;
    }

    return false;
}

static bool slist_timed_out(void) {
    // timeout interval in seconds
    // If this interval has passed, we recreate the list. Within this interval,
    // we reuse the current list.
    static const time_t resolve_slist_timeout = 600;
    static const time_t health_update_timeout = 120;
    // Keep a timer; at periodic intervals we reset the resolve_slist.
    // static so it persists between calls
    static __thread time_t prev_slist_time = 0;
    static __thread time_t prev_health_time = 0;
    time_t curtime;

    // If the list is still young, just return. The current list is still valid
    curtime = time(NULL);

    // We want to update the health status on all nodes currently unhealthy. We
    // do this on a different interval than the slist_timeout
    if (curtime - prev_health_time > health_update_timeout) {
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT,
            "slist_timed_out: updating health status all nodes");
        update_health_status_all_nodes();
        // Ready for the next invocation.
        prev_health_time = curtime;
    }
    if (curtime - prev_slist_time < resolve_slist_timeout) {
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT,
            "slist_timed_out: timeout has not elapsed; return with current slist (%p)", node_status.resolve_slist);
        return false;
    }

    // Ready for the next invocation.
    prev_slist_time = curtime;
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "slist_timed_out: timeout has elapsed on %s", nodeaddr);
    return true;
}

static bool needs_new_session(bool tmp_session) {
    CURL *session;
    const char *funcname = "needs_new_session";
    bool new_session = false;

    // Short circuit on tmp_session; we always need a new session
    if (tmp_session) {
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: tmp_session is true", funcname);
        return true;
    }

    // session is null
    pthread_once(&session_once, session_tsd_key_init);

    session = pthread_getspecific(session_tsd_key);
    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s?: session (%p)", funcname, session);

    if (!session) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: !session", funcname);
        new_session = true;
    }

    // no slist
    else if (!valid_slist()) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: !valid_slist", funcname);
        new_session = true;
    }

    // timeout
    else if (slist_timed_out()) {
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: slist_timed_out", funcname);
        new_session = true;
    }

    // We're going to create a new session, so get rid of the old
    if (new_session) {
        session_cleanup(session);
    }

    return new_session;
}

static CURL *update_session(bool tmp_session) {
    static const char *funcname = "update_session";
    CURL *session = NULL;

    // We only need a new addr_table if we need a new session, and if we call update_session,
    // we need a new session
    GHashTable *addr_table;
    addr_table = create_new_addr_table();
    // On getaddrinfo failure, NULL gets returned; pass it through
    if (addr_table == NULL) return NULL;

    // create the hash table of node addresses for which we will keep health status
    // We do this when the thread is initialized. We want the hashtable to survive reinitialization of the handle,
    // since the hashtable keeps track of the health status of connections causing the reinitialization

    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Opening cURL session");

    // if tmp_session, we need to get a new session for this request; otherwise see if we already have a session
    if (!tmp_session) {
        session = pthread_getspecific(session_tsd_key);
        if (session) {
            log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: Got unexpected already-existing session; deleting: %p", funcname, session);
            session_cleanup(session);
        }
    }

    session = curl_easy_init();
    if (!session) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: curl_easy_init returns NULL", funcname);
        return NULL;
    }
    // We don't want a tmp session to muck with start time and resetting the main session
    if (!tmp_session) {
        // Keep track of start time so we can track how long sessions stay open
        session_start_time = time(NULL);
        pthread_setspecific(session_tsd_key, session);
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: new session: %p", funcname, session);
        update_session_count(true);
    }

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: construct_resolve_slist: addr_table (%p)", funcname, addr_table);
    construct_resolve_slist(addr_table);
    g_hash_table_destroy(addr_table);

    return session;
}

static CURL *get_session(bool tmp_session) {
    CURL *session;
    static const char * funcname = "get_session";

    if (needs_new_session(tmp_session)) {
        session = update_session(tmp_session);
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: update_session (%p)", funcname, session);
    }
    else {
        session = pthread_getspecific(session_tsd_key);
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "%s: pthread session (%p)", funcname, session);
    }

    return session;
}

CURL *session_request_init(const char *path, const char *query_string, bool tmp_session) {
    CURL *session;
    char *full_url = NULL;
    char *escaped_path;
    static const char *funcname = "session_request_init";

    // If the whole cluster is sad, avoid access altogether for a given period of time.
    // Calls to this function, on detecting this error, set ENETDOWN, which is appropriate
    if (use_saint_mode()) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "%s: already in saint mode", funcname);
        return NULL;
    }

    session = get_session(tmp_session);

    if (!session) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: session handle NULL.", funcname);
        return NULL;
    }

    curl_easy_reset(session);

    // Whether we created a new resolve_slist or not, we still need to
    // make the setopt call for CURLOPT_RESOLVE.
    // Otherwise, libcurl will revert to its default, call getaddrinfo
    // on its own, and return the unsorted, unbalanced, first entry.
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: Sending resolve_slist (%p) to curl",
        funcname, node_status.resolve_slist);
    curl_easy_setopt(session, CURLOPT_RESOLVE, node_status.resolve_slist);
    curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, session_debug);
    // Empty the error buffer
    curl_errbuf[0] = '\0';
    curl_easy_setopt(session, CURLOPT_ERRORBUFFER, curl_errbuf);
    curl_easy_setopt(session, CURLOPT_VERBOSE, 1L);

    escaped_path = escape_except_slashes(session, path);
    if (escaped_path == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: Allocation failed in escape_except_slashes.", funcname);
        return NULL;
    }

    if (query_string == NULL) {
        asprintf(&full_url, "%s%s", get_base_url(), escaped_path);
    }
    else {
        asprintf(&full_url, "%s%s?%s", get_base_url(), escaped_path, query_string);
    }
    if (full_url == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "%s: Allocation failed in asprintf.", funcname);
        return NULL;
    }
    curl_free(escaped_path);
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "%s: Initialized request to URL: %s", funcname, full_url);
    free(full_url);

    if (ca_certificate != NULL)
        curl_easy_setopt(session, CURLOPT_CAINFO, ca_certificate);
    if (client_certificate != NULL) {
        curl_easy_setopt(session, CURLOPT_SSLCERT, client_certificate);
        curl_easy_setopt(session, CURLOPT_SSLKEY, client_certificate);
    }
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(session, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(session, CURLOPT_CONNECTTIMEOUT_MS, 1200);
    curl_easy_setopt(session, CURLOPT_TIMEOUT, 60);
    curl_easy_setopt(session, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(session, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    return session;
}

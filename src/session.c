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

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

pthread_mutex_t saint_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static state_t saint_state = STATE_HEALTHY;

pthread_mutex_t request_outstanding = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static int request_outstanding_lock_count = 0;

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

// When we construct a new slist, we need to track the status to know what action to take.
enum slist_status {SUCCESS, GETADDRINFO_FAILURE, REQUIRES_NEW_SLIST};

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

// Call handle_cleanup when reinitializing a handle, or called from session_destroy when thread exits
static void handle_cleanup(void *s) {
    CURL *session = s;

    assert(s);

    // The first log statement will get stripped from logstash because it has the stats designator |c, so log a second one
    log_print(LOG_INFO, SECTION_ENHANCED,
        "Destroying cURL handle -- fusedav.%s.sessions:-1|c fusedav.%s.session-duration:%lu|c",
        filesystem_cluster, filesystem_cluster, time(NULL) - session_start_time);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Destroying cURL handle");

    // Before we go, make sure we've printed the number of curl accesses we accumulated
    log_filesystem_nodes("handle_cleanup", CURLE_OK, 0, -1, "no path");
    // Free the resolve_slist before exiting the session
    curl_slist_free_all(node_status.resolve_slist);
    node_status.resolve_slist = NULL;
    curl_easy_cleanup(session);
}

// When a thread exits, we also want to free its hashtable. We don't want to free the hashtable if we are just
// reinitializing the thread, since we want to keep the health status that causes those reinitializations
static void session_destroy(void *s) {
    pthread_mutex_lock(&saint_state_mutex);
    try_release_request_outstanding();
    pthread_mutex_unlock(&saint_state_mutex);
    handle_cleanup(s);
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

static CURL *session_get_handle(bool new_handle) {
    CURL *session;

    pthread_once(&session_once, session_tsd_key_init);

    if ((session = pthread_getspecific(session_tsd_key))) {
        if (new_handle) {
            log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_get_handle: destroying old handle and creating a new one");
            handle_cleanup(session);
        }
        else {
            return session;
        }
    }

    // create the hash table of node addresses for which we will keep health status
    // We do this when the thread is initialized. We want the hashtable to survive reinitialization of the handle,
    // since the hashtable keeps track of the health status of connections causing the reinitialization

    // Keep track of start time so we can track how long sessions stay open
    session_start_time = time(NULL);

    // The first log print will be stripped by log stash because it has the stats designator 1|c, so log one without it
    log_print(LOG_INFO, SECTION_ENHANCED, "Opening cURL session -- fusedav.%s.sessions:1|c", filesystem_cluster);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Opening cURL session");
    session = curl_easy_init();
    pthread_setspecific(session_tsd_key, session);

    return session;
}

// get a temporary handles
static CURL *session_get_temp_handle(void) {
    CURL *session;

    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Opening temporary cURL session.");
    session = curl_easy_init();

    return session;
}

void session_temp_handle_destroy(CURL *session) {
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "Destroying temporary cURL session.");
    if (session) curl_easy_cleanup(session);
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

static int compare_node_score(const void *x, const void *y) {
    const struct addr_score_s *a = (const struct addr_score_s *)*(const struct addr_score_s * const *)x;
    const struct addr_score_s *b = (const struct addr_score_s *)*(const struct addr_score_s * const *)y;

    if (a->score > b->score) return 1;
    else if (a->score < b->score) return -1;
    else return 0;
}

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

static struct health_status_s *get_health_status(char *addr) {
    return g_hash_table_lookup(node_status.node_hash_table, addr);
}

static bool set_health_status(char *addr, char *curladdr) {
    bool added_entry = false;
    struct health_status_s *health_status = NULL;
    health_status = g_hash_table_lookup(node_status.node_hash_table, addr);
    if (health_status) {
        if (curladdr && health_status->curladdr[0] == '\0') {
            strncpy(health_status->curladdr, curladdr, LOGSTRSZ);
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "set_health_status: existing entry didn't have curladdr %s", addr);
        }
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "set_health_status: reusing entry for %s", addr);
        health_status->current = true;
    }
    else {
        health_status = g_new(struct health_status_s, 1);
        health_status->score = 0;
        health_status->timestamp = 0;
        health_status->current = true;
        if (curladdr) {
            strncpy(health_status->curladdr, curladdr, LOGSTRSZ);
        }
        else {
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "set_health_status: new entry doesn't have curladdr %s", addr);
        }
        g_hash_table_replace(node_status.node_hash_table, g_strdup(addr), health_status);
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "set_health_status: creating new entry for %s", addr);
        added_entry = true;
    }
    return added_entry;
}

/* cluster saint mode means:
 * 1. If in cluster saint mode, back off accessing the cluster for a given period of time
 * 2. If in cluster saint mode, where possible, assume local state is correct.
 * Regarding (2), propfinds should succeed, as should GETs (as if 304).
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
        log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Release lock for request_outstanding, lock_count: %d", request_outstanding_lock_count);
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
    log_print(LOG_NOTICE, SECTION_FUSEDAV_DEFAULT, "Event CLUSTER_FAILURE; transitioned to STATE_SAINT_MODE from STATE_HEALTHY.");
}
void action_s1_e2 (void) {}
void action_s1_e3 (void) {}
void action_s2_e1 (void) {}
void action_s2_e2 (void) {
    saint_state = STATE_ATTEMPTING_TO_EXIT_SAINT_MODE;
    log_print(LOG_NOTICE, SECTION_FUSEDAV_DEFAULT, "Event SAINT_MODE_DURATION_EXPIRED; transitioned to STATE_ATTEMPTING_TO_EXIT_SAINT_MODE from STATE_SAINT_MODE.");
}
void action_s2_e3 (void) {}
void action_s3_e1 (void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    failure_timestamp = now.tv_sec;
    try_release_request_outstanding();
    saint_state = STATE_SAINT_MODE;
    log_print(LOG_INFO, SECTION_ENHANCED, "Setting cluster saint mode for %lu seconds. fusedav.saint_mode:1|c", saint_mode_duration);
    log_print(LOG_NOTICE, SECTION_FUSEDAV_DEFAULT, "Event CLUSTER_FAILURE; transitioned to STATE_SAINT_MODE from STATE_ATTEMPTING_TO_EXIT_SAINT_MODE.");
}
void action_s3_e2 (void) {}
void action_s3_e3 (void) {
    try_release_request_outstanding();
    saint_state = STATE_HEALTHY;
    log_print(LOG_NOTICE, SECTION_FUSEDAV_DEFAULT, "Event CLUSTER_SUCCESS; transitioned to STATE_HEALTHY from STATE_ATTEMPTING_TO_EXIT_SAINT_MODE.");
}


void trigger_saint_mode_expired_if_needed(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (saint_state == STATE_SAINT_MODE && now.tv_sec >= failure_timestamp + saint_mode_duration) {
        state_table[saint_state][SAINT_MODE_DURATION_EXPIRED]();
        // If we've been in saintmode for longer than saint_mode_warning_threshold, emit a stat saying so.
        if (now.tv_sec >= unhealthy_since_timestamp + saint_mode_warning_threshold) {
            log_print(LOG_INFO, SECTION_ENHANCED,
                "saint_mode active for %d seconds -- fusedav.%s.server-%s.long_running_saint_mode:1|c", now.tv_sec-unhealthy_since_timestamp, filesystem_cluster, nodeaddr);
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
    } else if (saint_state == STATE_SAINT_MODE) {
        sm = true;
    } else if (saint_state == STATE_ATTEMPTING_TO_EXIT_SAINT_MODE) {
        if (pthread_mutex_trylock(&request_outstanding) == 0) {
            request_outstanding_lock_count++;
            log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Aquire lock for request_outstanding, lock_count: %d", request_outstanding_lock_count);
            sm = false;
        } else {
            log_print(LOG_DEBUG, SECTION_FUSEDAV_DEFAULT, "Failed to aquire request_outstanding, using saint_mode");
            sm = true;
        }
    }

    pthread_mutex_unlock(&saint_state_mutex);
    return sm;
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

static int construct_resolve_slist(bool force) {
    // getaddrinfo will put the linked list here
    const struct addrinfo *ai;
    struct addrinfo *aihead;
    // Restrict getaddrinfo to returning just the types we want. This
    // turns out to be just SOCK_STREAM.
    // REVIEW: is this true?
    struct addrinfo hints;
    // timeout interval in seconds
    // If this interval has passed, we recreate the list. Within this interval,
    // we reuse the current list.
    // REVIEW: arbitrary. Is there a better value than 2 minutes?
    const time_t resolve_slist_timeout = 120;
    // Keep a timer; at periodic intervals we reset the resolve_slist.
    // static so it persists between calls
    static __thread time_t prevtime = 0;
    time_t curtime;
    // number of ip addresses returned from getaddrinfo
    int count = 0;
    int addr_score_idx = 0;
    // result from function
    enum slist_status status = SUCCESS;
    int res = -1;
    bool reinserted_into_rotation = false; // Did we reinsert a previously unhealthy connection back into rotation?
    bool removed_from_rotation = false; // Did we remove a node from rotation?
    struct addr_score_s *addr_score[MAX_NODES + 1] = {NULL};
    GHashTableIter iter;
    gpointer key, value;

    // If the list is still young, just return. The current list is still valid
    curtime = time(NULL);

    if (!force && node_status.resolve_slist && (curtime - prevtime < resolve_slist_timeout)) {
        // status = SUCCESS; Not an error
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT,
            "construct_resolve_slist: timeout has not elapsed; return with current slist (%p)", node_status.resolve_slist);
        return status;
    }

    // Ready for the next invocation.
    prevtime = curtime;

    // Free the current list
    curl_slist_free_all(node_status.resolve_slist);
    node_status.resolve_slist = NULL;

    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "session_get_handle: node_status = %p", &node_status);
    if (node_status.node_hash_table == NULL) {
        node_status.node_hash_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }

    // Initialize current field to false. If we have an entry in the table which is no longer valid
    // and no longer being returned by getaddrinfo, we can delete it
    g_hash_table_iter_init (&iter, node_status.node_hash_table);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        struct health_status_s *healthstatus = (struct health_status_s *)value;
        healthstatus->current = false;
    }

    // Turn hints off
    memset(&hints, 0, sizeof(struct addrinfo));
    // By setting ai_family to 0, we allow both IPv4 and IPv6
    // By setting ai_protocol to 0, we allow any socket protocol (???)
    // Set hints to ensure SOCK_STREAM. Otherwise we get multiple copies
    // of each IP address back
    hints.ai_socktype = SOCK_STREAM;

    // get list from getaddrinfo
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "construct_resolve_slist: calling getaddrinfo with %s %s",
        filesystem_domain, filesystem_port);
    res = getaddrinfo(filesystem_domain, filesystem_port, &hints, &aihead);
    if(res) {
        status = GETADDRINFO_FAILURE;
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "construct_resolve_slist: getaddrinfo returns error: %d (%s)",
            res, gai_strerror(res));

        // This is an error. We do not set CURLOPT_RESOLVE, so libcurl will
        // do its default thing. If its call to getaddrinfo succeeds, the
        // first IP will be used (breaks load balancing).  If it fails as it does here,
        // it will do its own error processing.
        return status;
    }

    // If we got here, we are golden!
    // By setting this to SUCCESS, curl will not immediately start using our new list.
    // It will take some time (a couple of minutes?) before it makes the switch.
    // However, if we detect a change in status (added or deleted node, or a change in
    // health status of a node) we will force curl to create a new session and use the
    // new list.
    status = SUCCESS;

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
                log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "construct_resolve_slist: error on inet_ntop (AF_INET): %d %s",
                    errno, strerror(errno));
                free(ipstr);
                continue;
            }
        }
        // An IPv6 struct
        else if (ai->ai_family == AF_INET6) {
            if(!inet_ntop(ai->ai_family, &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr), ipaddr, IPSTR_SZ)) {
                log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "construct_resolve_slist: error on inet_ntop (AF_INET6): %d %s",
                    errno, strerror(errno));
                free(ipstr);
                continue;
            }
        }
        else {
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "construct_resolve_slist: ai_family not IPv4 nor IVv6 [%d]",
                ai->ai_family);
            free(ipstr);
            continue;
        }
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "construct_resolve_slist: ipaddr is %s", ipaddr);

        strcat(ipstr, ipaddr);

        // Check if ipstr is in hashtable, or put it there.
        // If we see a new entry, make sure we force curl to create a new session to use the new list
        if (set_health_status(logstr(ipaddr), ipstr)) {
            status = REQUIRES_NEW_SLIST;
        }
        // ipstr gets strdup'ed before being made the hashtable key, so free it here
        free(ipstr);

        ++count;
    }

    // TODO Originally, we were going to up the global variable num_filesystem_server_nodes to the count of nodes
    // returned by getaddrinfo, but are afraid that will cause too much load if the cluster is having difficulties
    // if (count > num_filesystem_server_nodes) num_filesystem_server_nodes = count;

    // Prepare a sortable array
    g_hash_table_iter_init (&iter, node_status.node_hash_table);
    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "construct_resolve_slist: hash_table [%p], iter [%p]",
        node_status.node_hash_table, iter);

    addr_score_idx = 0;
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        struct health_status_s *healthstatus = (struct health_status_s *)value;

        // If this entry was not updated while processing getaddrinfo, assume the node has been deleted
        // and remove it from the list
        if (healthstatus->current == false) {
            g_hash_table_iter_remove(&iter);
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT,
                "construct_resolve_slist: \'%s\' no longer returned from getaddrinfo; removing",
                healthstatus->curladdr);
            removed_from_rotation = true;
            status = REQUIRES_NEW_SLIST;
            continue;
        }

        // We need to sort on health score, but use the addr name.
        addr_score[addr_score_idx] = g_new(struct addr_score_s, 1);
        // Take the opportunity to decrement the score by the amount of time which has passed since it last went bad.
        // This will update the hashtable entry. It's a pointer, so update will stick
        if (!force && healthstatus->score != 0) {
            --healthstatus->score;
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "construct_resolve_slist: decrementing score; addr [%s], score [%d]",
                healthstatus->curladdr, healthstatus->score);
            reinserted_into_rotation = true;
            status = REQUIRES_NEW_SLIST;
        }

        // Save values into sortable array
        strncpy(addr_score[addr_score_idx]->addr, healthstatus->curladdr, IPSTR_SZ);
        addr_score[addr_score_idx]->score = healthstatus->score;
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "construct_resolve_slist: addr_score_idx [%d], addr [%s], score [%d]",
            addr_score_idx, addr_score[addr_score_idx]->addr, addr_score[addr_score_idx]->score);
        ++addr_score_idx;
    }

    if (count != addr_score_idx) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "construct_resolve_slist: addr_score_idx [%d] != count [%d]",
            addr_score_idx, count);
    }
    // Randomize first; then sort and expect that the order of items with the same score (think '0') stays randomized
    randomize((void *)addr_score, count);

    // sort the array
    qsort(addr_score, count, sizeof(struct addr_score_s *), compare_node_score);

    if (addr_score[0]->score != 0) {
        // All connections are in some state of bad
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "construct_resolve_slist: top entry is non-zero: %s -- %d",
            addr_score[0]->addr, addr_score[0]->score);
    }

    // addr_score_idx is the number of addresses we processed above
    for (int idx = 0; idx < addr_score_idx; idx++) {
        if (force || reinserted_into_rotation || removed_from_rotation) { // if we've potentially changed the list, let's see the new one
            log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "construct_resolve_slist: inserting into resolve_slist: %s, score %d",
                addr_score[idx]->addr, addr_score[idx]->score);
        }
        node_status.resolve_slist = curl_slist_append(node_status.resolve_slist, addr_score[idx]->addr);
        g_free(addr_score[idx]);
    }

    return status;
}

CURL *session_request_init(const char *path, const char *query_string, bool temporary_handle, bool new_slist) {
    CURL *session;
    char *full_url = NULL;
    char *escaped_path;
    enum slist_status status;

    // If the whole cluster is sad, avoid access altogether for a given period of time.
    // Calls to this function, on detecting this error, set ENETDOWN, which is appropriate
    if (use_saint_mode()) {
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "session_request_init: already in saint mode");
        return NULL;
    }

    // 1. new_slist is false
    // a. slist timeout has not elapsed: call construct_resolve_slist here but not
    // below. No new slist, no new session 
    // b. slist timeout has elapsed and no new nodes added or removed: create 
    // new slist here, but not below. New slist, no new session, new slist 
    // will take effect when curl gets around to it (a couple of minutes)
    // c. slist timeout has elapsed and new node added or deleted: create 
    // new slist and set new_slist below; this slist will be deleted when 
    // we make a new session, and then recreated in the call to 
    // construct_resolve_slist below since we set new_slist.
    // d. slist timeout has not elapsed, but there happens to be a node added
    // or deleted: it will not be detected in this call but only later when 
    // slist timeout has elapsed. So, for the duration of slist timeout, 
    // new nodes will not yet get traffic; deleted nodes will continue to get traffic
    // 2. new_slist is true
    // a. Skip this call to construct_resolve_slist, create new session below, then
    // call construct_resolve_slist below to create the new slist.
    //
    // If there is an added or deleted node, construct_slist is called redundantly;
    // the results of the first call are thrown out when a new session is created,
    // then the new slist is created again.
    //
    // The purpose of this initial call to construct_resolve_slist is to determine
    // whether a node has been added or deleted so we can take action and
    // make sure a new session and slist get created.

    status = SUCCESS; // eliminates warning about it might be unitialized
    if (new_slist == false) {
        // If we add or delete a node, or change its health status, we need to signal here to 
        // create a new session
        status = construct_resolve_slist(new_slist);

        if (status == REQUIRES_NEW_SLIST) {
            new_slist = true;
        }
    }

    if (temporary_handle) {
        session = session_get_temp_handle();
    }
    else {
        session = session_get_handle(new_slist);
    }

    if (!session) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_request_init: session handle NULL.");
        return NULL;
    }

    curl_easy_reset(session);

    // If we got a new handle above, we need to reset slist
    if (new_slist) {
        status = construct_resolve_slist(new_slist);
    }

    // Treat this failure as a session failure; no point in continuing
    if (status == GETADDRINFO_FAILURE) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_request_init: GETADDRINFO_FAILURE.");
        return NULL;
    }

    // Whether we created a new resolve_slist or not, we still need to
    // make the setopt call for CURLOPT_RESOLVE.
    // Otherwise, libcurl will revert to its default, call getaddrinfo
    // on its own, and return the unsorted, unbalanced, first entry.
    // (REVIEW: not sure if the above is true. Won't the current session
    // just continue using the previous slist? I think it doesn't timeout)
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_request_init: Sending resolve_slist (%p) to curl",
        node_status.resolve_slist);
    curl_easy_setopt(session, CURLOPT_RESOLVE, node_status.resolve_slist);
    curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, session_debug);
    curl_easy_setopt(session, CURLOPT_VERBOSE, 1L);

    escaped_path = escape_except_slashes(session, path);
    if (escaped_path == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_request_init: Allocation failed in escape_except_slashes.");
        return NULL;
    }

    if (query_string == NULL) {
        asprintf(&full_url, "%s%s", get_base_url(), escaped_path);
    }
    else {
        asprintf(&full_url, "%s%s?%s", get_base_url(), escaped_path, query_string);
    }
    if (full_url == NULL) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_request_init: Allocation failed in asprintf.");
        return NULL;
    }
    curl_free(escaped_path);
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_request_init: Initialized request to URL: %s", full_url);
    free(full_url);

    //curl_easy_setopt(session, CURLOPT_USERAGENT, "FuseDAV/" PACKAGE_VERSION);
    if (ca_certificate != NULL)
        curl_easy_setopt(session, CURLOPT_CAINFO, ca_certificate);
    if (client_certificate != NULL) {
        curl_easy_setopt(session, CURLOPT_SSLCERT, client_certificate);
        curl_easy_setopt(session, CURLOPT_SSLKEY, client_certificate);
    }
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(session, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(session, CURLOPT_CONNECTTIMEOUT_MS, 500);
    curl_easy_setopt(session, CURLOPT_TIMEOUT, 60);
    //curl_easy_setopt(session, CURLOPT_LOW_SPEED_LIMIT, 1024);
    //curl_easy_setopt(session, CURLOPT_LOW_SPEED_TIME, 60);
    curl_easy_setopt(session, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(session, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    // For curl configured for nss rather than openssl
    // curl-config --configure ... '--without-ssl' '--with-nss'
    // cipher list for nss at:
    // https://git.fedorahosted.org/cgit/mod_nss.git/plain/docs/mod_nss.html
    // Restrict to TLSv1.2
    // Prefer gcm, but allow lesser cipher
    // Don't set client ciphering; rely on server
    // curl_easy_setopt(session, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    // curl_easy_setopt(session, CURLOPT_SSL_CIPHER_LIST, "ecdhe_rsa_aes_128_gcm_sha_256");

    return session;
}

static void increment_node_failure(char *addr, const CURLcode res, const long response_code) {
    struct health_status_s *health_status = get_health_status(addr);
    if (!health_status) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "increment_node_failure: health_status null for %s", addr);
        return;
    }
    // Currently treat !CURLE_OK and response_code > 500 the same, but leave in structure if we want to treat them differently.
    if (res != CURLE_OK) {
        health_status->score = 2;
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "increment_node_failure: !CURLE_OK: %s addr score set to %d",
            addr, health_status->score);
    }
    else if (response_code >= 500) {
        health_status->score = 2;
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "increment_node_failure: response_code %lu: %s addr score set to %d",
            response_code, addr, health_status->score);
    }
    health_status->timestamp = time(NULL); // Most recent failure. We don't currently use this value, but it might be interesting
}

static void increment_node_success(char *addr) {
    struct health_status_s *health_status = get_health_status(addr);
    if (!health_status) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "increment_node_success: health_status null for %s", addr);
        return;
    }
    if (health_status->score > 0) {
        --health_status->score;
        health_status->timestamp = time(NULL); // Reset since we just used it
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "increment_node_success: %s addr score set to %u",
            addr, health_status->score);
    }
}

static void print_errors(const int iter, const char *type_str, const char *fcn_name, 
        const CURLcode res, const long response_code, const char *path) {
    char *failure_str = NULL;
    char *error_str = NULL;
    asprintf(&failure_str, "%d_failures", iter + 1);

    if (res != CURLE_OK) {
        asprintf(&error_str, "%s :: %s", curl_easy_strerror(res), "no rc");
    } else {
        asprintf(&error_str, "%s :: %lu", "no curl error", response_code);
    }

    // Track number of failures
    log_print(LOG_INFO, SECTION_ENHANCED,
        "%s: curl iter %d on path %s; %s -- fusedav.%s.server-%s.%s:1|c",
        fcn_name, iter, path, error_str, filesystem_cluster, nodeaddr, failure_str);

    free(failure_str);

    // Distinguish curl from 500-status failures
    log_print(LOG_INFO, SECTION_ENHANCED,
        "%s: curl iter %d on path %s; %s -- fusedav.%s.server-%s.%s:1|c",
        fcn_name, iter, path, error_str, filesystem_cluster, nodeaddr, type_str);

    log_print(LOG_INFO, SECTION_ENHANCED,
        "%s: curl iter %d on path %s; %s -- fusedav.%s.server-%s.failures:1|c",
        fcn_name, iter, path, error_str, filesystem_cluster, nodeaddr);

    log_print(LOG_ERR, SECTION_SESSION_DEFAULT,
        "%s: curl iter %d on path %s; %s -- fusedav.%s.server-%s.failures",
        fcn_name, iter, path, error_str, filesystem_cluster, nodeaddr);

    free(error_str);
}

void log_filesystem_nodes(const char *fcn_name, const CURLcode res, const long response_code, const int iter, const char *path) {
    static __thread unsigned long count = 0;
    static __thread time_t previous_time = 0;
    static __thread char previous_nodeaddr[LOGSTRSZ];
    // Print every 100th access
    const unsigned long count_trigger = 1000;
    // Print every 60th second
    const time_t time_trigger = 60;
    time_t current_time;
    bool print_it;
    int nodeaddr_changed;

    ++count;
    // Track curl accesses to this filesystem node
    // fusedav.conf will always set SECTION_ENHANCED to 6 in LOG_SECTIONS. These log entries will always
    // print, but at INFO will be easier to filter out
    // We're overloading the journal, so only log every print_count_trigger count or every print_interval time
    current_time = time(NULL);
    // Always print the first one. Then print if our interval has expired
    print_it = (previous_time == 0) || (current_time - previous_time >= time_trigger);
    // If this is the very first call, initialize previous to current
    if (previous_nodeaddr[0] == '\0') strncpy(previous_nodeaddr, nodeaddr, LOGSTRSZ);
    nodeaddr_changed = strncmp(nodeaddr, previous_nodeaddr, LOGSTRSZ);
    // Also print if we have exceeded count
    if (print_it || count >= count_trigger || nodeaddr_changed) {
        if (nodeaddr_changed) --count; // Print for previous node, which doesn't include this call, then for this call
        log_print(LOG_INFO, SECTION_ENHANCED,
            "curl iter %d on path %s -- fusedav.%s.server-%s.attempts:%lu|c", iter, path, filesystem_cluster, previous_nodeaddr, count);
        count = 0;
        previous_time = current_time;
        if (nodeaddr_changed) {
            log_print(LOG_INFO, SECTION_ENHANCED,
                "curl iter %d changed to path %s -- fusedav.%s.server-%s.attempts:%lu|c",
                iter, path, filesystem_cluster, nodeaddr, 1);
            strncpy(previous_nodeaddr, nodeaddr, LOGSTRSZ);
        }
    }

    if (res != CURLE_OK) {
        // Track errors
        print_errors(iter, "curl_failures", fcn_name, res, response_code, path);
        increment_node_failure(nodeaddr, res, response_code);
    }
    else if (response_code >= 500) {
        // Track errors
        print_errors(iter, "status500_failures", fcn_name, res, response_code, path);
        increment_node_failure(nodeaddr, res, response_code);
    }
    // If iter > 0 then we failed on iter 0. If we didn't fail on this iter, then we recovered. Log it.
    else if (iter > 0) {
        log_print(LOG_INFO, SECTION_ENHANCED,
            "%s: curl iter %d on path %s -- fusedav.%s.server-%s.recoveries:1|c", fcn_name, iter, path, filesystem_cluster, nodeaddr);
        log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT,
            "%s: curl iter %d on path %s -- fusedav.%s.server-%s.recoveries", fcn_name, iter, path, filesystem_cluster, nodeaddr);
        increment_node_success(nodeaddr);
    }
    else if (iter != -1) { // -1 is like a sentinel for when we call this during switch to new handle
        increment_node_success(nodeaddr);
    }
}

static void common_aggregate_log_print(unsigned int log_level, unsigned int section, const char *cluster, const char *server,
        const char *name, time_t *previous_time, const char *description1, unsigned long *count1, unsigned long value1,
        const char *description2, long *count2, long value2) {

    /* Print aggregate stats. It is in this file for ready access to server names and the ability
     * to call it on thread destroy.
     */
    // Print every 100th access
    const unsigned long count_trigger = 1000;
    // Print every 60th second
    const time_t time_trigger = 60;
    time_t current_time;
    bool print_it = false;

    *count1 += value1;
    if (count2) *count2 += value2;
    // Track curl accesses to this filesystem node
    // fusedav.conf will always set SECTION_ENHANCED to 6 in LOG_SECTIONS. These log entries will always
    // print, but at INFO will be easier to filter out
    // We're overloading the journal, so only log every print_count_trigger count or every print_interval time
    current_time = time(NULL);

    // if previous_time is NULL then this is a pair to an earlier call, and we always print it
    if (previous_time != NULL) {
        // Always print the first one. Then print if our interval has expired
        print_it = (*previous_time == 0) || (current_time - *previous_time >= time_trigger);
    }
    else {
        print_it = true;
    }
    // Also print if we have exceeded count
    if (print_it || *count1 >= count_trigger) {
        if (cluster && server) {
            log_print(log_level, section, "%s: fusedav.%s.server-%s.%s:%lu|c", name, filesystem_cluster, nodeaddr, description1, *count1);
        }
        else if(cluster) {
            log_print(log_level, section, "%s: fusedav.%s.%s:%lu|c", name, filesystem_cluster, description1, *count1);
        }
        else {
            log_print(log_level, section, "%s: fusedav.%s:%lu|c", name, description1, *count1);
        }
        if (description2 && count2) {
            long result;
            // Cheating. We just know that the second value is a latency total which needs to
            // be passed through as an average latency.
            if (*count1 == 0) result = 0;
            else result = (*count2 / *count1);
            if (cluster && server) {
                log_print(log_level, section, "%s: fusedav.%s.server-%s.%s:%ld|c", name, filesystem_cluster, nodeaddr, description2, result);
            }
            else if (cluster) {
                log_print(log_level, section, "%s: fusedav.%s.%s:%ld|c", name, filesystem_cluster, description2, result);
            }
            else {
                log_print(log_level, section, "%s: fusedav.%s:%ld|c", name, description2, result);
            }
            *count2 = 0;
        }
        *count1 = 0;
        if (previous_time) *previous_time = current_time;
    }
    return;
}

void aggregate_log_print_server(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
        const char *description1, unsigned long *count1, unsigned long value1,
        const char *description2, long *count2, long value2) {

    // pass in filesystem_cluster and nodeaddr
    common_aggregate_log_print(log_level, section, filesystem_cluster, nodeaddr, name, previous_time,
        description1, count1, value1, description2, count2, value2);

}

void aggregate_log_print_local(unsigned int log_level, unsigned int section, const char *name, time_t *previous_time,
        const char *description1, unsigned long *count1, unsigned long value1,
        const char *description2, long *count2, long value2) {

    // don't pass in filesystem_cluster and nodeaddr
    common_aggregate_log_print(log_level, section, NULL, NULL, name, previous_time,
        description1, count1, value1, description2, count2, value2);

}

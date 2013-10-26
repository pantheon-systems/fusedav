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

#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "session.h"

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

static char *ca_certificate = NULL;
static char *client_certificate = NULL;
static char *base_url = NULL;
static char *filesystem_domain = NULL;
static char *filesystem_port = NULL;

const char *get_base_url(void) {
    return base_url;
}

int session_config_init(char *base, char *ca_cert, char *client_cert, char *filesystem_domain_in, char *filesystem_port_in) {
    size_t base_len;

    assert(base);

    if (curl_global_init(CURL_GLOBAL_ALL)) {
        log_print(LOG_CRIT, SECTION_SESSION_DEFAULT, "session_config_init: Failed to initialize libcurl.");
        return -1;
    }

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
            log_print(LOG_WARNING, SECTION_SESSION_DEFAULT, "session_config_init: Remapping deprecated certificate path: %s", client_certificate);
            strncpy(client_certificate + strlen(client_certificate) - 4, ".pem", 4);
        }

        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_config_init: Using client certificate at path: %s", client_certificate);
    }

    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "session_config_init: Using filesystem domain and port: %s %s", filesystem_domain_in, filesystem_port_in);
    if (filesystem_domain_in != NULL && filesystem_port_in != NULL) {
        filesystem_domain = strdup(filesystem_domain_in);
        filesystem_port = strdup(filesystem_port_in);
    }
    else {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "session_config_init: Null filesystem domain or port: %s %s", filesystem_domain_in, filesystem_port_in);
    }

    return 0;
}

void session_config_free(void) {
    free(base_url);
    free(ca_certificate);
    free(client_certificate);
}

static void session_destroy(void *s) {
    CURL *session = s;
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Destroying cURL session.");
    assert(s);
    curl_easy_cleanup(session);
}

static void session_tsd_key_init(void) {
    log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "session_tsd_key_init()");
    pthread_key_create(&session_tsd_key, session_destroy);
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
#define LOGSTRSZ 80
static void print_ipaddr_pair(char *msg) {
    char addr[LOGSTRSZ];
    char *end;
    // msg+9 takes us past "  Trying ". We assume the ip addr starts there.
    strncpy(addr, msg + 9, LOGSTRSZ);
    addr[LOGSTRSZ - 1] = '\0'; // Just make sure it's null terminated
    // end finds the first two dots after the ip addr. We put a zero there
    // to turn the original string into just the IP addr.
    end = strstr(addr, "..");
    end[0] = '\0';
    // We print the key=value pair.
    // REVIEW: I'm not sure of the exact syntax of this key=value pair so
    // that our logging facility detects and turns it into a stat.
    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Using filesystem node @ Domain=%s", addr);
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
                log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "cURL: %s", msg);
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

CURL *session_get_handle(void) {
    CURL *session;

    pthread_once(&session_once, session_tsd_key_init);

    if ((session = pthread_getspecific(session_tsd_key)))
        return session;

    log_print(LOG_NOTICE, SECTION_SESSION_DEFAULT, "Opening cURL session.");
    session = curl_easy_init();
    pthread_setspecific(session_tsd_key, session);

    return session;
}

// Return value should be freed using curl_free().
char *escape_except_slashes(CURL *session, const char *path) {
    size_t path_len = strlen(path);
    char *mutable_path = strndup(path, path_len);
    char *escaped_path = NULL;
    size_t escaped_path_pos;

    if (mutable_path == NULL) {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "Could not allocate memory in strndup for escape_except_slashes.");
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
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "Could not allocate memory in curl_easy_escape for escape_except_slashes.");
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

/* For reference, keep the different sockaddr structs available for inspection

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

// All pointers to socket address structures are often cast to pointers
// to this type before use in various functions and system calls:

struct sockaddr {
    unsigned short    sa_family;    // address family, AF_xxx
    char              sa_data[14];  // 14 bytes of protocol address
};


// IPv4 AF_INET sockets:

struct sockaddr_in {
    short            sin_family;   // e.g. AF_INET, AF_INET6
    unsigned short   sin_port;     // e.g. htons(3490)
    struct in_addr   sin_addr;     // see struct in_addr, below
    char             sin_zero[8];  // zero this if you want to
};

struct in_addr {
    unsigned long s_addr;          // load with inet_pton()
};


// IPv6 AF_INET6 sockets:

struct sockaddr_in6 {
    u_int16_t       sin6_family;   // address family, AF_INET6
    u_int16_t       sin6_port;     // port number, Network Byte Order
    u_int32_t       sin6_flowinfo; // IPv6 flow information
    struct in6_addr sin6_addr;     // IPv6 address
    u_int32_t       sin6_scope_id; // Scope ID
};

struct in6_addr {
    unsigned char   s6_addr[16];   // load with inet_pton()
};


// General socket address holding structure, big enough to hold either
// struct sockaddr_in or struct sockaddr_in6 data:

struct sockaddr_storage {
    sa_family_t  ss_family;     // address family

    // all this is padding, implementation specific, ignore it:
    char      __ss_pad1[_SS_PAD1SIZE];
    int64_t   __ss_align;
    char      __ss_pad2[_SS_PAD2SIZE];
};
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

// The string we pass to curl is domain:port:ip:address, so leave room
#define IPSTR_SZ 128
// Maximum number of A records (bzw IP addresses) our domain can resolve to
#define MAX_NODES 32

static int construct_resolve_slist(CURL *session, bool force) {
    // This will be the list of randomized addresses we pass to curl
    // static so it persists between calls
    static struct curl_slist *resolve_slist = NULL;
    // This will hold the ip addresses in the order they get returned from gethostaddr; later to be randomized
    // for resolve_slist.
    char prelist[MAX_NODES][IPSTR_SZ];
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
    const time_t resolve_slist_timeout = 30; 
    // Keep a timer; at periodic intervals we reset the resolve_slist.
    // static so it persists between calls
    static time_t prevtime = 0;
    time_t curtime;
    // number of ip addresses returned from getaddrinfo
    int count = 0;
    // result from function
    int res = -1;
    // For srand
    struct timespec ts;

    // If the list is still young, just return. The current list is still valid
    curtime = time(NULL);
    if (!force && curtime - prevtime < resolve_slist_timeout) {
        res = 0; // Not an error
        log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "construct_resolve_slist: timeout has not elapsed; return with current slist");
        // goto finish so we can still set CURLOPT_RESOLVE; otherwise libcurl will do its default thing
        goto finish;
    }
    // Ready for the next invocation.
    prevtime = curtime;

    // Free the current list
    curl_slist_free_all(resolve_slist);
    resolve_slist = NULL;
    // Turn hints off
    memset(&hints, 0, sizeof(struct addrinfo));
    // By setting ai_family to 0, we allow both IPv4 and IPv6
    // By setting ai_protocol to 0, we allow any socket protocol (???)
    // Set hints to ensure SOCK_STREAM. Otherwise we get multiple copies
    // of each IP address back
    hints.ai_socktype = SOCK_STREAM;

    // get list from getaddrinfo
    log_print(LOG_INFO, SECTION_SESSION_DEFAULT, "construct_resolve_slist: calling getaddrinfo with %s %s", filesystem_domain, filesystem_port);
    res = getaddrinfo(filesystem_domain, filesystem_port, &hints, &aihead);
    if(res) {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "construct_resolve_slist: getaddrinfo returns error: %d (%s)", res, gai_strerror(res));
        // This is an error. We do not set CURLOPT_RESOLVE, so libcurl will
        // do its default thing. If its call to getaddrinfo succeeds, the
        // first IP will be used (breaks load balancing).  If it fails as it does here,
        // it will do its own error processing.
        return res;
    }

    /* getaddrinfo returned a list of addrinfo structs (for our purposes, IP addresses).
     * Some of those structs represent IPv4, others IPv6. We decide which is which
     * by the addrlen which gets returned (16 for IPv4, 26 (28?) for IPv6.
     * The components of the address we need are in an array of chars or ints, so
     * we pull them out one by one and append them to the string we are building.
     * Ultimately, this string, per libcurl's CURLOPT_RESOLVE requirements,
     * will be DOMAIN:PORT:IP-ADDRESS
     */
    for (ai = aihead; ai != NULL; ai = ai->ai_next) {
        // Holds the string we are constructing
        char ipstr[IPSTR_SZ];
        // Each element in the address. An IPv4 address can have a string length
        // of 3 (255.), so a size of 4 to hold the null
        char octet[4];

        // The domain comes first, followed by a colon per libcurl's requirement
        strncpy(ipstr, filesystem_domain, IPSTR_SZ);
        ipstr[IPSTR_SZ - 1] = '\0'; // Just make sure it's null terminated
        strcat(ipstr, ":");

        // The port and colon come next.
        strcat(ipstr, filesystem_port);
        strcat(ipstr, ":");

        // An IPv4 struct
        if (ai->ai_family == AF_INET) {
            /* The basic struct sockaddr gets overlaid with the IPv4 version
             * struct sockaddr_in. The relevant field is a struct in_addr, which
             * has a single field s_addr, which is a long. We treat that
             * as 4 independent chars. Let's hope we don't change endianness!
             * The structures are in the comment above this function.
             */
            struct sockaddr_in *ipv4_sockaddr = (struct sockaddr_in *)ai->ai_addr;
            char *ex = (char *)&ipv4_sockaddr->sin_addr.s_addr;
            // There are four elements to the IPv4 address (127.1.1.1)
            for (int idx = 0; idx < 4; idx++) {
                // dot between elements; skip a dot in front and rear.
                if (idx != 0) strcat(ipstr, ".");
                // Grab the element and append to the string
                sprintf(octet, "%d", ex[idx]);
                strcat(ipstr, octet);
            }
        }
        // An IPv6 struct
        else if (ai->ai_family == AF_INET6) {
            // 2001:4801:7820:75:78c8:1542:ff10:a6cf
            /* The basic struct sockaddr gets overlaid with the IPv6 version
             * struct sockaddr_in6. The relevant field is an in6_addr, which
             * has a single field s6_addr, which is a char array of size 16.
             * Each address element is made up of two of these chars.
             */
            struct sockaddr_in6 *ipv6_sockaddr = (struct sockaddr_in6 *)ai->ai_addr;
            for (int idx = 0; idx < 16; idx++) {
                // Before the next pair of octets, put a dot. Avoid a colon at the start and end
                // Concatenate 2 octets before putting in the colon
                if (idx % 2 == 0 && idx != 0) strcat(ipstr, ":");
                // Grab an item and append to string
                sprintf(octet, "%02x", ipv6_sockaddr->sin6_addr.s6_addr[idx]);
                strcat(ipstr, octet);
            }
        }
        // Store the string in our "pre" list. It will be in sorted order. We randomize later
        strcpy(prelist[count++], ipstr);
        log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "construct_resolve_slist: entering %s into prelist[%d]", prelist[count - 1], count - 1);
    }

    // Randomize!
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand(ts.tv_nsec * ts.tv_sec);
    // Count is the number of addresses we processed above
    for (int idx = 0; idx < count; idx++) {
        bool found = false;
        // The random one we will take
        int pick;
        // Which element we are at
        int iter = 0;
        pick = rand() % (count - idx);
        for (int jdx = 0; jdx < count; jdx++) {
            /* When we find the entry we remove it and put it next in the slist which
             * we will pass to curl_easy_setopt. We then "zero out" the entry. Effectively,
             * we are shortening the list, without moving all the elements.
             * There is assuredly a more efficient way to do this (we are O(n2)), but
             * we only expect small numbers of nodes that we will process here.
             */
            // If this is a non-zero entry in prelist and the pick equals the iter,
            // we have found our match!
            if (pick == iter && prelist[jdx][0] != '\0') {
                // add it to the slist
                resolve_slist = curl_slist_append(resolve_slist, prelist[jdx]);
                log_print(LOG_DEBUG, SECTION_SESSION_DEFAULT, "construct_resolve_slist: inserting into resolve_slist: %s [%d]", prelist[jdx], iter);
                // zero it out so it won't be seen in the future
                prelist[jdx][0] = '\0';
                // This is just a sanity check in case this code is defective and we need to report the error
                found = true;
                break;
            }
            // The iter increments if the current entry is a non-zero one
            if (prelist[jdx][0] != '\0') ++iter;
        }
        // This should only happen if I'm a chucklehead
        if (!found) log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "construct_resolve_slist: construct_resolve_slist: Item for resolve_slist not found::Count:idx:pick:iter %d:%d:%d:%d", count, idx, pick, iter);
    }

    // If we got here, we are golden!
    res = 0;

    // If we create a new list we need to make the curl_easy_setopt call.
    // But if we are within our timeout period and do not create a new list,
    // we still need to make the call with the current, unchanged list.
    // Otherwise, libcurl will revert to its default, call getaddrinfo
    // on its own, and return the unsorted, unbalanced, first entry.

    finish:
    curl_easy_setopt(session, CURLOPT_RESOLVE, resolve_slist);

    return res;
}

CURL *session_request_init(const char *path, const char *query_string) {
    CURL *session;
    char *full_url = NULL;
    char *escaped_path;
    int error;
    bool force = false;

    session = session_get_handle();

    curl_easy_reset(session);
    curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, session_debug);
    curl_easy_setopt(session, CURLOPT_VERBOSE, 1L);

    escaped_path = escape_except_slashes(session, path);
    if (escaped_path == NULL) {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "session_request_init: Allocation failed in escape_except_slashes.");
        return NULL;
    }

    if (query_string == NULL) {
        asprintf(&full_url, "%s%s", get_base_url(), escaped_path);
    }
    else {
        asprintf(&full_url, "%s%s?%s", get_base_url(), escaped_path, query_string);
    }
    if (full_url == NULL) {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "session_request_init: Allocation failed in asprintf.");
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

    error = construct_resolve_slist(session, force);
    /* If we get an error from construct_resolve_slist, we didn't set up the
     * randomized slist and call CURLOPT_RESOLVE. libcurl will revert to calling
     * getaddrinfo on its own, and use the first, sorted address it returns.
     * This is not incorrect, but if it happens often, we will not be balancing
     * the load across the multiple nodes.
     */
    if (error) {
        log_print(LOG_ERR, SECTION_SESSION_DEFAULT, "session_request_init: Error creating randomized resolve slist; libcurl can survive but with load imbalance");
    }

    return session;
}

/* Allow us to retry curl_easy_perform in the presence of errors.
 * This is in conjunction with the way we get IP addresses that a
 * given domain resolves to and randomize them.
 */
int retry_curl_easy_perform(CURL *session) {
    CURLcode res;
    long response_code;
    bool force = true; // Force us to recreate the randomized slist for CURLOPT_RESOLVE
    int iter = 0;
    // REVIEW: How many retries should we do?
    // If we see certain errors, retry
    const int max_tries = 4;
    
    res = curl_easy_perform(session);
    curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);
    while ((res != CURLE_OK || response_code >= 500) && iter < max_tries) {
        log_print(LOG_WARNING, SECTION_SESSION_DEFAULT, "retry_curl_easy_perform: res %d %s; response_code %d", res, curl_easy_strerror(res), response_code);
        // Force recreation of the random slist
        construct_resolve_slist(session, force);
        res = curl_easy_perform(session);
        curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);
        ++iter;
    }
    return res;
}

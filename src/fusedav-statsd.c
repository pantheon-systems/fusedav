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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "log.h"
#include "log_sections.h"
#include "fusedav-statsd.h"
#include "session.h"

// e.g. fusedav.valhallayolo1b.server-104_130_221_144.exceeded-time-small-GET-latency (82 characters)
#define STATS_MSG_LEN 128
// Needs to hold the prefix for a stat, e.g. fusedav
#define STATS_PREFIX_LEN 32

/* Socket and server for function sendto */
/* server is a sockaddr_storage so it can hold either IPV4 or IPV6 */
struct stats_server {
    char stats_prefix[STATS_PREFIX_LEN];
    struct sockaddr_storage server;
    int serverlen;
    int sock;
};

// A single one for the whole application.
struct stats_server server;

/* Create the socket */
static int set_socket(int family, int type, int protocol){
    errno = 0;
    server.sock = socket(family, type, protocol);
    if (server.sock == -1) {
        // NOTICE rather than ERR, since we assume the calling code can try again
        log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "set_socket: Failed: family %d; type %d; protocol %d; errno: %d (%s)", 
                family, type, protocol, errno, strerror(errno));
    }
    return server.sock;
}

/* Get the socket and the server components.
 * Get the list of addresses via getaddrinfo that the metrics URL fronts.
 * The first socket we can create wins. (This might not be the best strategy.)
 */
static int set_addr(const char *domain, const char *port, struct stats_server *svr) {
    int error;
    long iport;
    char *endptr;
    const struct addrinfo *ai;
    struct addrinfo *aihead;
    struct addrinfo hints;

    const char *funcname = "set_addr";

    errno = 0;
    iport = strtol(port, &endptr, 10);
    if ((errno == ERANGE && (iport == LONG_MAX || iport == LONG_MIN)) || (errno != 0 && iport == 0)) {
        // Can't continue without a port
        log_print(LOG_CRIT, SECTION_STATS_DEFAULT, "%s: FAILURE. Invalid port %s", 
                funcname, port);
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // allow IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM;
    // Other hints fields are possible, but we would pick the ones with 0 value anyway

    // Make the call to getaddrinfo and set the world in motion
    error = getaddrinfo(domain, port, &hints, &aihead);
    if (error) {
        // Can't continue without getaddrinfo info
        log_print(LOG_CRIT, SECTION_STATS_DEFAULT, "%s: FAILURE. getaddrinfo returns error %d (%s)", 
                funcname, error, gai_strerror(error));
        return -1;
    }

    /* Loop through the addrinfo items returned by the call to getaddrinfo until
     * one is found which succeeds in creating the socket.
     * Note that the output from a particular node will return the items
     * in the same order each time. See reference section at bottom of page
     * for more information.
     * This means that one node will always direct traffic to the same server.
     * Since sort order depends on each node's own IP address, and our nodes
     * have varying IP addresses in the parts of the address which trigger the
     * sort order, we should overall direct to servers in a distributed way.
     * If this is not adequate, change the following to sort of randomly
     * pick one of the entries.
     */
    for (ai = aihead; ai != NULL; ai = ai->ai_next) {
        int sock = -1;
        // An IPv4 struct
        if (ai->ai_family == AF_INET) {
            memcpy(&(((struct sockaddr_in *)&(svr->server))->sin_addr), 
                    &((struct sockaddr_in *)(ai->ai_addr))->sin_addr, 
                    sizeof(struct in_addr));
            ((struct sockaddr_in *)&(svr->server))->sin_family = ai->ai_family;
            ((struct sockaddr_in *)&(svr->server))->sin_port = htons((unsigned short)iport);
            svr->serverlen = sizeof(struct sockaddr_in);
        }
        // An IPv6 struct
        else if (ai->ai_family == AF_INET6) {
            memcpy(&(((struct sockaddr_in6 *)&(svr->server))->sin6_addr), 
                    &((struct sockaddr_in6 *)(ai->ai_addr))->sin6_addr, 
                    sizeof(struct in6_addr));
            ((struct sockaddr_in6 *)&(svr->server))->sin6_family = ai->ai_family;
            ((struct sockaddr_in6 *)&(svr->server))->sin6_port = htons((u_int16_t)iport);
            svr->serverlen = sizeof(struct sockaddr_in6);
        }
        else {
            log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "%s: ai_family not IPv4 nor IVv6 [%d]",
                funcname, ai->ai_family);
            continue;
        }
        // Can we create a socket from what we got?
        sock = set_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == -1) {
            // Let's get the human readable IP string to get a better handle on what failed
            char ipaddr[INET6_ADDRSTRLEN];
            if (ai->ai_family == AF_INET) {
                if(inet_ntop(ai->ai_family, &(((struct sockaddr_in *)ai->ai_addr)->sin_addr), ipaddr, INET6_ADDRSTRLEN)) {
                    log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "%s: set_socket returns -1 on addr %s", funcname, ipaddr);
                }
            }
            // An IPv6 struct
            else if (ai->ai_family == AF_INET6) {
                if(inet_ntop(ai->ai_family, &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN)) {
                    log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "%s: set_socket returns -1 on addr %s", funcname, ipaddr);
                }
            }
            // Failing to get a socket is not fatal. Try again.
            continue;
        } else if (logging(LOG_NOTICE, SECTION_STATS_DEFAULT)) { // Don't do all the work if we aren't logging
            // Let's get the human readable IP string
            char ipaddr[INET6_ADDRSTRLEN];
            if (ai->ai_family == AF_INET) {
                if(inet_ntop(ai->ai_family, &(((struct sockaddr_in *)ai->ai_addr)->sin_addr), ipaddr, INET6_ADDRSTRLEN)) {
                    log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "%s: set_socket succeeds on addr %s", funcname, ipaddr);
                }
            }
            // An IPv6 struct
            else if (ai->ai_family == AF_INET6) {
                if(inet_ntop(ai->ai_family, &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr), ipaddr, INET6_ADDRSTRLEN)) {
                    log_print(LOG_NOTICE, SECTION_STATS_DEFAULT, "%s: set_socket succeeds on addr %s", funcname, ipaddr);
                }
            }
        }
        break;
    }

    freeaddrinfo(aihead);

    // We cycled through all getaddrinfo items, and ended up with nothing. Major failure.
    if (!ai) {
        log_print(LOG_CRIT, SECTION_STATS_DEFAULT, "%s: FAILURE. Couldn't get any sockets.", funcname);
        return -1;
    }

    // All's good!
    return 0;
}

/* Initialize the server and socket */
int stats_init(const char *domain, const char *port) {

    memset(&server, 0, sizeof(server));
    // stats_prefix is, after being set here, an unchanging global string
    snprintf(server.stats_prefix, STATS_PREFIX_LEN, "fusedav");

    if (set_addr(domain, port, &server)) {
        // FAILURE; pass it on
        return -1;
    }
    return 0;
}

// Cleanup when fusedav exits
int stats_close(void) {
    if (server.sock != -1) {
        close(server.sock);
        server.sock = -1;
    }
    return 0;
}

/*  Send the stat. */
static int stats_send(const char *statmsg) {
    int bytes;

    errno = 0;
    bytes = sendto(server.sock, statmsg, strlen(statmsg), 0, (struct sockaddr *)&(server.server), server.serverlen);
    if (bytes == -1) {
        // Since the is UDP, sendto can't know if the message was never delivered. Error means local error that
        // it can detect.
        log_print(LOG_CRIT, SECTION_STATS_DEFAULT, "stats_send: Error, errno: %d, %s. Couldn't send stat \"%s\"", 
                errno, strerror(errno), statmsg);
    } else if (logging(LOG_INFO, SECTION_STATS_DEFAULT)) {
        if (((struct sockaddr_storage *)&(server.server))->ss_family == AF_INET) {
            char ipaddr[INET6_ADDRSTRLEN];
            unsigned short port;
            struct in_addr addr;
            struct sockaddr_in *srv;
            srv = (struct sockaddr_in *)&(server.server);
            port = ntohs(srv->sin_port);
            addr = srv->sin_addr;
            inet_ntop(srv->sin_family, &addr, ipaddr, INET6_ADDRSTRLEN);
            log_print(LOG_DEBUG, SECTION_STATS_DEFAULT, "stats_send: INET: bytes: %d; sock: %d; port: %d; serverlen: %d; addr: %s; msg: %s", 
                    bytes, server.sock, port, server.serverlen, ipaddr, statmsg);
        } else if (((struct sockaddr_storage *)&(server.server))->ss_family == AF_INET6) {
            log_print(LOG_DEBUG, SECTION_STATS_DEFAULT, "stats_send: INET6: msg: %s", statmsg);
        }
    }

    return 0;
}

static int compose_message(const char *statname, const signed int value, char *type, char *msg, const char *cluster, const char *node) {
    if (node) {
        return snprintf(msg, STATS_MSG_LEN, "%s.%s.server-%s.%s:%d|%s\n", 
                server.stats_prefix, cluster, node, statname, value, type);
    } else if (cluster) {
        return snprintf(msg, STATS_MSG_LEN, "%s.%s.%s:%d|%s\n", 
                server.stats_prefix, cluster, statname, value, type);
    } else {
        return snprintf(msg, STATS_MSG_LEN, "%s.%s:%d|%s\n", 
                server.stats_prefix, statname, value, type);
    }

}

static int stats_counter_common(const char *statname, const int value, const char *cluster, const char *node) {
    int error;
    int res;
    char msg[STATS_MSG_LEN];
    char type[] = "c";
    res = compose_message(statname, value, type, msg, cluster, node);
    if (res < 0) {
        return res;
    }
    error = stats_send(msg);
    return error;
}

int stats_counter(const char *statname, const int value) {
    return stats_counter_common(statname, value, get_filesystem_cluster(), get_nodeaddr());
}

int stats_counter_cluster(const char *statname, const int value) {
    return stats_counter_common(statname, value, get_filesystem_cluster(), NULL);
}

int stats_counter_local(const char *statname, const int value) {
    return stats_counter_common(statname, value, NULL, NULL);
}

static int stats_gauge_common(const char *statname, const int value, const char *cluster, const char *node) {
    int error;
    int res;
    char msg[STATS_MSG_LEN];
    char type[] = "g";
    res = compose_message(statname, value, type, msg, cluster, node);
    if (res < 0) {
        return res;
    }
    error = stats_send(msg);
    return error;
}

int stats_gauge(const char *statname, const int value) {
    return stats_gauge_common(statname, value, get_filesystem_cluster(), get_nodeaddr());
}

int stats_gauge_cluster(const char *statname, const int value) {
    return stats_gauge_common(statname, value, get_filesystem_cluster(), NULL);
}

int stats_gauge_local(const char *statname, const int value) {
    return stats_gauge_common(statname, value, NULL, NULL);
}

static int stats_timer_common(const char *statname, const int value, const char *cluster, const char *node) {
    int error;
    int res;
    char msg[STATS_MSG_LEN];
    char type[] = "ms";
    res = compose_message(statname, value, type, msg, cluster, node);
    if (res < 0) {
        return res;
    }
    error = stats_send(msg);
    return error;
}

int stats_timer(const char *statname, const int value) {
    return stats_timer_common(statname, value, get_filesystem_cluster(), get_nodeaddr());
}

int stats_timer_cluster(const char *statname, const int value) {
    return stats_timer_common(statname, value, get_filesystem_cluster(), NULL);
}

int stats_timer_local(const char *statname, const int value) {
    return stats_timer_common(statname, value, NULL, NULL);
}

/* For reference: 
 * 
 * A couple of urls which describe getaddrinfo, particularly its sort order:
 * https://books.google.com/books?id=kVBn2Zx-pnkC&pg=PA154&lpg=PA154&dq=getaddrinfo%20sorts%20entries&source=bl&ots=7mVAg-Hoyf&sig=BkQvv31KMtXfwnsyfyEe_LDpoOE&hl=en&sa=X&ved=0ahUKEwip1dev3JvMAhXCbz4KHVcVAIQQ6AEIIzAB#v=onepage&q=getaddrinfo%20sorts%20entries&f=false
 *
 * https://daniel.haxx.se/blog/2012/01/03/getaddrinfo-with-round-robin-dns-and-happy-eyeballs/
 *
 * keep the different sockaddr structs available for inspection
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

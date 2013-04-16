/***
  This file is part of fusedav.

  fusedav is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  fusedav is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.

  You should have received a copy of the GNU General Public License
  along with fusedav; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#include <uriparser/Uri.h>
#include <curl/curl.h>

// Included to eventually use res_query() for lookups and failover.
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "log.h"
#include "util.h"
#include "session.h"
#include "fusedav.h"

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

static char *ca_certificate = NULL;
static char *client_certificate = NULL;
static char *base_url = NULL;
static char *base_host = NULL;
static char *base_directory = NULL;

const char *get_base_url(void) {
    return base_url;
}

const char *get_base_directory(void) {
    return base_directory;
}

const char *get_base_host(void) {
    return base_host;
}

static void set_bases(const char *url) {
    UriParserStateA state;
    UriUriA uri;
    char *base;
    off_t base_pos, addition;

    state.uri = &uri;
    if (uriParseUriA(&state, url) != URI_SUCCESS) {
        uriFreeUriMembersA(&uri);
    }

    base = malloc(strlen(url));
    base[0] = '/';
    base_pos = 0;

    for (UriPathSegmentA *cur = uri.pathHead; cur != NULL; cur = cur->next) {
        ++base_pos;
        addition = cur->text.afterLast - cur->text.first;
        strncpy(base + base_pos, cur->text.first, addition);
        base_pos += addition;
        base[base_pos] = '/';
    }

    // Keep the slash as the base directory if there's nothing else.
    if (base_pos == 1)
        base_pos = 1;

    base[base_pos] = '\0';

    // @TODO: Investigate. This seems to be necessary, but I don't think it should be.
    if (base[base_pos - 1] == '/' && base_pos > 1)
        base[base_pos - 1] = '\0';

    // Assemble the base host.
    base_host = malloc(strlen(url));

    // Scheme.
    addition = uri.scheme.afterLast - uri.scheme.first;
    strncpy(base_host, uri.scheme.first, addition);
    base_pos = addition;
    base_host[base_pos++] = ':';
    base_host[base_pos++] = '/';
    base_host[base_pos++] = '/';

    // Host.
    addition = uri.hostText.afterLast - uri.hostText.first;
    strncpy(base_host + base_pos, uri.hostText.first, addition);
    base_pos += addition;
    base_host[base_pos++] = ':';

    // Port.
    addition = uri.portText.afterLast - uri.portText.first;
    strncpy(base_host + base_pos, uri.portText.first, addition);
    base_pos += addition;
    base_host[base_pos++] = '\0';

    uriFreeUriMembersA(&uri);

    log_print(LOG_INFO, "Using base directory: %s", base);
    log_print(LOG_INFO, "Using base host: %s", base_host);

    base_directory = base;
}

int session_config_init(char *base, char *ca_cert, char *client_cert) {
    size_t base_len;

    assert(base);

    if (curl_global_init(CURL_GLOBAL_ALL)) {
        log_print(LOG_CRIT, "Failed to initialize libcurl.");
        return -1;
    }

    // Ensure the base URL has a trailing slash.
    base_len = strlen(base);
    if (base[base_len - 1] == '/')
        base_url = strdup(base);
    else
        asprintf(&base_url, "%s/", base);
    set_bases(base_url);

    if (ca_cert != NULL)
        ca_certificate = strdup(ca_cert);

    if (client_cert != NULL) {
        client_certificate = strdup(client_cert);

        // Repair p12 to point to pem for now.
        if (strcmp(client_certificate + strlen(client_certificate) - 4, ".p12") == 0) {
            log_print(LOG_WARNING, "Remapping deprecated certificate path: %s", client_certificate);
            strncpy(client_certificate + strlen(client_certificate) - 4, ".pem", 4);
        }

        log_print(LOG_INFO, "Using client certificate at path: %s", client_certificate);
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
    log_print(LOG_NOTICE, "Destroying cURL session.");
    assert(s);
    curl_easy_cleanup(session);
}

static void session_tsd_key_init(void) {
    log_print(LOG_DEBUG, "session_tsd_key_init()");
    pthread_key_create(&session_tsd_key, session_destroy);
}

static int session_debug(__unused CURL *handle, curl_infotype type, char *data, size_t size, __unused void *userp) {
    if (type == CURLINFO_TEXT) {
        char *msg = malloc(size + 1);
        strncpy(msg, data, size);
        msg[size] = '\0';
        if (msg[size - 1] == '\n')
            msg[size - 1] = '\0';
        if (msg != NULL) {
            log_print(LOG_INFO, "cURL: %s", msg);
        }
        free(msg);
    }
    return 0;
}

CURL *session_get_handle(void) {
    CURL *session;

    pthread_once(&session_once, session_tsd_key_init);

    if ((session = pthread_getspecific(session_tsd_key)))
        return session;

    log_print(LOG_NOTICE, "Opening cURL session.");
    session = curl_easy_init();
    pthread_setspecific(session_tsd_key, session);

    return session;
}

CURL *session_request_init(const char *path) {
    CURL *session;
    char *full_url = NULL;

    session = session_get_handle();

    curl_easy_reset(session);
    curl_easy_setopt(session, CURLOPT_DEBUGFUNCTION, session_debug);
    curl_easy_setopt(session, CURLOPT_VERBOSE, 1L);

    asprintf(&full_url, "%s%s", get_base_host(), path);
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    log_print(LOG_INFO, "Initializing request to URL: %s", full_url);
    free(full_url);

    //curl_easy_setopt(session, CURLOPT_USERAGENT, "FuseDAV/" PACKAGE_VERSION);
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    if (ca_certificate != NULL)
        curl_easy_setopt(session, CURLOPT_CAINFO, ca_certificate);
    if (client_certificate != NULL) {
        curl_easy_setopt(session, CURLOPT_SSLCERT, client_certificate);
        curl_easy_setopt(session, CURLOPT_SSLKEY, client_certificate);
    }
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(session, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(session, CURLOPT_CONNECTTIMEOUT_MS, 100);
    curl_easy_setopt(session, CURLOPT_TIMEOUT, 600);
    curl_easy_setopt(session, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(session, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    return session;
}

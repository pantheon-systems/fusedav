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

#include <curl/curl.h>

#include "log.h"
#include "session.h"
#include "fusedav.h"

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

static char *ca_certificate = NULL;
static char *client_certificate = NULL;
static char *base_url = NULL;

const char *get_base_url(void) {
    return base_url;
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

    if (ca_cert != NULL)
        ca_certificate = strdup(ca_cert);

    if (client_cert != NULL)
        client_certificate = strdup(client_cert);

    // Repair p12 to point to pem for now.
    if (strcmp(client_certificate + strlen(client_certificate) - 4, "p12") == 0)
        strncpy(client_certificate + strlen(client_certificate) - 4, "pem", 3);

    log_print(LOG_NOTICE, "Using client certificate at path: %s", client_certificate);

    return 0;
}

void session_config_free(void) {
    free(base_url);
    free(ca_certificate);
    free(client_certificate);
}

static void session_destroy(void *s) {
    CURL *session = s;
    log_print(LOG_NOTICE, "Destroying session.");
    assert(s);
    curl_easy_cleanup(session);
}

static void session_tsd_key_init(void) {
    log_print(LOG_DEBUG, "session_tsd_key_init()");
    pthread_key_create(&session_tsd_key, session_destroy);
}

CURL *session_get_handle(void) {
    CURL *session;

    pthread_once(&session_once, session_tsd_key_init);

    if ((session = pthread_getspecific(session_tsd_key)))
        return session;

    log_print(LOG_NOTICE, "Opening session.");
    session = curl_easy_init();
    log_print(LOG_NOTICE, "Session opened.");
    pthread_setspecific(session_tsd_key, session);

    return session;
}

CURL *session_request_init(const char *path) {
    CURL *session;
    char *full_url = NULL;

    log_print(LOG_NOTICE, "0");

    session = session_get_handle();

    curl_easy_reset(session);

    log_print(LOG_NOTICE, "10");

    asprintf(&full_url, "%s%s", base_url, path);
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    free(full_url);

    log_print(LOG_NOTICE, "20");
    curl_easy_setopt(session, CURLOPT_USERAGENT, "FuseDAV/PACKAGE_VERSION");
    log_print(LOG_NOTICE, "30");
    curl_easy_setopt(session, CURLOPT_URL, full_url);
    log_print(LOG_NOTICE, "40");
    if (ca_certificate != NULL)
        curl_easy_setopt(session, CURLOPT_CAINFO, ca_certificate);
    if (client_certificate != NULL) {
        curl_easy_setopt(session, CURLOPT_SSLCERT, client_certificate);
        curl_easy_setopt(session, CURLOPT_SSLKEY, client_certificate);
    }
    log_print(LOG_NOTICE, "50");
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(session, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(session, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(session, CURLOPT_CONNECTTIMEOUT_MS, 100);
    curl_easy_setopt(session, CURLOPT_TIMEOUT, 600);

    log_print(LOG_NOTICE, "Initialized request to: %s", path);

    return session;
}

/* $Id$ */

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

#include <ne_uri.h>
#include <ne_request.h>
#include <ne_basic.h>
#include <ne_props.h>
#include <ne_utils.h>
#include <ne_socket.h>
#include <ne_auth.h>
#include <ne_dates.h>
#include <ne_redirect.h>

#include "session.h"
#include "fusedav.h"

static pthread_once_t session_once = PTHREAD_ONCE_INIT;
static pthread_key_t session_tsd_key;

ne_uri uri;
static int b_uri = 0;

char *username = NULL;
static char *password = NULL;
char *base_directory = NULL;

static pthread_mutex_t credential_mutex = PTHREAD_MUTEX_INITIALIZER;

static char* ask_user(const char *p, int hidden) {
    char q[256], *r;
    struct termios t;
    int c = 0, l;

    if (hidden) {
        if (!isatty(fileno(stdin)))
            hidden = 0;
        else {
            if (tcgetattr(fileno(stdin),  &t) < 0)
                hidden = 0;
            else {
                c = t.c_lflag;
                t.c_lflag &= ~ECHO;
                if (tcsetattr(fileno(stdin), TCSANOW, &t) < 0)
                    hidden = 0;
            }
        }
    }
    
    fprintf(stderr, "%s: ", p);
    r = fgets(q, sizeof(q), stdin);
    l = strlen(q);
    if (l && q[l-1] == '\n')
        q[l-1] = 0;

    if (hidden) {
        t.c_lflag = c;
        tcsetattr(fileno(stdin), TCSANOW, &t);
        fprintf(stderr, "\n");
    }
    
    return r ? strdup(r) : NULL;
}

static int ssl_verify_cb(__unused void *userdata, __unused int failures, __unused const ne_ssl_certificate *cert) {
    return 0;
}

static int ne_auth_creds_cb(__unused void *userdata, const char *realm, int attempt, char *u, char *p) {
    int r = -1;
    
    pthread_mutex_lock(&credential_mutex);

    if (attempt) {
        fprintf(stderr, "Authentication failure!\n");
        free((void*) username);
        free((void*) password);
        username = password = NULL;
    }

    if (!username || !password)
        fprintf(stderr, "Realm '%s' requires authentication.\n", realm);
    
    if (!username)
        username = ask_user("Username", 0);
    
    if (username && !password)
        password = ask_user("Password", 1);

    if (username && password) {
        snprintf(u, NE_ABUFSIZ, "%s", username);
        snprintf(p, NE_ABUFSIZ, "%s", password);
        r  = 0;
    }

    pthread_mutex_unlock(&credential_mutex);
    return r;
}

static ne_session *session_open(int with_lock) {
    const char *scheme = NULL;
    ne_session *session;

    extern ne_lock_store *lock_store;

    if (!b_uri)
        return NULL;

    scheme = uri.scheme ? uri.scheme : "http";
    
    if (!(session = ne_session_create(scheme, uri.host, uri.port ? uri.port : ne_uri_defaultport(scheme)))) {
        fprintf(stderr, "Failed to create session\n");
        return NULL;
    }

    ne_ssl_set_verify(session, ssl_verify_cb, NULL);
    ne_set_server_auth(session, ne_auth_creds_cb, NULL);
    ne_redirect_register(session);

    if (with_lock && lock_store)
        ne_lockstore_register(lock_store, session);
    
    return session;
}

static void session_destroy(void *s) {
    ne_session *session = s;
    assert(s);
    ne_session_destroy(session);
}

static void session_tsd_key_init(void) {
    pthread_key_create(&session_tsd_key, session_destroy);
}

ne_session *session_get(int with_lock) {
    ne_session *session;
    
    pthread_once(&session_once, session_tsd_key_init);

    if ((session = pthread_getspecific(session_tsd_key)))
        return session;

    session = session_open(with_lock);
    pthread_setspecific(session_tsd_key, session);

    return session;
}

int session_set_uri(const char *s, const char *u, const char *p) {
    int l;
        
    assert(!b_uri);
    assert(!username);
    assert(!password);

    if (ne_uri_parse(s, &uri)) {
        fprintf(stderr, "Invalid URI <%s>\n", s);
        goto finish;
    }

    b_uri = 1;

    if (!uri.host) {
        fprintf(stderr, "Missing host part in URI <%s>\n", s);
        goto finish;
    }

    base_directory = strdup(uri.path);
    l = strlen(base_directory);
    if (base_directory[l-1] == '/')
        ((char*) base_directory)[l-1] = 0;

    if (u)
        username = strdup(u);

    if (p)
        password = strdup(p);

    return 0;
    
finish:
    
    if (b_uri) {
        ne_uri_free(&uri);
        b_uri = 0;
    }

    return -1;
}


void session_free(void) {
    if (b_uri) {
        ne_uri_free(&uri);
        b_uri = 0;
    }

    free((char*) username);
    free((char*) password);
    free((char*) base_directory);

    username = password = base_directory = NULL;
}

int session_is_local(const ne_uri *u) {
    assert(u);
    assert(b_uri);

    return
        strcmp(u->scheme, uri.scheme) == 0 &&
        strcmp(u->host, uri.host) == 0 &&
        u->port == uri.port;
}


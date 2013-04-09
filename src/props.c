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

  This file also contains code derived from W3C test code:
  http://dev.w3.org/XML/testDAV.c
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <expat.h>
#include <curl/curl.h>

#include "log.h"
#include "props.h"
#include "session.h"
#include "util.h"

struct parser_state {
    char path[PATH_MAX];
    bool exists;
    struct stat st;
    char *current_data;
    size_t current_data_len;
};

struct propfind_state {
    props_result_callback callback;
    struct parser_state pstate;
};

static void startElement(__unused void *userData, const XML_Char *name, __unused const XML_Char **atts) {
    //struct propfind_state *state = (struct propfind_state *) userData;
    log_print(LOG_DEBUG, "startElement: %s", name);
}

static void characterDataHandler(void *userData, const XML_Char *s, int len) {
    struct propfind_state *state = (struct propfind_state *) userData;
    log_print(LOG_DEBUG, "characterDataHandler");

    return;

    // If the current string is uninitialized, add one to the length
    // to accomodate the NUL terminator.
    if (state->pstate.current_data == NULL)
        ++len;

    // Extend the size of current_data by len. If it's uninitialized,
    // realloc will malloc for size len.
    state->pstate.current_data = realloc(state->pstate.current_data, state->pstate.current_data_len + len);

    // Copy in the new data, starting by overwriting the NUL terminator.
    strncpy(state->pstate.current_data + state->pstate.current_data_len - 1, s, len);

    // Update the string length.
    state->pstate.current_data_len += len;

    // NUL-terminate the new string.
    state->pstate.current_data[state->pstate.current_data_len - 1] = '\0';
}

/*
static void fill_stat(struct stat *st, const ne_prop_result_set *results, bool *is_deleted, int is_dir) {
    const char *rt, *e, *gcl, *glm, *cd;

    assert(st && results);

    // If it's a collection, force the type to directory.
    log_print(LOG_DEBUG, "fill_stat: resourcetype=%s", rt);
    if (rt && strstr(rt, "collection")) {
        is_dir = 1;
    }

    if (is_deleted != NULL) {
        const char *ev;
        ev = ne_propset_value(results, &event);
        if (ev == NULL) {
            *is_deleted = false;
        }
        else {
            log_print(LOG_INFO, "DAV:event=%s", ev);
            *is_deleted = (strcmp(ev, "DESTROYED") == 0);
        }
    }

    memset(st, 0, sizeof(struct stat));

    if (is_dir) {
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 3;            // find will ignore this directory if nlin <= and st_size == 0
        st->st_size = 4096;
    } else {
        st->st_mode = S_IFREG | (e && (*e == 'T' || *e == 't') ? 0777 : 0666);
        st->st_nlink = 1;
        st->st_size = gcl ? atoll(gcl) : 0;
    }

    st->st_atime = time(NULL);
    st->st_mtime = glm ? ne_rfc1123_parse(glm) : 0;
    st->st_ctime = cd ? ne_iso8601_parse(cd) : 0;

    st->st_blocks = (st->st_size+511)/512;
    //log_print(LOG_DEBUG, "a: %u; m: %u; c: %u", st->st_atime, st->st_mtime, st->st_ctime);

    st->st_mode &= ~mask;

    st->st_uid = getuid();
    st->st_gid = getgid();
}
*/

static void endElement(void *userData, const XML_Char *name) {
    struct propfind_state *state = (struct propfind_state *) userData;
    log_print(LOG_DEBUG, "endElement: %s", name);
    return;

    /*
    const ne_propname resourcetype = { "DAV:", "resourcetype" };
    const ne_propname executable = { "http://apache.org/dav/props/", "executable" };
    const ne_propname getcontentlength = { "DAV:", "getcontentlength" };
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    const ne_propname creationdate = { "DAV:", "creationdate" };
    const ne_propname event = { "DAV:", "event" };

    rt = ne_propset_value(results, &resourcetype);
    e = ne_propset_value(results, &executable);
    gcl = ne_propset_value(results, &getcontentlength);
    glm = ne_propset_value(results, &getlastmodified);
    cd = ne_propset_value(results, &creationdate);

    */

    // Reset parser state.
    free(state->pstate.current_data);
    memset(&state->pstate, 0, sizeof(struct parser_state));
}

static size_t write_parsing_callback(void *contents, size_t length, size_t nmemb, void *userp) {
    XML_Parser parser = (XML_Parser) userp;
    size_t real_size = length * nmemb;

    log_print(LOG_INFO, "Got chunk of %u bytes.", real_size);

    if (XML_Parse(parser, contents, real_size, 0) == 0) {
        int error_code = XML_GetErrorCode(parser);
        log_print(LOG_WARNING, "Parsing response buffer of length %u failed with error: %s", real_size, XML_ErrorString(error_code));
        return 0; // Zero bytes processed is failure.
    }

    return real_size;
}

int simple_propfind(const char *path, size_t depth, props_result_callback results, __unused void *userdata) {
    // Local variables for cURL.
    CURL *session = session_request_init(path);
    struct curl_slist *slist = NULL;
    CURLcode res;
    char *header = NULL;
    unsigned long response_code;

    // Local variables for Expat and parsing.
    XML_Parser parser;
    struct propfind_state state;

    int ret = -1;

    // Set a blank initial state, except for the callback.
    memset(&state, 0, sizeof(struct propfind_state));
    state.callback = results;

    // Configure the parser.
    parser = XML_ParserCreate(NULL);
    XML_SetUserData(parser, &state);
    XML_SetElementHandler(parser, startElement, endElement);
    XML_SetCharacterDataHandler(parser, characterDataHandler);
    curl_easy_setopt(session, CURLOPT_WRITEDATA, (void *) parser);
    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, write_parsing_callback);

    // Add the Depth header and PROPFIND verb.
    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "PROPFIND");
    asprintf(&header, "Depth: %lu", depth);
    slist = curl_slist_append(slist, header);
    free(header);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

    /* @TODO: Send the proper PROPFIND body:
     * <?xml version="1.0" encoding="utf-8" ?>
     * <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
     */

    // Perform the request and parse the response.
    log_print(LOG_INFO, "About to perform PROPFIND.");
    res = curl_easy_perform(session);

    // Finalize parsing.
    if (XML_Parse(parser, NULL, 0, 1) == 0) {
        int error_code = XML_GetErrorCode(parser);
        log_print(LOG_WARNING, "Finalizing parsing failed with error: %s", XML_ErrorString(error_code));
    }

    if (res != CURLE_OK) {
        log_print(LOG_WARNING, "PROPFIND failed: %s", curl_easy_strerror(res));
        goto finish;
    }

    curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 207) {
        log_print(LOG_WARNING, "PROPFIND failed with response code: %u", response_code);
        goto finish;
    }

    ret = 0;

finish:
    curl_slist_free_all(slist);
    XML_ParserFree(parser);
    return ret;
}

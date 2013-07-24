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

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <expat.h>
#include <curl/curl.h>
#include <errno.h>
#include <sys/stat.h>
#include <uriparser/Uri.h>

#include "log.h"
#include "log_sections.h"
#include "props.h"
#include "session.h"
#include "util.h"

struct response_state {
    char path[PATH_MAX];
    unsigned long status_code;
    struct stat st;
};

struct element_state {
    char *current_data;
    size_t current_data_len;
};

struct propfind_state {
    props_result_callback callback;
    void *userdata;
    CURL *session;
    struct response_state rstate;
    struct element_state estate;
    bool failure;
};

static char *get_relative_path(UriUriA *base_uri, UriUriA *source_uri) {
    char *path = NULL;
    char *segment;
    size_t segment_len = 0;
    UriPathSegmentA *cur_base = base_uri->pathHead;
    UriPathSegmentA *cur = source_uri->pathHead;

    // Iterate through the identical parts.
    while (cur != NULL && cur_base != NULL) {
        size_t base_segment_len = cur_base->text.afterLast - cur_base->text.first;
        segment_len = cur->text.afterLast - cur->text.first;

        if (segment_len != base_segment_len || strncmp(cur->text.first, cur_base->text.first, segment_len) != 0) {
            break;
        }

        cur = cur->next;
        cur_base = cur_base->next;
    }

    // Verify that we're done with the base path
    // and still have parts left of the main path.
    if (cur == NULL || cur_base != NULL) {
        return NULL;
    }

    // Iterate through the unique parts.
    while (cur != NULL) {
        segment_len = cur->text.afterLast - cur->text.first;
        segment = malloc(segment_len + 1);
        strncpy(segment, cur->text.first, segment_len);
        segment[segment_len] = '\0';

        if (path == NULL) {
            path = segment;
        }
        else {
            char *oldpath = path;
            asprintf(&path, "%s/%s", oldpath, segment);
            free(segment);
            free(oldpath);
        }
        cur = cur->next;
    }

    return path;
}

static char *get_path_beyond_base(const char *source_url) {
    UriUriA base_uri;
    UriParserStateA base_state;
    UriUriA source_uri;
    UriParserStateA source_state;
    const char *base_url = get_base_url();
    char *path = NULL;
    size_t path_len;

    base_state.uri = &base_uri;
    source_state.uri = &source_uri;

    // Parse the URLs.
    if (uriParseUriA(&base_state, base_url) != URI_SUCCESS) {
        uriFreeUriMembersA(&base_uri);
        return NULL;
    }
    if (uriParseUriA(&source_state, source_url) != URI_SUCCESS) {
        goto finish;
    }

    // Normalize the paths.
    if (uriNormalizeSyntaxExA(&base_uri, URI_NORMALIZE_PATH) != URI_SUCCESS) {
        goto finish;
    }
    if (uriNormalizeSyntaxExA(&source_uri, URI_NORMALIZE_PATH) != URI_SUCCESS) {
        goto finish;
    }

    // Compute the relative path and store it to a string.
    path = get_relative_path(&base_uri, &source_uri);

    // If we've got a NULL, it's just the base path.
    if (path == NULL) {
        path = strdup("");
        goto finish;
    }

    path_len = strlen(path);

    // Drop any trailing slash.
    if (path[path_len - 1] == '/') {
        path[path_len - 1] = '\0';
    }

finish:
    uriFreeUriMembersA(&base_uri);
    uriFreeUriMembersA(&source_uri);

    log_print(LOG_DEBUG, SECTION_PROPS_DEFAULT, "get_path_beyond_base: computed path: %s", path);

    return path;
}


static void startElement(__unused void *userData, __unused const XML_Char *name, __unused const XML_Char **atts) {
    struct propfind_state *state = (struct propfind_state *) userData;

    state->estate.current_data = malloc(1);
    state->estate.current_data[0] = '\0';
    state->estate.current_data_len = 1;
}

static void characterDataHandler(void *userData, const XML_Char *s, int len) {
    struct propfind_state *state = (struct propfind_state *) userData;

    // Extend the size of current_data by len. If it's uninitialized,
    // realloc will malloc for size len.
    state->estate.current_data = realloc(state->estate.current_data, state->estate.current_data_len + len);

    // Copy in the new data, starting by overwriting the NUL terminator.
    strncpy(state->estate.current_data + state->estate.current_data_len - 1, s, len);

    // Update the string length.
    state->estate.current_data_len += len;

    // NUL-terminate the new string.
    state->estate.current_data[state->estate.current_data_len - 1] = '\0';
}

static void endElement(void *userData, const XML_Char *name) {
    struct propfind_state *state = (struct propfind_state *) userData;

    if (strcmp(name, "DAV:status") == 0) {
        char *token_status = NULL;
        strtok_r(state->estate.current_data, " ", &token_status);
        state->rstate.status_code = (unsigned long) atol(strtok_r(NULL, " ", &token_status));
    }
    else if (strcmp(name, "DAV:href") == 0) {
        char *path = get_path_beyond_base(state->estate.current_data);
        char *unescaped_path = NULL;
        asprintf(&path, "/%s", path);
        unescaped_path = curl_easy_unescape(state->session, path, 0, NULL);
        free(path);
        log_print(LOG_INFO, SECTION_PROPS_DEFAULT, "DAV:href: %s", state->estate.current_data);
        strncpy(state->rstate.path, unescaped_path, PATH_MAX);
        state->rstate.path[PATH_MAX - 1] = '\0';
        free(unescaped_path);
    }
    else if (strcmp(name, "DAV:collection") == 0) {
        state->rstate.st.st_mode |= S_IFDIR;
    }
    else if (strcmp(name, "DAV:getcontentlength") == 0) {
        state->rstate.st.st_size = atol(state->estate.current_data);
    }
    else if (strcmp(name, "DAV:getlastmodified") == 0) {
        state->rstate.st.st_mtime = curl_getdate(state->estate.current_data, NULL);
        state->rstate.st.st_atime = state->rstate.st.st_mtime;
    }
    else if (strcmp(name, "DAV:creationdate") == 0) {
        struct tm t;
        strptime(state->estate.current_data, "%FT%H:%M:%S%z", &t);
        state->rstate.st.st_ctime = mktime(&t);
    }
    else if (strcmp(name, "DAV:response") == 0) {
        // Default to a normal file if it's not explicitly a directory.
        if (state->rstate.st.st_mode & S_IFDIR) {
            state->rstate.st.st_mode |= 0770;
            state->rstate.st.st_nlink = 3;
        }
        else {
            state->rstate.st.st_mode |= S_IFREG | 0660;
            state->rstate.st.st_nlink = 1;
        }
        state->rstate.st.st_blksize = 4096;

        // Default to the current time or mtime.
        if (state->rstate.st.st_mtime == 0)
            state->rstate.st.st_mtime = time(NULL);
        if (state->rstate.st.st_atime == 0)
            state->rstate.st.st_atime = state->rstate.st.st_mtime;
        if (state->rstate.st.st_ctime == 0)
            state->rstate.st.st_ctime = state->rstate.st.st_mtime;

        state->rstate.st.st_uid = getuid();
        state->rstate.st.st_gid = getgid();

        log_print(LOG_DEBUG, SECTION_PROPS_DEFAULT, "Response for path: %s (code %lu, size, %lu)", state->rstate.path, state->rstate.status_code, state->rstate.st.st_size);
        state->callback(state->userdata, state->rstate.path, state->rstate.st, state->rstate.status_code);

        // Reset response state.
        memset(&state->rstate, 0, sizeof(struct response_state));
    }

    // Reset element state.
    free(state->estate.current_data);
    memset(&state->estate, 0, sizeof(struct element_state));
}

static size_t write_parsing_callback(void *contents, size_t length, size_t nmemb, void *userp) {
    XML_Parser parser = (XML_Parser) userp;
    size_t real_size = length * nmemb;
    struct propfind_state *state;

    log_print(LOG_DEBUG, SECTION_PROPS_DEFAULT, "Got chunk of %u bytes.", real_size);

    state = (struct propfind_state *) XML_GetUserData(parser);

    // Skip further parsing if we're already in a failure state.
    if (!state->failure) {
        if (XML_Parse(parser, contents, real_size, 0) == 0) {
            int error_code = XML_GetErrorCode(parser);
            log_print(LOG_NOTICE, SECTION_PROPS_DEFAULT, "Parsing response buffer of length %u failed with error: %s", real_size, XML_ErrorString(error_code));
            state->failure = true;
        }
    }

    return real_size;
}

int simple_propfind(const char *path, size_t depth, time_t last_updated, props_result_callback results, void *userdata) {
    // Local variables for cURL.
    CURL *session;
    struct curl_slist *slist = NULL;
    CURLcode res;
    char *header = NULL;
    char *query_string = NULL;
    long response_code;

    // Local variables for Expat and parsing.
    XML_Parser parser;
    struct propfind_state state;

    int ret = -1;

    // Set up the request handle.
    if (last_updated > 0) {
        asprintf(&query_string, "changes_since=%lu", last_updated);
    }
    session = session_request_init(path, query_string);
    free(query_string);

    // Set a blank initial state, except for the callback.
    memset(&state, 0, sizeof(struct propfind_state));
    state.callback = results;
    state.userdata = userdata;
    state.failure = false;
    state.session = session;

    // Configure the parser.
    parser = XML_ParserCreateNS(NULL, '\0');
    XML_SetUserData(parser, &state);
    XML_SetElementHandler(parser, startElement, endElement);
    XML_SetCharacterDataHandler(parser, characterDataHandler);
    curl_easy_setopt(session, CURLOPT_WRITEDATA, (void *) parser);
    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, write_parsing_callback);

    // Add the Depth header and PROPFIND verb.
    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "PROPFIND");
    asprintf(&header, "Depth: %lu", depth);
    slist = curl_slist_append(slist, header);
    slist = curl_slist_append(slist, "Content-Type: text/xml");
    free(header);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

    // Send the PROPFIND body.
    curl_easy_setopt(session, CURLOPT_POSTFIELDS,
        "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        "<D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>");

    // Perform the request and parse the response.
    log_print(LOG_INFO, SECTION_PROPS_DEFAULT, "About to perform PROPFIND.");
    res = curl_easy_perform(session);

    if (res != CURLE_OK) {
        log_print(LOG_WARNING, SECTION_PROPS_DEFAULT, "PROPFIND failed: %s", curl_easy_strerror(res));
        goto finish;
    }

    curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code == 207) {
        // Finalize parsing.
        if (state.failure) {
            log_print(LOG_WARNING, SECTION_PROPS_DEFAULT, "Could not finalize parsing of the 207 response because it's already in a failed state.");
            goto finish;
        }

        if (XML_Parse(parser, NULL, 0, 1) == 0) {
            int error_code = XML_GetErrorCode(parser);
            log_print(LOG_WARNING, SECTION_PROPS_DEFAULT, "Finalizing parsing failed with error: %s", XML_ErrorString(error_code));
        }
        else {
            log_print(LOG_DEBUG, SECTION_PROPS_DEFAULT, "Finished final parsing on the PROPFIND response.");
        }
    }
    else if (response_code == 404) {
        // Tell the callback that the item is gone.
        memset(&state.rstate, 0, sizeof(struct response_state));
        state.callback(state.userdata, path, state.rstate.st, 410);
    }
    else if (response_code == 412) {
        ret = -ESTALE;
        goto finish;
    }
    else {
        log_print(LOG_WARNING, SECTION_PROPS_DEFAULT, "PROPFIND failed with response code: %u", response_code);
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_PROPS_DEFAULT, "PROPFIND completed on path %s", path);
    ret = 0;

finish:
    curl_slist_free_all(slist);
    XML_ParserFree(parser);
    return ret;
}

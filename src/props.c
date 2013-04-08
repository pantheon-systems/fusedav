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

#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <curl/curl.h>

#include "log.h"

// @TODO: Invoke xmlCleanupParser() somehow.

static struct propfind_response {
  char *content;
  size_t length;
};

static size_t write_callback(void *contents, size_t length, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct propfind_response *response = (struct propfind_response *)userp;

    response->content = realloc(response->content, response->length + realsize + 1);
    if(response->content == NULL) {
        log_print(LOG_ERR, "Not enough memory (realloc returned NULL).");
        return 0;
    }

    memcpy(&(response->content[response->length]), contents, realsize);
    response->length += realsize;
    response->content[response->length] = 0;

    return realsize;
}

static int parse_multistatus(propfind_response *response, props_result results, void *userdata) {
    xmlDoc *doc;

    doc = xmlReadMemory(response->content, response->length, "noname.xml", NULL, 0);
    if (doc == NULL) {
        log_print(LOG_ERR, "Failed to parse document.");
        return -1;
    }

    for (xmlNode *current = xmlDocGetRootElement(doc); current; current = current->next) {
        if (current->type == XML_ELEMENT_NODE) {
            printf("Multistatus type: Element, name: %s\n", current->name);
            results(current, results, userdata);
        }
    }

    xmlFreeDoc(doc);
    return 0;
}

int simple_propfind(const char *path, size_t depth, props_result results, void *userdata) {
    CURL *session = session_request_init(path);
    struct curl_slist *slist = NULL;
    char *header = NULL;
    CURLcode res;
    propfind_response response;
    int ret = -1;

    // Set the PROPFIND verb and response buffering.
    memset(&response, 0, sizeof(propfind_response));
    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(session, CURLOPT_WRITEDATA, (void *) &response);
    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "PROPFIND");

    // Add the Depth header.
    asprintf(&header, "Depth: %u", depth);
    slist = curl_slist_append(slist, header);
    free(header);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, headers);

    /* @TODO: Send the proper PROPFIND body:
     * <?xml version="1.0" encoding="utf-8" ?>
     * <D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>
     */

    // Perform the request and parse the response.
    res = curl_easy_perform(session);
    // @TODO: Handle non-multistatus.
    parse_multistatus(&response, results, userdata);

    if(res != CURLE_OK) {
        log_print(LOG_DEBUG, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        goto finish;
    }

finish:
    curl_slist_free_all(slist);
    free(response.buffer);
    return ret;
}

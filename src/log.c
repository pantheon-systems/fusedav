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

#include <systemd/sd-journal.h>
#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <stdlib.h>

#include "log.h"
#include "log_sections.h"
#include "session.h"

// Store values for loggging in the log_key_value array, which is set in fusedav_config.
#define USER_AGENT_ABBREV 0
#define USER_AGENT_FULL 1
#define BASEURL_FIRST 2
#define BASEURL_SECOND 3
#define BASEURL_THIRD 4
#define BASEURL_FOURTH 5
#define BASEURL_FIFTH 6
#define BASEURL_SIXTH 7
#define BASEURL_SEVENTH 8
#define BASEURL_EIGHTH 9
// last item plus one
#define KVITEMS BASEURL_EIGHTH + 1

// array to hold values for rich journald key=value pairs
// see http://0pointer.de/blog/projects/journal-submit.html for examples

// max size for strings in log_key_value array
#define KVITEM_SIZE 64

static unsigned int global_log_level = 5;
static unsigned int section_log_levels[SECTIONS] = {0};
static const char *log_key_value[KVITEMS];

static const char *errlevel[] = {"EMERG:  ", "ALERT:  ", "CRIT:   ", "ERR:    ", "WARN:   ", "NOTICE: ", "INFO:   ", "DEBUG:  "};

// From the base url get the site id and site env
static void initialize_site(void) {
    char *str = strdup(get_base_url());
    char *token;
    const char *delim = "/";
    int idx;
    
    // If there is no base url, we'll fill with a marker ("(null)")
    for (idx = BASEURL_FIRST; idx <= BASEURL_EIGHTH; idx++) {
        log_key_value[idx] = "(null)";
    }
    
    /* get the first token */
    token = strtok(str, delim);

    idx = BASEURL_FIRST;
    /* walk through other tokens */
    while( token != NULL ) 
    {
        printf("%s\n", token);
        log_key_value[idx++] = strndup(token, KVITEM_SIZE);
        token = strtok(NULL, delim);
    }
    return;
}

/* The log_prefix comes from fusedav.conf; the base_url from curl and fuse. */
void log_init(unsigned int log_level, const char *log_level_by_section, const char *user_agent) {
            
    unsigned int vlen;

    global_log_level = log_level;

    // Set log levels. We use get_base_url for the log message, so this call needs to follow
    // session_config_init, where base_url is set
    if (user_agent) {
        // Assume that the log_prefix is the thing which identifies this instance of fusedav, e.g. binding id
        log_key_value[USER_AGENT_FULL] = strndup(user_agent, KVITEM_SIZE);
        log_key_value[USER_AGENT_ABBREV] = strndup(user_agent, 8);
    }
    else {
        // If we don't have a log prefix, we don't have an instance identifier
        log_key_value[USER_AGENT_FULL] = "(null)";
        log_key_value[USER_AGENT_ABBREV] = "(null)";
    }
    
    initialize_site();
    
    if (log_level_by_section == NULL) return;

    // If we see a section whose value is greater than vlen, its value will be 0 by default.
    // Zero means use the global log level
    vlen = strlen(log_level_by_section);
    for (unsigned int idx = 0; idx < vlen; idx++) {
        section_log_levels[idx] = log_level_by_section[idx] - '0'; // Looking for an integer 0-7
    }
    return;
}

// Are we logging this message?
int logging(unsigned int log_level, unsigned int section) {
    unsigned int local_log_level = global_log_level;

    // If the section verbosity is not 0 for this section, use it as the verbosity level;
    // otherwise, just use the global_log_level
    if (section < SECTIONS && section_log_levels[section]) {
        local_log_level = section_log_levels[section];
    }

    return log_level <= local_log_level;
}

#define max_msg_sz 2048
int log_print(unsigned int log_level, unsigned int section, const char *format, ...) {
    int ret = 0;
    if (logging(log_level, section)) {
        va_list ap;
        char *formatwithtid;
        char msg[max_msg_sz + 1];

        va_start(ap, format);
        vsnprintf(msg, max_msg_sz, format, ap);
        asprintf(&formatwithtid, "[tid=%lu] [bid=%s] %s", syscall(SYS_gettid), log_key_value[USER_AGENT_ABBREV], errlevel[log_level]);
        assert(formatwithtid);
        // fusedav-valhalla standardizing on names BINDING, SITE, and ENVIRONMENT
        ret = sd_journal_send("MESSAGE=%s%s", formatwithtid, msg,
                              "PRIORITY=%d", log_level,
                              "USER-AGENT=%s", log_key_value[USER_AGENT_FULL],
                              "SITE=%s", log_key_value[BASEURL_SECOND],
                              "ENVIRONMENT=%s", log_key_value[BASEURL_FOURTH],
                              "TID=%lu", syscall(SYS_gettid),
                              "PACKAGE_VERSION=%s", PACKAGE_VERSION,
                              NULL);
        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}

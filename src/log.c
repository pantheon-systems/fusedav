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
#include "fusedav_config.h"

__thread unsigned int LOG_DYNAMIC = LOG_INFO;

// Store values for loggging in the log_key_value array, which is set in fusedav_config.
#define USER_AGENT_ABBREV 0
#define BASEURL_FIRST 1
#define BASEURL_SECOND 2
#define BASEURL_THIRD 3
#define BASEURL_FOURTH 4
#define BASEURL_FIFTH 5
#define BASEURL_SIXTH 6
#define BASEURL_SEVENTH 7
#define BASEURL_EIGHTH 8
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
    while( token != NULL ) {
        log_key_value[idx++] = strndup(token, KVITEM_SIZE);
        token = strtok(NULL, delim);
    }
    free(str);
    return;
}

/* The log_prefix comes from fusedav.conf; the base_url from curl and fuse. */
void log_init(unsigned int log_level, const char *log_level_by_section, const char *user_agent_abbrev) {

    unsigned int vlen;

    global_log_level = log_level;

    // Set log levels. We use get_base_url for the log message, so this call needs to follow
    // session_config_init, where base_url is set
    if (user_agent_abbrev) {
        log_key_value[USER_AGENT_ABBREV] = strndup(user_agent_abbrev, 8);
    }
    else {
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

/* When fusedav detects an error, it will set dynamic logging. For those log statements whose log level is LOG_DYNAMIC,
 * this will lower its log threshold and make it likely that the statement will print.
 * This will continue during the dynamic_logging_duration. Each thread has its own view of whether it is
 * in a dynamic logging state or not.
 * Include a rest period so if we are in serious error mode, we don't overload the logging system
 */
static __thread time_t dynamic_logging_start = 0;
const int dynamic_logging_duration = 10;
const int dynamic_logging_rest = 120;

static bool turning_off_dynamic_logging(void) {
    struct timespec now;
    bool turn_off_dynamic_logging = false;

    // If we're not currently doing dynamic_logging, there's noting to turn off
    if (LOG_DYNAMIC == LOG_INFO) return false;

    clock_gettime(CLOCK_MONOTONIC, &now);
    turn_off_dynamic_logging = (dynamic_logging_start + dynamic_logging_duration < now.tv_sec);
    if (turn_off_dynamic_logging) {
        LOG_DYNAMIC = LOG_INFO;
    }
    return turn_off_dynamic_logging;
}

void set_dynamic_logging(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (dynamic_logging_start + dynamic_logging_rest > now.tv_sec) {
        // still in rest period
        log_print(LOG_INFO, SECTION_FUSEDAV_DEFAULT,
            "Not setting dynamic_logging, still in rest period");
    }
    else {
        dynamic_logging_start = now.tv_sec;
        log_print(LOG_NOTICE, SECTION_FUSEDAV_DEFAULT,
            "Setting dynamic_logging for %lu seconds. fusedav.dynamic_logging:1|c", dynamic_logging_duration);
        LOG_DYNAMIC = LOG_INFO - 1;
    }
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

static int print_it(const char const *formatwithtid, const char const *msg, int log_level) {
    int ret;
    // fusedav-valhalla standardizing on names BINDING, SITE, and ENVIRONMENT
    ret = sd_journal_send("MESSAGE=%s%s", formatwithtid, msg,
                          "PRIORITY=%d", log_level,
                          "USER_AGENT=%s", get_user_agent(),
                          "SITE=%s", log_key_value[BASEURL_FOURTH],
                          "ENVIRONMENT=%s", log_key_value[BASEURL_SIXTH],
                          "HOST_ADDRESS=%s", log_key_value[BASEURL_SECOND],
                          "TID=%lu", syscall(SYS_gettid),
                          "PACKAGE_VERSION=%s", PACKAGE_VERSION,
                          NULL);
    return ret;
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

        // print the intended message
        ret = print_it(formatwithtid, msg, log_level);

        // Check and see if we're no longer doing dynamic logging. If so, it will take effect after this call. Then print a message
        if (turning_off_dynamic_logging()) {
            strcpy(msg, "revert_dynamic_logging");
            print_it(formatwithtid, msg, log_level);
        }

        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}


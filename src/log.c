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

static unsigned int global_log_level = 5;
static unsigned int section_log_levels[SECTIONS] = {0};
static const char *log_key_value[KVITEMS];

static const char *errlevel[] = {"EMERG:  ", "ALERT:  ", "CRIT:   ", "ERR:    ", "WARN:   ", "NOTICE: ", "INFO:   ", "DEBUG:  "};

/* The log_prefix comes from fusedav.conf; the base_url from curl and fuse. */
void log_init(unsigned int log_level, const char *log_level_by_section, const char *log_key_values[]) {
            
    unsigned int vlen;

    global_log_level = log_level;

    // Grab the strings out of the input array
    for (int idx = 0; idx < KVITEMS; idx++) {
        log_key_value[idx] = log_key_values[idx];
    }

    if (log_level_by_section == NULL) return;

    // If we see a section whose value is greater than vlen, its value will be 0 by default.
    // Zero means use the global log level
    vlen = strlen(log_level_by_section);
    for (unsigned int idx = 0; idx < vlen; idx++) {
        section_log_levels[idx] = log_level_by_section[idx] - '0'; // Looking for an integer 0-7
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

#define max_msg_sz 80
int log_print(unsigned int log_level, unsigned int section, const char *format, ...) {
    int ret = 0;
    if (logging(log_level, section)) {
        va_list ap;
        char *formatwithtid;
        char msg[max_msg_sz + 1];

        va_start(ap, format);
        vsnprintf(msg, max_msg_sz, format, ap);
        asprintf(&formatwithtid, "[tid=%lu] [bid=%s] %s", syscall(SYS_gettid), log_key_value[INSTANCE_ID_ABBREV], errlevel[log_level]);
        assert(formatwithtid);
        // fusedav-valhalla standardizing on names BINDING, SITE, and ENVIRONMENT
        ret = sd_journal_send("MESSAGE=%s%s", formatwithtid, msg,
                              "PRIORITY=%d", log_level,
                              "BINDING=%s", log_key_value[INSTANCE_ID_FULL],
                              "SITE=%s", log_key_value[SITE_ID],
                              "ENVIRONMENT=%s", log_key_value[SITE_ENV],
                              "TID=%lu", syscall(SYS_gettid),
                              "PACKAGE_VERSION=%s", PACKAGE_VERSION,
                              NULL);
        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}

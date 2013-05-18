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
#include <jemalloc/jemalloc.h>

#include "log.h"
#include "log_sections.h"

static unsigned int global_log_level = 5;
static unsigned int section_log_levels[SECTIONS] = {0};
static char log_prefix_abbrev[9] = {0};

static const char *errlevel[] = {"EMERG:  ", "ALERT:  ", "CRIT:   ", "ERR:    ", "WARN:   ", "NOTICE: ", "INFO:   ", "DEBUG:  "};

void log_init(unsigned int log_level, const char *log_level_by_section, const char *log_prefix) {
    unsigned int vlen;
    const char *base_dir = NULL;

    global_log_level = log_level;

    // @TODO once we have the new titan with log_prefix, remove base_dir code
    base_dir = strstr(log_prefix, "/sites");

    if (log_prefix == NULL) {
        strncpy(log_prefix_abbrev, "(null)", 8);
    }
    else if(base_dir != NULL) {
        if (strlen(base_dir) > 15) {
            strncpy(log_prefix_abbrev, base_dir + 7, 8);
         }
        // But of course, if base_dir is too short, but at least 8, copy the first 8. We have no idea
        // what this will look like.
        else if (strlen(base_dir) > 8) {
            strncpy(log_prefix_abbrev, base_dir, 8);
        }
        // But of course, if it doesn't have 8 chars, just copy in what it does have
        else if (strlen(base_dir) > 0) {
            strcpy(log_prefix_abbrev, base_dir);
        }
        else {
            strncpy(log_prefix_abbrev, "(null)", 8);
        }
    }
    else if (strlen(log_prefix) > 0) {
        strncpy(log_prefix_abbrev, log_prefix, 8);
    }
    // But of course, if it's an empty string, just set site id to (null)
    else {
        strncpy(log_prefix_abbrev, "(null)", 8);
    }

    // JB @TODO Until both fusedav and titan are on the new versions reading the config file,
    // vstr will be NULL, so check and take evasive measures. Later, we should be able to
    // remove this check
    if (log_level_by_section == NULL) return;

    // If we see a section whose value is greater than vlen, its value will be 0 by default.
    // Zero means use the global log level
    vlen = strlen(log_level_by_section);
    for (unsigned int idx = 0; idx < vlen; idx++) {
        section_log_levels[idx] = log_level_by_section[idx] - '0'; // Looking for an integer 0-7
    }
}

int log_print(unsigned int log_level, unsigned int section, const char *format, ...) {
    int ret = 0;
    va_list ap;
    char *formatwithtid;
    unsigned int local_log_level = global_log_level;

    // If the section verbosity is not 0 for this section, use it as the verbosity level;
    // otherwise, just use the global_log_level
    if (section < SECTIONS && section_log_levels[section]) {
        local_log_level = section_log_levels[section];
    }

    if (log_level <= local_log_level) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[%s] [tid=%lu] [sid=%s] %s%s", PACKAGE_VERSION, syscall(SYS_gettid), log_prefix_abbrev, errlevel[log_level], format);
        assert(formatwithtid);
        ret = sd_journal_printv(log_level, formatwithtid, ap);
        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}

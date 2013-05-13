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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <unistd.h>
#include <syscall.h>
#include <assert.h>

#include "log.h"
#include "log_sections.h"

static unsigned int maximum_verbosity = 5;
static unsigned int section_verbosity[SECTIONS] = {0};
static char base_directory_abbrev[9] = {0};

static const char *errlevel[] = {"EMERG:  ", "ALERT:  ", "CRIT:   ", "ERR:    ", "WARN:   ", "NOTICE: ", "INFO:   ", "DEBUG:  "};

void log_init(unsigned int verbosity, const char *base_dir, char *vstr) {
    unsigned int vlen;
    maximum_verbosity = verbosity;

    // We assume "/sites/<site id>/environments/..."
    // So get ride of "/sites/", and copy the next 8, which will be an abbreviated version of the site id.
    // If base_dir does not follow this pattern, we don't know what to do, so just copy bytes 8-15 and
    // we'll get what we get.
    if (strlen(base_dir) > 15) {
        strncpy(base_directory_abbrev, base_dir + 7, 8);
    }
    // But of course, if base_dir is too short, but at least 8, copy the first 8. We have no idea
    // what this will look like.
    else if (strlen(base_dir) > 8) {
        strncpy(base_directory_abbrev, base_dir, 8);
    }
    // But of course, if it doesn't have 8 chars, just copy in what it does have
    else if (strlen(base_dir) > 0) {
        strcpy(base_directory_abbrev, base_dir);
    }
    // But of course, if it's an empty string, just set site id to (null)
    else {
        strcpy(base_directory_abbrev, "(null)");
    }

    // JB @TODO Until both fusedav and titan are on the new versions reading the config file,
    // vstr will be NULL, so check and take evasive measures. Later, we should be able to
    // remove this check
    if (vstr == NULL) return;
    vlen = strlen(vstr);
    for (unsigned int idx = 0; idx < vlen; idx++) {
        section_verbosity[idx] = vstr[idx] - '0'; // Looking for an integer 0-7
    }
}

int log_print(unsigned int verbosity, unsigned int section, const char *format, ...) {
    int ret = 0;
    va_list ap;
    char *formatwithtid;
    unsigned int local_verbosity = maximum_verbosity;

    // If the section verbosity is not 0 for this section, use it as the verbosity level;
    // otherwise, just use the global maximum_verbosity
    if (section < SECTIONS && section_verbosity[section]) {
        local_verbosity = section_verbosity[section];
    }

    if (verbosity <= local_verbosity) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[%s] [tid=%lu] [sid=%s] %s%s", PACKAGE_VERSION, syscall(SYS_gettid), base_directory_abbrev, errlevel[verbosity], format);
        assert(formatwithtid);
        ret = sd_journal_printv(verbosity, formatwithtid, ap);
        free(formatwithtid);
        va_end(ap);
    }

    return ret;
}

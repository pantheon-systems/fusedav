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

#include <systemd/sd-journal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <syscall.h>
#include <assert.h>

#include "log.h"

static int maximum_verbosity;
// temporary until we adopt this strategy
#define SECTION_DEFAULT 0
static char *section_verbosity_levels;

void log_set_maximum_verbosity(int verbosity) {
    maximum_verbosity = verbosity;
}

void log_set_section_verbosity(char *section_levels) {
    section_verbosity_levels = section_levels;
}

int log_print(int verbosity, const char *format, ...) {
    int r = 0;
    va_list ap;
    char *formatwithtid;

    if (verbosity <= maximum_verbosity) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[%s] [tid=%lu] %s", PACKAGE_VERSION, syscall(SYS_gettid), format);
        assert(formatwithtid);
        r = sd_journal_printv(verbosity, formatwithtid, ap);
        free(formatwithtid);
        va_end(ap);
    }

    return r;
}

int log_print_sections(int verbosity, int code_section, const char *format, ...) {
    int r = 0;
    va_list ap;
    char *formatwithtid;
    int section_verbosity;

    // Temporary placeholder until we decide to go forward with this strategy
    // If 0 is specified, no section is indicated, so use global default
    if (code_section == 0) {
        section_verbosity = maximum_verbosity;
    }
    else {
        // if the string is too short to have an entry, use the global maximum_verbosity
        if (code_section >= strlen(section_verbosity_levels)) {
            section_verbosity = maximum_verbosity;
        }
        // zero as an entry is the tag meaning use the global default
        else if (section_verbosity_levels[code_section] == '0') {
            section_verbosity = maximum_verbosity;
        }
        else {
            section_verbosity = section_verbosity_levels[code_section] - '0';
        }
    }

    // We don't allow sections to lower their verbosity.
    if (section_verbosity < maximum_verbosity) section_verbosity = maximum_verbosity;

    if (verbosity <= section_verbosity) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[%s] [tid=%lu] %s", PACKAGE_VERSION, syscall(SYS_gettid), format);
        assert(formatwithtid);
        r = sd_journal_printv(verbosity, formatwithtid, ap);
        free(formatwithtid);
        va_end(ap);
    }

    return r;
}

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

void log_set_maximum_verbosity(int verbosity) {
    maximum_verbosity = verbosity;
}

int log_print(int verbosity, const char *format, ...) {
    int r = 0;
    va_list ap;
    char *formatwithtid;

    if (verbosity <= maximum_verbosity) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[tid=%lu] %s", syscall(SYS_gettid), format);
        assert(formatwithtid);
        r = sd_journal_printv(verbosity, formatwithtid, ap);
        free(formatwithtid);
        va_end(ap);
    }

    return r;
}

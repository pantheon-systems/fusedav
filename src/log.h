#ifndef foologhfoo
#define foologhfoo

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

#include <systemd/sd-journal.h>

// These are shared between config and log
// Pantheon-specific
#define INSTANCE_ID_ABBREV 0
#define INSTANCE_ID_FULL 1
#define SITE_ID 2
#define SITE_ENV 3

// array to hold values for rich journald key=value pairs
// see http://0pointer.de/blog/projects/journal-submit.html for examples

// site_env + 1
#define KVITEMS 4
// max size for strings in log_key_value array
#define KVITEM_SIZE 64

void log_init(unsigned int log_level, const char *log_level_by_section, const char *log_key_values[]);
int log_print(unsigned int log_level, unsigned int section, const char *format, ...);
int logging(unsigned int log_level, unsigned int section);

#endif

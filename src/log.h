#ifndef foologhfoo
#define foologhfoo

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

#include <systemd/sd-journal.h>

void log_set_maximum_verbosity(int verbosity);
void log_set_section_verbosity(char *section_levels);
int log_print(int verbosity, const char *format, ...);
int log_print_sections(int verbosity, int code_section, const char *format, ...);

#endif

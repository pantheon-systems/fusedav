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

void log_set_section_verbosity(char *vstr);
void log_init(unsigned int verbosity, const char *base_dir);
int log_print_old(unsigned int verbosity, const char *format, ...);
int log_print(unsigned int verbosity, unsigned int section, const char *format, ...);

#endif

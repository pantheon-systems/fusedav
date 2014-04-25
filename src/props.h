#ifndef foopropshfoo
#define foopropshfoo

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

#include <glib.h>

#define PROPFIND_DEPTH_ZERO 0
#define PROPFIND_DEPTH_ONE 1
#define PROPFIND_DEPTH_INFINITY 2

typedef void (*props_result_callback)(void *userdata, const char *href, struct stat st, unsigned long status_code, GError **gerr);
int simple_propfind(const char *path, size_t depth, time_t last_updated, bool maintenance_mode, props_result_callback results,
    void *userdata, GError **gerr);

#endif

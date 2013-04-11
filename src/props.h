#ifndef foopropshfoo
#define foopropshfoo

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

#include <sys/types.h>
#include <sys/stat.h>

#define PROPFIND_DEPTH_ZERO 0
#define PROPFIND_DEPTH_ONE 1
#define PROPFIND_DEPTH_INFINITY 2

typedef void (*props_result_callback)(void *userdata, const char *href, struct stat st, unsigned long status_code);
int simple_propfind(const char *path, size_t depth, props_result_callback results, void *userdata);

#endif

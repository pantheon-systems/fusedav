#ifndef fooutilhfoo
#define fooutilhfoo

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

#include <time.h>
#include <unistd.h>

#ifdef __GNUC__
#define __unused __attribute__ ((unused))
#else
#define __unused
#endif

char *path_parent(const char *uri);
char *path_escape(const char *path);

// Error injection routines
extern bool injecting_errors;
int fusedav_errors(void);
int filecache_errors(void);
int statcache_errors(void);

void *inject_error_mechanism(void *ptr);
bool fusedav_inject_error(int edx);
bool filecache_inject_error(int edx);
bool statcache_inject_error(int edx);

#endif

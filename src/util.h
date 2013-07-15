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

#ifdef __GNUC__
#define __unused __attribute__ ((unused))
#else
#define __unused
#endif

#include <glib.h>

char *path_parent(const char *uri);
char *strip_trailing_slash(char *fn, int *is_dir);

// For GError
#ifndef G_DEFINE_QUARK

#define             G_DEFINE_QUARK(QN, q_n)\
GQuark \
q_n##_quark (void) \
{ \
  static GQuark g_define_quark = 0; \
  if (G_UNLIKELY (g_define_quark == 0)) \
    g_define_quark = g_quark_from_string (#QN); \
  return g_define_quark; \
}

#endif
// Error injection routines
int fusedav_errors(void);
int filecache_errors(void);
int statcache_errors(void);

void *inject_error_mechanism(void *ptr);

#if INJECT_ERRORS

#define injecting_errors true
bool fd_inject_error(int edx);
bool fc_inject_error(int edx);
bool sc_inject_error(int edx);

#define fusedav_inject_error(edx) fd_inject_error(edx)
#define filecache_inject_error(edx) fc_inject_error(edx)
#define statcache_inject_error(edx) sc_inject_error(edx)

#else

#define injecting_errors false
#define fusedav_inject_error(edx) false
#define filecache_inject_error(edx) false
#define statcache_inject_error(edx) false

#endif

#endif

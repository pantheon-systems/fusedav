#ifndef foofusedevhfoo
#define foofusedevhfoo

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
#include "util.h"

extern int debug;

#ifndef G_DEFINE_QUARK

#define             G_DEFINE_QUARK(QN, q_n)\
static GQuark \
q_n##_quark (void) \
{ \
  static GQuark g_define_quark = 0; \
  if (G_UNLIKELY (g_define_quark == 0)) \
    g_define_quark = g_quark_from_string (#QN); \
  return g_define_quark; \
}

// @TODO: Move this elsewhere.
char *strip_trailing_slash(char *fn, int *is_dir);

#endif
#endif

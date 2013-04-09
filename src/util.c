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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "util.h"

// @TODO: Fix path_parent to not require this.
static char *strndup(const char *s, size_t n) {
    size_t length;
    char *copy;

    if (s == NULL) {
        errno = EINVAL;
        return NULL;
    }
    length = strlen(s);
    if (length > n)
        length = n;
    copy = malloc(length + 1);
    if (copy == NULL)
        return NULL;
    memcpy(copy, s, length);
    copy[length] = '\0';
    return copy;
}

// Return value is allocated and must be freed.
char *path_parent(const char *uri) {
    size_t len = strlen(uri);
    const char *pnt = uri + len - 1;
    // skip trailing slash (parent of "/foo/" is "/")
    if (pnt >= uri && *pnt == '/')
        pnt--;
    // find previous slash
    while (pnt > uri && *pnt != '/')
        pnt--;
    if (pnt < uri || (pnt == uri && *pnt != '/'))
        return NULL;
    return strndup(uri, pnt - uri + 1);
}

#ifndef foofilecachehfoo
#define foofilecachehfoo

/* $Id$ */

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

void* file_cache_open(const char *path, int flags);
void* file_cache_get(const char *path);
void file_cache_unref(void *f);

int file_cache_close(void *f);

int file_cache_read(void *f, char *buf, size_t size, off_t offset);
int file_cache_write(void *f, const char *buf, size_t size, off_t offset);
int file_cache_truncate(void *f, off_t s);
int file_cache_sync(void *f);
int file_cache_close_all(void);


#endif

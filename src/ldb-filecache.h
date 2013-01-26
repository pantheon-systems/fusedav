#ifndef fooldbfilecachehfoo
#define fooldbfilecachehfoo

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

#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <leveldb/c.h>
#include <ne_basic.h>
#include "session.h"
#include "fuse.h"

typedef leveldb_t ldb_filecache_t;

int ldb_filecache_init(char *cache_path);
int ldb_filecache_delete(ldb_filecache_t *cache, const char *path);
int ldb_filecache_open(char *cache_path, ldb_filecache_t *cache, const char *path, struct fuse_file_info *info);
ssize_t ldb_filecache_read(struct fuse_file_info *info, char *buf, size_t size, ne_off_t offset);
ssize_t ldb_filecache_write(struct fuse_file_info *info, const char *buf, size_t size, ne_off_t offset);
int ldb_filecache_release(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info);
int ldb_filecache_sync(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info, bool do_put);
int ldb_filecache_truncate(struct fuse_file_info *info, ne_off_t s);
int ldb_filecache_fd(ldb_filecache_t *cache, const char *path);
int ldb_filecache_pdata_move(ldb_filecache_t *cache, const char *old_path, const char *new_path);

#endif

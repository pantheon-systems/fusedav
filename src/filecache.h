#ifndef fooldbfilecachehfoo
#define fooldbfilecachehfoo

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

#include <leveldb/c.h>
#include <glib.h>
#include "fuse.h"

/* Ultimately, it will be a dav_* function returning the value, so set it up for appropriate
 * values here, i.e. errno-like values. If curl errors occur, they are network errors
 * so report them as ENETDOWN. For leveldb, EIO is not a perfect fit,
 * but since it might get propagated to all kinds of dav_* function, EIO seems the closest
 * match. The closest approximation to PDATANULL is ENOENT; it means whenever we're trying
 * to do an operation, we don't have the file in the cache, so we can't update, etc.
 * Calling file too large EFBIG is pretty obvious.
 */
#define E_FC_PDATANULL ENOENT
#define E_FC_SDATANULL EIO
#define E_FC_LDBERR EIO
#define E_FC_CURLERR ENETDOWN
#define E_FC_FILETOOLARGE EFBIG

typedef leveldb_t filecache_t;

void filecache_print_stats(void);
void filecache_init(char *cache_path, GError **gerr);
void filecache_delete(filecache_t *cache, const char *path, bool unlink, GError **gerr);
void filecache_open(char *cache_path, filecache_t *cache, const char *path, struct fuse_file_info *info,
    unsigned grace_level, bool *used_grace, GError **gerr);
ssize_t filecache_read(struct fuse_file_info *info, char *buf, size_t size, off_t offset, GError **gerr);
ssize_t filecache_write(struct fuse_file_info *info, const char *buf, size_t size, off_t offset, GError **gerr);
void filecache_close(struct fuse_file_info *info, GError **gerr);
bool filecache_sync(filecache_t *cache, const char *path, struct fuse_file_info *info, bool do_put, GError **gerr);
void filecache_truncate(struct fuse_file_info *info, off_t s, GError **gerr);
int filecache_fd(struct fuse_file_info *info);
void filecache_set_error(struct fuse_file_info *info, int error_code);
void filecache_forensic_haven(const char *cache_path, filecache_t *cache, const char *path, off_t fsize, GError **gerr);
void filecache_pdata_move(filecache_t *cache, const char *old_path, const char *new_path, GError **gerr);
void filecache_cleanup(filecache_t *cache, const char *cache_path, bool first, GError **gerr);

#endif

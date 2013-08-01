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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fuse.h>
#include <jemalloc/jemalloc.h>

#include "util.h"
#include "log.h"
#include "log_sections.h"
#include "stats.h"
#include "statcache.h"

struct statistics stats;

static void malloc_stats_output(__unused void *cbopaque, const char *s) {
    char stripped[256];
    size_t len;

    len = strlen(s);
    if (len >= 256) {
        log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "Skipping line over 256 characters.");
        return;
    }

    // Ignore up to one leading space.
    if (s[0] == '\n')
        strncpy(stripped, s + 1, len);
    else
        strncpy(stripped, s, len);

    // Ignore up to two trailing spaces.
    if (stripped[len - 2] == '\n')
        stripped[len - 2] = '\0';
    if (stripped[len - 1] == '\n')
        stripped[len - 1] = '\0';
    stripped[len] = '\0';

    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "%s", stripped);
}

void print_stats(void) {
    mallctl("prof.dump", NULL, NULL, NULL, 0);

    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "Caught SIGUSR2. Printing status.");
    malloc_stats_print(malloc_stats_output, NULL, "");

    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "Operations:");
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  chmod:       %u", FETCH(dav_chmod));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  chown:       %u", FETCH(dav_chown));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  create:      %u", FETCH(dav_create));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  fsync:       %u", FETCH(dav_fsync));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  flush:       %u", FETCH(dav_flush));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  ftruncate:   %u", FETCH(dav_ftruncate));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  fgetattr:    %u", FETCH(dav_fgetattr));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  getattr:     %u", FETCH(dav_getattr));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  mkdir:       %u", FETCH(dav_mkdir));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  mknod:       %u", FETCH(dav_mknod));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  open:        %u", FETCH(dav_open));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  read:        %u", FETCH(dav_read));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  readdir:     %u", FETCH(dav_readdir));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  release:     %u", FETCH(dav_release));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  rename:      %u", FETCH(dav_rename));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  rmdir:       %u", FETCH(dav_rmdir));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  unlink:      %u", FETCH(dav_unlink));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  utimens:     %u", FETCH(dav_utimens));
    log_print(LOG_NOTICE, SECTION_FUSEDAV_OUTPUT, "  write:       %u", FETCH(dav_write));

    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "Filecache Operations:");
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  cache_file:  %u", FETCH(filecache_cache_file));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_set:   %u", FETCH(filecache_pdata_set));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  create_file: %u", FETCH(filecache_create_file));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_get:   %u", FETCH(filecache_pdata_get));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  fresh_fd:    %u", FETCH(filecache_fresh_fd));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  open:        %u", FETCH(filecache_open));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  read:        %u", FETCH(filecache_read));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  write:       %u", FETCH(filecache_write));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  close:       %u", FETCH(filecache_close));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  return_etag: %u", FETCH(filecache_return_etag));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  sync:        %u", FETCH(filecache_sync));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  truncate:    %u", FETCH(filecache_truncate));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  delete:      %u", FETCH(filecache_delete));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_move:  %u", FETCH(filecache_pdata_move));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  orphans:     %u", FETCH(filecache_orphans));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  cleanup:     %u", FETCH(filecache_cleanup));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  get_fd:      %u", FETCH(filecache_get_fd));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  set_error:   %u", FETCH(filecache_set_error));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  forensic:    %u", FETCH(filecache_forensic_haven));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  init:        %u", FETCH(filecache_init));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  path2key:    %u", FETCH(filecache_path2key));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  key2path:    %u", FETCH(filecache_key2path));

    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "Stat Cache Operations:");
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  local_gen:   %u", FETCH(statcache_local_gen));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  path2key:    %u", FETCH(statcache_path2key));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  key2path:    %u", FETCH(statcache_key2path));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  open:        %u", FETCH(statcache_open));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  close:       %u", FETCH(statcache_close));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  value_get:   %u", FETCH(statcache_value_get));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  updated_ch:  %u", FETCH(statcache_updated_ch));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  read_updated:%u", FETCH(statcache_read_updated));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  value_set:   %u", FETCH(statcache_value_set));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  delete:      %u", FETCH(statcache_delete));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  del_parent:  %u", FETCH(statcache_del_parent));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  iter_free:   %u", FETCH(statcache_iter_free));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  iter_init:   %u", FETCH(statcache_iter_init));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  iter_current:%u", FETCH(statcache_iter_current));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  iter_next:   %u", FETCH(statcache_iter_next));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  enumerate:   %u", FETCH(statcache_enumerate));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  has_child:   %u", FETCH(statcache_has_child));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  delete_older:%u", FETCH(statcache_delete_older));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  forensic:    %u", FETCH(statcache_forensic_haven));
    log_print(LOG_NOTICE, SECTION_STATCACHE_OUTPUT, "  prune:       %u", FETCH(statcache_prune));
}

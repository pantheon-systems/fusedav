#ifndef foostatshfoo
#define foostatshfoo

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

#include <stdbool.h>

struct statistics {
    unsigned dav_chmod;
    unsigned dav_chown;
    unsigned dav_create;
    unsigned dav_fsync;
    unsigned dav_flush;
    unsigned dav_ftruncate;
    unsigned dav_fgetattr;
    unsigned dav_getattr;
    unsigned dav_mkdir;
    unsigned dav_mknod;
    unsigned dav_open;
    unsigned dav_read;
    unsigned dav_readdir;
    unsigned dav_release;
    unsigned dav_rename;
    unsigned dav_rmdir;
    unsigned dav_unlink;
    unsigned dav_utimens;
    unsigned dav_write;

    unsigned filecache_cache_file;
    unsigned filecache_pdata_set;
    unsigned filecache_create_file;
    unsigned filecache_pdata_get;
    unsigned filecache_fresh_fd;
    unsigned filecache_open;
    unsigned filecache_read;
    unsigned filecache_write;
    unsigned filecache_close;
    unsigned filecache_return_etag;
    unsigned filecache_sync;
    unsigned filecache_truncate;
    unsigned filecache_delete;
    unsigned filecache_pdata_move;
    unsigned filecache_orphans;
    unsigned filecache_cleanup;
    unsigned filecache_get_fd;
    unsigned filecache_set_error;
    unsigned filecache_forensic_haven;
    unsigned filecache_init;
    unsigned filecache_path2key;
    unsigned filecache_key2path;
    unsigned filecache_get_xxsm_timing;
    unsigned filecache_get_xxsm_count;
    unsigned filecache_get_xsm_timing;
    unsigned filecache_get_xsm_count;
    unsigned filecache_get_sm_timing;
    unsigned filecache_get_sm_count;
    unsigned filecache_get_med_timing;
    unsigned filecache_get_med_count;
    unsigned filecache_get_lg_timing;
    unsigned filecache_get_lg_count;
    unsigned filecache_get_xlg_timing;
    unsigned filecache_get_xlg_count;
    unsigned filecache_put_xxsm_timing;
    unsigned filecache_put_xxsm_count;
    unsigned filecache_put_xsm_timing;
    unsigned filecache_put_xsm_count;
    unsigned filecache_put_sm_timing;
    unsigned filecache_put_sm_count;
    unsigned filecache_put_med_timing;
    unsigned filecache_put_med_count;
    unsigned filecache_put_lg_timing;
    unsigned filecache_put_lg_count;
    unsigned filecache_put_xlg_timing;
    unsigned filecache_put_xlg_count;

    unsigned statcache_local_gen;
    unsigned statcache_path2key;
    unsigned statcache_key2path;
    unsigned statcache_open;
    unsigned statcache_close;
    unsigned statcache_value_get;
    unsigned statcache_updated_ch;
    unsigned statcache_read_updated;
    unsigned statcache_value_set;
    unsigned statcache_delete;
    unsigned statcache_del_parent;
    unsigned statcache_iter_free;
    unsigned statcache_iter_init;
    unsigned statcache_iter_current;
    unsigned statcache_iter_next;
    unsigned statcache_enumerate;
    unsigned statcache_has_child;
    unsigned statcache_delete_older;
    unsigned statcache_prune;
};

extern struct statistics stats;

#define TIMING(op, timing) __sync_fetch_and_add(&stats.op, (timing))
#define BUMP(op) __sync_fetch_and_add(&stats.op, 1)
#define FETCH(c) __sync_fetch_and_or(&stats.c, 0)

void print_stats(void);
void dump_stats(bool log, const char *cache_path);
void binding_busyness_stats(void);

#endif

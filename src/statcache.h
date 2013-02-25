#ifndef foostatcachehfoo
#define foostatcachehfoo

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

#include <sys/stat.h>
#include <leveldb/c.h>

#define RGEN_LEN 128
#define STAT_CACHE_OLD_DATA 2
#define STAT_CACHE_NO_DATA 1

#define STAT_CACHE_NEGATIVE_TTL 3

typedef leveldb_t stat_cache_t;

struct stat_cache_supplemental {
    leveldb_cache_t *lru;
    leveldb_options_t *options;
};

// Used opaquely outside this library.
struct stat_cache_iterator {
    leveldb_iterator_t *ldb_iter;
    leveldb_readoptions_t *ldb_options;
    char *key_prefix;
    size_t key_prefix_len;
};

struct stat_cache_value {
    struct stat st;
    unsigned long local_generation;
    time_t updated;
    bool prepopulated; // Added to the local cache; not from the server.
    char remote_generation[RGEN_LEN];
};

int print_stat(struct stat *stbuf, const char *title);

unsigned long stat_cache_get_local_generation(void);

int stat_cache_open(stat_cache_t **cache, struct stat_cache_supplemental *supplemental, char *cache_path);
int stat_cache_close(stat_cache_t *cache, struct stat_cache_supplemental supplemental);

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *path, bool skip_freshness_check);
int stat_cache_updated_children(stat_cache_t *cache, const char *path, time_t timestamp);
time_t stat_cache_read_updated_children(stat_cache_t *cache, const char *path);
int stat_cache_value_set(stat_cache_t *cache, const char *path, struct stat_cache_value *value);
void stat_cache_value_free(struct stat_cache_value *value);

int stat_cache_delete(stat_cache_t *cache, const char* path);
int stat_cache_delete_parent(stat_cache_t *cache, const char *path);
int stat_cache_delete_older(stat_cache_t *cache, const char *key_prefix, unsigned int minimum_local_generation);

int stat_cache_enumerate(stat_cache_t *cache, const char *key_prefix, void (*f) (const char *path, const char *child_path, void *user), void *user, bool force);

#endif

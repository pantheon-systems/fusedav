#ifndef foostatcachehfoo
#define foostatcachehfoo

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

#include <sys/stat.h>
#include <leveldb/c.h>
#include <glib.h>
#include <errno.h>
#include <stdbool.h>

#define RGEN_LEN 128
#define STAT_CACHE_OLD_DATA 2
#define STAT_CACHE_NO_DATA 1

#define STAT_CACHE_NEGATIVE_TTL 2

/* Since ultimately we return errno-like values, assign them here to our errors.
 * The only one is a leveldb error. Use EIO, since it indicates something unusual
 * has happened. This is probably the best approximation.
 */
#define E_SC_SUCCESS 0
#define E_SC_LDBERR EIO

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

// For values which have been requested but don't exist in the cache
// Make this a structure so that if we need more fields in the
// future, we will have the facility to add them.
struct stat_cache_negative_value {
    // Track the number of times a propfind has returned ENOENT on this path
    time_t propfinds_made;
};

// For values which exist in the cache
struct stat_cache_value {
    struct stat st;
    unsigned long local_generation;
    time_t updated;
    // Unused
    bool prepopulated; // Added to the local cache; not from the server.
    // We aren't using remote_generation, so reuse the field
    // Since the items we store in the cache are all of a size
    // which included remote_generation, leave it in.
    // Make sure struct stat_cache_negative_value never exceeds
    // RGEN_LEN in length.
    union {
        char remote_generation[RGEN_LEN];
        struct stat_cache_negative_value negative_value;
    } negative_value;
};

void stat_cache_print_stats(void);
int print_stat(struct stat *stbuf, const char *title);

unsigned long stat_cache_get_local_generation(void);

void stat_cache_open(stat_cache_t **cache, struct stat_cache_supplemental *supplemental, char *cache_path, GError **gerr);
void stat_cache_close(stat_cache_t *cache, struct stat_cache_supplemental supplemental);

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *path, bool skip_freshness_check, GError **gerr);
void stat_cache_updated_children(stat_cache_t *cache, const char *path, time_t timestamp, GError **gerr);
time_t stat_cache_read_updated_children(stat_cache_t *cache, const char *path, GError **gerr);
void stat_cache_value_set(stat_cache_t *cache, const char *path, struct stat_cache_value *value, GError **gerr);
void stat_cache_value_free(struct stat_cache_value *value);

bool stat_cache_is_negative_entry(struct stat_cache_value value);
void stat_cache_negative_entry(stat_cache_t *cache, const char* path, bool update, GError **gerr);
void stat_cache_delete(stat_cache_t *cache, const char* path, GError **gerr);
void stat_cache_delete_parent(stat_cache_t *cache, const char *path, GError **gerr);
void stat_cache_delete_older(stat_cache_t *cache, const char *key_prefix, unsigned long minimum_local_generation, GError **gerr);

void stat_cache_walk(void);
int stat_cache_enumerate(stat_cache_t *cache, const char *key_prefix, void (*f) (const char *path_prefix, 
            const char *filename, void *user), void *user, bool force);
bool stat_cache_dir_has_child(stat_cache_t *cache, const char *path);
void stat_cache_prune(stat_cache_t *cache);

#endif

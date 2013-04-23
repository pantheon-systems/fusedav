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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <limits.h>

#include "statcache.h"
#include "fusedav.h"
#include "log.h"
#include "session.h"
#include "bloom-filter.h"
#include "util.h"

#define CACHE_TIMEOUT 3

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

struct stat_cache_entry {
    const char *key;
    const struct stat_cache_value *value;
};

struct statistics {
    unsigned local_gen;
    unsigned path2key;
    unsigned key2path;
    unsigned open;
    unsigned close;
    unsigned value_get;
    unsigned updated_ch;
    unsigned read_updated;
    unsigned value_set;
    unsigned delete;
    unsigned del_parent;
    unsigned iter_free;
    unsigned iter_init;
    unsigned iter_current;
    unsigned iter_next;
    unsigned enumerate;
    unsigned has_child;
    unsigned delete_older;
    unsigned prune;
};

static struct statistics stats;

#define BUMP(op) __sync_fetch_and_add(&stats.op, 1)
#define FETCH(c) __sync_fetch_and_or(&stats.c, 0)

void stat_cache_print_stats(void) {
    log_print(LOG_NOTICE, "Stat Cache Operations:");
    log_print(LOG_NOTICE, "  local_gen:   %u", FETCH(local_gen));
    log_print(LOG_NOTICE, "  path2key:    %u", FETCH(path2key));
    log_print(LOG_NOTICE, "  key2path:    %u", FETCH(key2path));
    log_print(LOG_NOTICE, "  open:        %u", FETCH(open));
    log_print(LOG_NOTICE, "  close:       %u", FETCH(close));
    log_print(LOG_NOTICE, "  value_get:   %u", FETCH(value_get));
    log_print(LOG_NOTICE, "  updated_ch:  %u", FETCH(updated_ch));
    log_print(LOG_NOTICE, "  read_updated:%u", FETCH(read_updated));
    log_print(LOG_NOTICE, "  value_set:   %u", FETCH(value_set));
    log_print(LOG_NOTICE, "  delete:      %u", FETCH(delete));
    log_print(LOG_NOTICE, "  del_parent:  %u", FETCH(del_parent));
    log_print(LOG_NOTICE, "  iter_free:   %u", FETCH(iter_free));
    log_print(LOG_NOTICE, "  iter_init:   %u", FETCH(iter_init));
    log_print(LOG_NOTICE, "  iter_current:%u", FETCH(iter_current));
    log_print(LOG_NOTICE, "  iter_next:   %u", FETCH(iter_next));
    log_print(LOG_NOTICE, "  enumerate:   %u", FETCH(enumerate));
    log_print(LOG_NOTICE, "  has_child:   %u", FETCH(has_child));
    log_print(LOG_NOTICE, "  delete_older:%u", FETCH(delete_older));
    log_print(LOG_NOTICE, "  prune:       %u", FETCH(prune));
}

G_DEFINE_QUARK(LDB, leveldb)
G_DEFINE_QUARK(BLOOM, bloomfilter)

unsigned long stat_cache_get_local_generation(void) {
    static unsigned long counter = 0;
    unsigned long ret;

    BUMP(local_gen);

    pthread_mutex_lock(&counter_mutex);
    if (counter == 0) {
        // Top 40 bits for the timestamp. Bottom 24 bits for the counter.
        // Will be safe for at least a couple hundred years.
        counter = time(NULL);
        //log_print(LOG_DEBUG, "Pre-shift counter: %lu", counter);
        counter <<= 24;
        //log_print(LOG_DEBUG, "Initialized counter: %lu", counter);
    }
    ret = ++counter;
    pthread_mutex_unlock(&counter_mutex);
    //log_print(LOG_DEBUG, "stat_cache_get_local_generation: %lu", ret);
    return ret;
}

int print_stat(struct stat *stbuf, const char *title) {
    if (debug) {
        log_print(LOG_DEBUG, "stat: %s", title);
        log_print(LOG_DEBUG, "  .st_mode=%04o", stbuf->st_mode);
        log_print(LOG_DEBUG, "  .st_nlink=%ld", stbuf->st_nlink);
        log_print(LOG_DEBUG, "  .st_uid=%d", stbuf->st_uid);
        log_print(LOG_DEBUG, "  .st_gid=%d", stbuf->st_gid);
        log_print(LOG_DEBUG, "  .st_size=%ld", stbuf->st_size);
        log_print(LOG_DEBUG, "  .st_blksize=%ld", stbuf->st_blksize);
        log_print(LOG_DEBUG, "  .st_blocks=%ld", stbuf->st_blocks);
        log_print(LOG_DEBUG, "  .st_atime=%ld", stbuf->st_atime);
        log_print(LOG_DEBUG, "  .st_mtime=%ld", stbuf->st_mtime);
        log_print(LOG_DEBUG, "  .st_ctime=%ld", stbuf->st_ctime);
    }
    return E_SC_SUCCESS;
}

void stat_cache_value_free(struct stat_cache_value *value) {
    leveldb_free(value);
}

// Allocates a new string.
static char *path2key(const char *path, bool prefix) {
    char *key = NULL;
    unsigned int depth = 0;
    size_t pos = 0;
    bool slash_found = false;
    size_t last_slash_pos = 0;

    BUMP(path2key);

    log_print(LOG_DEBUG, "path2key(%s, %i)", path, prefix);

    if (prefix)
        ++depth;

    while (path[pos]) {
        if (path[pos] == '/') {
            ++depth;
            last_slash_pos = pos;
            slash_found = true;
        }
        ++pos;
    }

    // If the given path ended with a slash and a prefix was requested,
    // ignore the trailing slash for depth purposes and avoid adding a
    // second trailing slash.
    if (prefix && slash_found && last_slash_pos == pos - 1) {
        depth--;
        asprintf(&key, "%u%s", depth, path);
    }
    else if (prefix) {
        asprintf(&key, "%u%s/", depth, path);
    }
    else {
        asprintf(&key, "%u%s", depth, path);
    }
    return key;
}

// Does *not* allocate a new string.
static const char *key2path(const char *key) {
    size_t pos = 0;

    BUMP(key2path);

    while (key[pos]) {
        if (key[pos] == '/')
            return key + pos;
        ++pos;
    }
    return NULL;
}

void stat_cache_open(stat_cache_t **cache, struct stat_cache_supplemental *supplemental, char *cache_path, GError **gerr) {
    char *errptr = NULL;
    char storage_path[PATH_MAX];

    BUMP(open);

    // Check that a directory is set.
    if (!cache_path) {
        // @TODO: Before public release: Use a mkdtemp-based path.
        g_set_error (gerr, leveldb_quark(), EINVAL, "stat_cache_open: no cache path specified.");
        return;
    }

    snprintf(storage_path, PATH_MAX, "%s/leveldb", cache_path);

    supplemental->options = leveldb_options_create();

    // Initialize LevelDB's LRU cache.
    supplemental->lru = NULL;
    //supplemental->lru = leveldb_cache_create_lru(5 * 1048576); // 5MB
    //leveldb_options_set_cache(supplemental->options, supplemental->lru);

    // Create the database if missing.
    leveldb_options_set_create_if_missing(supplemental->options, true);
    leveldb_options_set_error_if_exists(supplemental->options, false);

    // Use a fusedav logger.
    leveldb_options_set_info_log(supplemental->options, NULL);

    *cache = leveldb_open(supplemental->options, storage_path, &errptr);
    if (errptr) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_open: Error opening db; %s.", errptr);
        free(errptr);
        return;
    }

    return;
}

void stat_cache_close(stat_cache_t *cache, struct stat_cache_supplemental supplemental) {

    BUMP(close);

    if (cache != NULL)
        leveldb_close(cache);
    if (supplemental.options != NULL) {
        leveldb_options_destroy(supplemental.options);
        log_print(LOG_DEBUG, "leveldb_options_destroy");
    }
    if (supplemental.lru != NULL)
        leveldb_cache_destroy(supplemental.lru);
    return;
}

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *path, bool skip_freshness_check, GError **gerr) {
    struct stat_cache_value *value = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;
    time_t current_time;

    BUMP(value_get);

    key = path2key(path, false);

    log_print(LOG_DEBUG, "CGET: %s", key);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    value = (struct stat_cache_value *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);
    free(key);

    if (errptr != NULL) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "leveldb_get error: %s", errptr);
        free(errptr);
        free(value);
        return NULL;
    }

    if (value == NULL) {
        log_print(LOG_DEBUG, "stat_cache_value_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct stat_cache_value)) {
        log_print(LOG_NOTICE, "Length %lu is not expected length %lu.", vallen, sizeof(struct stat_cache_value));
    }

    if (!skip_freshness_check) {
        current_time = time(NULL);

        // First, check against the stat item itself.
        //log_print(LOG_DEBUG, "Current time: %lu", current_time);
        if (current_time - value->updated > CACHE_TIMEOUT) {
            char *directory;
            time_t directory_updated;
            int is_dir;

            log_print(LOG_DEBUG, "Stat entry %s is %lu seconds old.", path, current_time - value->updated);

            // If that's too old, check the last update of the directory.
            directory = strip_trailing_slash(path_parent(path), &is_dir);
            directory_updated = stat_cache_read_updated_children(cache, directory);
            //log_print(LOG_DEBUG, "Directory contents for %s are %lu seconds old.", directory, (current_time - directory_updated));
            free(directory);
            if (current_time - directory_updated > CACHE_TIMEOUT) {
                log_print(LOG_DEBUG, "%s is too old.", path);
                free(value);
                return NULL;
            }
        }
    }

    return value;
}

void stat_cache_updated_children(stat_cache_t *cache, const char *path, time_t timestamp, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;

    BUMP(updated_ch);

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_writeoptions_create();
    if (timestamp == 0)
        leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    else
        leveldb_put(cache, options, key, strlen(key) + 1, (char *) &timestamp, sizeof(time_t), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_updated_children: leveldb_set error: %s", errptr);
        free(errptr);
        return;
    }

    return;
}

time_t stat_cache_read_updated_children(stat_cache_t *cache, const char *path, GError **gerr) {
    leveldb_readoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;
    time_t *value = NULL;
    time_t ret;
    size_t vallen;

    BUMP(read_updated);

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    value = (time_t *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_read_updated_children: leveldb_get error: %s", errptr);
        free(errptr);
        free(value);
        return 0;
    }

    if (value == NULL) return 0;

    ret = *value;

    log_print(LOG_DEBUG, "Children for directory %s were updated at timestamp %lu.", path, ret);

    free(value);
    return ret;
}

void stat_cache_value_set(stat_cache_t *cache, const char *path, struct stat_cache_value *value, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;

    if (path == NULL) return 0;

    BUMP(value_set);

    assert(value);

    value->updated = time(NULL);
    value->local_generation = stat_cache_get_local_generation();

    key = path2key(path, false);
    log_print(LOG_DEBUG, "CSET: %s (mode %04o)", key, value->st.st_mode);

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) value, sizeof(struct stat_cache_value), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_value_set: leveldb_set error: %s", errptr);
        free(errptr);
        return;
    }

    return;
}

void stat_cache_delete(stat_cache_t *cache, const char *path, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *key;
    char *errptr = NULL;

    BUMP(delete);

    key = path2key(path, false);

    log_print(LOG_DEBUG, "stat_cache_delete: %s", key);

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (errptr != NULL) {
        g_set_error (gerr, leveldb_quark(), E_SC_LDBERR, "stat_cache_delete: leveldb_delete error: %s", errptr);
        free(errptr);
        return;
    }

    log_print(LOG_DEBUG, "stat_cache_delete: exit %s", path);

    return;
}

void stat_cache_delete_parent(stat_cache_t *cache, const char *path) {
    char *p;

    BUMP(del_parent);

    log_print(LOG_DEBUG, "stat_cache_delete_parent: %s", path);
    if ((p = path_parent(path))) {
        int l = strlen(p);

        log_print(LOG_DEBUG, "stat_cache_delete_parent: deleting parent %s", p);
        if (strcmp(p, "/") && l) {
            if (p[l-1] == '/')
                p[l-1] = 0;
        }

        stat_cache_delete(cache, p);
        stat_cache_updated_children(cache, p, time(NULL) - CACHE_TIMEOUT - 1);
        free(p);
    }
    else {
        log_print(LOG_DEBUG, "stat_cache_delete_parent: not deleting parent, deleting child %s", path);
        stat_cache_delete(cache, path);
        stat_cache_updated_children(cache, path, time(NULL) - CACHE_TIMEOUT - 1);
    }
    return;
}

static void stat_cache_iterator_free(struct stat_cache_iterator *iter) {

    BUMP(iter_free);

    leveldb_iter_destroy(iter->ldb_iter);
    leveldb_readoptions_destroy(iter->ldb_options);
    free(iter->key_prefix);
    free(iter);
}

static struct stat_cache_iterator *stat_cache_iter_init(stat_cache_t *cache, const char *path_prefix) {
    struct stat_cache_iterator *iter = NULL;

    BUMP(iter_init);

    iter = malloc(sizeof(struct stat_cache_iterator));
    iter->key_prefix = path2key(path_prefix, true); // Handles allocating the duplicate.
    iter->key_prefix_len = strlen(iter->key_prefix) + 1;

    log_print(LOG_DEBUG, "creating leveldb iterator for prefix %s", iter->key_prefix);
    iter->ldb_options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(iter->ldb_options, false);
    iter->ldb_iter = leveldb_create_iterator(cache, iter->ldb_options);

    leveldb_iter_seek(iter->ldb_iter, iter->key_prefix, iter->key_prefix_len);

    return iter;
}

static struct stat_cache_entry *stat_cache_iter_current(struct stat_cache_iterator *iter) {
    struct stat_cache_entry *entry;
    const struct stat_cache_value *value;
    const char *key;
    size_t klen, vlen;

    BUMP(iter_current);

    assert(iter);

    // If we've gone beyond the end of the dataset, quit.
    if (!leveldb_iter_valid(iter->ldb_iter)) {
        return NULL;
    }

    key = leveldb_iter_key(iter->ldb_iter, &klen);
    log_print(LOG_DEBUG, "fetched key: %s", key);

    // If we've gone beyond the end of the prefix range, quit.
    // Use (iter->key_prefix_len - 1) to exclude the NULL at the prefix end.
    if (strncmp(key, iter->key_prefix, iter->key_prefix_len - 1) != 0) {
        log_print(LOG_DEBUG, "Key %s does not match prefix %s for %lu characters. Ending iteration.", key, iter->key_prefix, iter->key_prefix_len);
        return NULL;
    }

    value = (const struct stat_cache_value *) leveldb_iter_value(iter->ldb_iter, &vlen);

    entry = malloc(sizeof(struct stat_cache_entry));
    entry->key = key;
    entry->value = value;
    log_print(LOG_DEBUG, "iter_current: key = %s; value = %s", key, value);
    return entry;
}

static void stat_cache_iter_next(struct stat_cache_iterator *iter) {

    BUMP(iter_next);

    leveldb_iter_next(iter->ldb_iter);
}

/*
static void stat_cache_list_all(stat_cache_t *cache, const char *path) {
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *options;
    const struct stat_cache_value *itervalue;
    struct stat_cache_value *value;
    size_t klen, vlen;
    const char *iterkey;
    char *key = path2key(path, true);

    options = leveldb_readoptions_create();
    iter = leveldb_create_iterator(cache, options);
    leveldb_readoptions_destroy(options);

    leveldb_iter_seek(iter, key, strlen(key) + 1);
    free(key);

    while (leveldb_iter_valid(iter)) {
        //log_print(LOG_DEBUG, "Listing key: %s", leveldb_iter_key(iter, &klen));

        itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);
        if (S_ISDIR(itervalue->st.st_mode)) {
            iterkey = leveldb_iter_key(iter, &klen);
            log_print(LOG_DEBUG, "Listing directory: %s", iterkey);

            value = stat_cache_value_get(cache, key2path(iterkey));
            if (value) {
                log_print(LOG_DEBUG, "Direct get mode: %04o", value->st.st_mode);
                free(value);
            }
        }

        leveldb_iter_next(iter);
    }

    leveldb_iter_destroy(iter);
}
*/

int stat_cache_enumerate(stat_cache_t *cache, const char *path_prefix, void (*f) (const char *path, const char *child_path, void *user), void *user, bool force) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    unsigned found_entries = 0;
    time_t timestamp;
    time_t current_time;

    BUMP(enumerate);

    log_print(LOG_DEBUG, "stat_cache_enumerate(%s)", path_prefix);

    //stat_cache_list_all(cache, path_prefix);
    if (!force) {
        // Pass NULL for gerr; not tracking error, just zero return
        timestamp = stat_cache_read_updated_children(cache, path_prefix, NULL);

        if (timestamp == 0) {
            return -STAT_CACHE_NO_DATA;
        }

        // Check for cache values which are too old; but timestamp = 0 needs to trigger below
        current_time = time(NULL);
        if (current_time - timestamp > CACHE_TIMEOUT) {
            log_print(LOG_DEBUG, "cache value too old: %s %u", path_prefix, (unsigned)timestamp);
            return -STAT_CACHE_OLD_DATA;
        }
    }

    iter = stat_cache_iter_init(cache, path_prefix);
    log_print(LOG_DEBUG, "iterator initialized with prefix: %s", iter->key_prefix);

    while ((entry = stat_cache_iter_current(iter))) {
        log_print(LOG_DEBUG, "key: %s", entry->key);
        log_print(LOG_DEBUG, "fn: %s", entry->key + (iter->key_prefix_len - 1));
        f(path_prefix, entry->key + (iter->key_prefix_len - 1), user);
        ++found_entries;
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);
    log_print(LOG_DEBUG, "Done iterating: %u items.", found_entries);

    if (found_entries == 0)
        return -STAT_CACHE_NO_DATA;

    return E_SC_SUCCESS;
}

bool stat_cache_dir_has_child(stat_cache_t *cache, const char *path) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    bool has_children = false;

    BUMP(has_child);

    log_print(LOG_DEBUG, "stat_cache_dir_has_children(%s)", path);

    iter = stat_cache_iter_init(cache, path);
    if ((entry = stat_cache_iter_current(iter))) {
        has_children = true;
        log_print(LOG_DEBUG, "stat_cache_dir_has_children(%s); entry \'%s\'", path, entry->key);
        free(entry);
    }
    stat_cache_iterator_free(iter);

    return has_children;
}

void stat_cache_delete_older(stat_cache_t *cache, const char *path_prefix, unsigned long minimum_local_generation) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;

    BUMP(delete_older);

    log_print(LOG_DEBUG, "stat_cache_delete_older: %s", path_prefix);
    iter = stat_cache_iter_init(cache, path_prefix);
    while ((entry = stat_cache_iter_current(iter))) {
        if (entry->value->local_generation < minimum_local_generation) {
            stat_cache_delete(cache, key2path(entry->key));
        }
        free(entry);
        stat_cache_iter_next(iter);
    }
    stat_cache_iterator_free(iter);

    log_print(LOG_DEBUG, "stat_cache_delete_older: calling stat_cache_prune on %s", path_prefix);
    stat_cache_prune(cache);

    return;
}

vpod stat_cache_prune(stat_cache_t *cache) {
    // leveldb stuff
    leveldb_readoptions_t *roptions;
    leveldb_writeoptions_t *woptions;
    struct leveldb_iterator_t *iter;
    const char *iterkey;
    const char *key;
    char path[PATH_MAX];
    char *slash;
    const struct stat_cache_value *itervalue;
    size_t klen, vlen;

    // bloom filter stuff
    bloomfilter_options_t *boptions;
    char *errptr = NULL;

    int pass = 0;
    int passes = 1; // passes will grow as we detect larger depths
    int depth;
    int max_depth = 0;
    const char *base_directory = get_base_directory();
    size_t base_directory_len = strlen(base_directory);

    // Statistics
    int visited_entries = 0;
    int deleted_entries = 0;
    int issues = 0;
    time_t elapsedtime;

    BUMP(prune);

    elapsedtime = time(NULL);

    log_print(LOG_DEBUG, "stat_cache_prune: enter");

    boptions = bloomfilter_init(0, NULL, 0, &errptr);
    if (boptions == NULL) {
        g_set_error (gerr, bloomfilter_quark(), E_SC_BLOOMERR, "stat_cache_prune: failed to allocate bloom filter: %s", errptr);
        free(errptr);
        return;
    }

    // We need to make sure the base_directory is in the filter before continuing
    log_print(LOG_DEBUG, "stat_cache_prune: attempting base_directory %s)", base_directory);
    if (bloomfilter_add(boptions, base_directory, strlen(base_directory)) < 0) {
        g_set_error (gerr, bloomfilter_quark(), E_SC_BLOOMERR, "stat_cache_prune: seed: error on ITERKEY: \'%s\')", path);
        return;
    }

    log_print(LOG_DEBUG, "stat_cache_prune: put base_directory %s in filter", base_directory);

    roptions = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(roptions, false);
    iter = leveldb_create_iterator(cache, roptions);

    // Entries are in alphabetical order, so 10 is before 6;
    // on the first pass, find the first depth less than 10, and process to the end;
    // on the second pass, process depth greater or equal to than 10 but less than 99;
    // on the second pass, process depth greater or equal to than 100 but less than 999;
    // on the second pass, process depth greater or equal to than 1000 but less than 9999;
    while (pass < passes) {

        log_print(LOG_DEBUG, "stat_cache_prune: Changing pass:%d (%d)", pass, passes);
        leveldb_iter_seek_to_first(iter);

        for (; leveldb_iter_valid(iter); leveldb_iter_next(iter)) {
            iterkey = leveldb_iter_key(iter, &klen);
            // I have encountered bad entries in stat cache during development;
            // armor against potential faults
            key = key2path(iterkey);
            if (key == NULL) {
                log_print(LOG_NOTICE, "stat_cache_prune: ignoring malformed iterkey");
                woptions = leveldb_writeoptions_create();
                leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
                leveldb_writeoptions_destroy(woptions);
                ++issues;
                continue;
            }
            // We'll need to change path below, so we don't want it to be a part of iterkey.
            // Make a copy first.
            strncpy(path, key, PATH_MAX);
            log_print(LOG_DEBUG, "stat_cache_prune: ITERKEY: \'%s\' :: %s :: %s", iterkey, path, key);
            itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);

            // We control what kinds of entries are in the leveldb db.
            // Those beginning with a number are stat cache entries and
            // will be alphabetically first. As soon as we find an entry that
            // strtol cannot turn into a number, we know we have passed beyond
            // the normal stat cache entries into something else (e.g. filecache).
            // However, we also have to handle "updated_children" entries. We
            // handle them separately below.
            errno = 0;
            depth = strtol(iterkey, NULL, 10);

            // @TODO seems not to set errno on returning 0
            if (depth == 0 /*&& errno != 0*/) {
                log_print(LOG_DEBUG, "stat_cache_prune: depth = 0; break:%d, %d", depth, errno);
                break;
            }

            /* We need to handle paths which have up to 4096 directories in the path name.
             * (Note, the length of the path name itself, not the number of directories in a
             * particular subdirectory.)
             * Since we don't expect depths greater than 99, we avoid iterating again
             * when we know we don't have depths that great.
             * When max_depth crosses a boundary (10, 100, 1000), set it to the max
             * at that boundary (99, 999, 9999) to prevent continually calling this section.
             */
            if (depth > max_depth) {
                max_depth = depth;
                if (max_depth >= 1000) {
                    passes = 4;
                    max_depth = 9999;
                }
                else if (max_depth >= 100) {
                    passes = 3;
                    max_depth = 999;
                }
                else if (max_depth >= 10) {
                    passes = 2;
                    max_depth = 99;
                }
                log_print(LOG_DEBUG, "stat_cache_prune: New max_depth %d (%d :: %d %d)", max_depth, depth, pass, passes);
            }

            if ((pass == 0 && depth <= 9) || (pass == 1 && (depth >= 10 && depth <= 99)) ||
                (pass == 2 && (depth >= 100 && depth <= 999)) || (pass == 3 && depth >= 1000)) {

                log_print(LOG_DEBUG, "stat_cache_prune: Pass %d (%d)", pass, passes);
                ++visited_entries;

                // If base_directory is in the stat cache, we don't want to compare it
                // to its parent directory, find it absent in the filter, and remove base_directory
                if (strcmp(path, base_directory) == 0) {
                    continue;
                }

                // Find the trailing slash
                slash = strrchr(path, '/');

                // If there's no slash, there's no parent directory to compare against.
                // Effectively, we are ignorning this entry. Since base_directory is already
                // in the stat cache, this must be an errant entry. We should error instead?
                if (slash == NULL) {
                    log_print(LOG_INFO, "stat_cache_prune: ignoring errant entry \'%s\'", path);
                    continue;
                }

                // By putting a null in place of the last slash, path is now dirname(path).
                // The condition is to preserve base directories of just "/"
                if (base_directory_len > 1)
                    slash[0] = '\0';
                else
                    slash[1] = '\0';

                if (bloomfilter_exists(boptions, path, strlen(path))) {
                    log_print(LOG_DEBUG, "stat_cache_prune: exists in bloom filter\'%s\'", path);
                    // If the parent is in the filter, and this child is a directory, add it to
                    // the filter for iteration at the next depth
                    if (S_ISDIR(itervalue->st.st_mode)) {
                        // Reset to original, complete path
                        if (slash) slash[0] = '/';

                        log_print(LOG_DEBUG, "stat_cache_prune: add path to filter \'%s\')", path);
                        if (bloomfilter_add(boptions, path, strlen(path)) < 0) {
                            log_print(LOG_ERR, "stat_cache_prune: error on bloomfilter_add: \'%s\')", path);
                            break;
                        }
                    }
                }
                else {
                    log_print(LOG_DEBUG, "stat_cache_prune: doesn't exist in bloom filter \'%s\'", path);
                    ++deleted_entries;
                    // Reset to original, complete path
                    if (slash) slash[0] = '/';
                    log_print(LOG_DEBUG, "stat_cache_prune: deleting \'%s\'", path);
                    stat_cache_delete(cache, path);
                }
            }
        }
        ++pass;
        log_print(LOG_DEBUG, "stat_cache_prune: updating pass %d", pass);
    }

    // Handle updated_children entries
    leveldb_iter_seek(iter, "updated_children:", strlen("updated_children:") + 1);

    while (leveldb_iter_valid(iter)) {
        const char *basepath = NULL;
        iterkey = leveldb_iter_key(iter, &klen);

        // If we pass the last key which begins with updated_children:, we're done
        if (strncmp(iterkey, "updated_children:", strlen("updated_children:"))) {
            break;
        }
        ++visited_entries;
        // basepath is the "path" we use for the filter, it has "updated_children:" removed
        // If that path is in the filter, keep the updated_children entry; otherwise, delete
        // Unlike the processing above, we do not add to the filter, nor do we deal with
        // the parent path.
        basepath = strchr(iterkey, '/');

        // Bad entry. Log, delete from cache, continue
        if (basepath == NULL) {
            log_print(LOG_NOTICE, "stat_cache_prune: key error in updated_children entry: %s", iterkey);
            woptions = leveldb_writeoptions_create();
            leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
            leveldb_writeoptions_destroy(woptions);
            if (errptr != NULL) {
                log_print(LOG_ERR, "stat_cache_prune: leveldb_delete error: %s", errptr);
                free(errptr);
            }
            break;
        }

        if (bloomfilter_exists(boptions, basepath, strlen(basepath))) {
            log_print(LOG_DEBUG, "stat_cache_prune: exists in bloom filter (basepath of)\'%s\'", iterkey);
        }
        else {
            log_print(LOG_DEBUG, "stat_cache_prune: updated_children: deleting \'%s\'", iterkey);
            ++deleted_entries;
            // We recreate the basics of stat_cache_delete here, since we can't call it directly
            // since it doesn't deal with keys with "updated_children:"
            woptions = leveldb_writeoptions_create();
            leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
            leveldb_writeoptions_destroy(woptions);
            if (errptr != NULL) {
                log_print(LOG_ERR, "stat_cache_prune: leveldb_delete error: %s", errptr);
                free(errptr);
            }
        }
        leveldb_iter_next(iter);
    }

    leveldb_iter_destroy(iter);
    leveldb_readoptions_destroy(roptions);

    elapsedtime = time(NULL) - elapsedtime;
    log_print(LOG_NOTICE, "stat_cache_prune: visited %d cache entries; deleted %d; had %d issues; elapsedtime %lu", visited_entries, deleted_entries, issues, elapsedtime);

    bloomfilter_destroy(boptions);

    return;
}

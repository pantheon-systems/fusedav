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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
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

#include <ne_uri.h>

#define CACHE_TIMEOUT 3

static pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;

struct stat_cache_entry {
    const char *key;
    const struct stat_cache_value *value;
};

unsigned long stat_cache_get_local_generation(void) {
    static unsigned long counter = 0;
    unsigned long ret;
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
    return 0;
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
    while (key[pos]) {
        if (key[pos] == '/')
            return key + pos;
        ++pos;
    }
    return NULL;
}

int stat_cache_open(stat_cache_t **cache, struct stat_cache_supplemental *supplemental, char *cache_path) {
    char *error = NULL;
    char storage_path[PATH_MAX];

    // Check that a directory is set.
    if (!cache_path) {
        // @TODO: Before public release: Use a mkdtemp-based path.
        log_print(LOG_WARNING, "No cache path specified.");
        return -EINVAL;
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

    *cache = leveldb_open(supplemental->options, storage_path, &error);
    if (error) {
        log_print(LOG_ERR, "ERROR opening db: %s", error);
        return -1;
    }

    return 0;
}

int stat_cache_close(stat_cache_t *cache, struct stat_cache_supplemental supplemental) {
    if (cache != NULL)
        leveldb_close(cache);
    if (supplemental.options != NULL) {
        leveldb_options_destroy(supplemental.options);
        log_print(LOG_DEBUG, "leveldb_options_destroy");
    }
    if (supplemental.lru != NULL)
        leveldb_cache_destroy(supplemental.lru);
    return 0;
}

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *path, bool skip_freshness_check) {
    struct stat_cache_value *value = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;
    //void *f;
    time_t current_time;

    key = path2key(path, false);

    log_print(LOG_DEBUG, "CGET: %s", key);

    options = leveldb_readoptions_create();
    value = (struct stat_cache_value *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);
    free(key);

    //log_print(LOG_DEBUG, "Mode: %04o", value->st.st_mode);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_get error: %s", errptr);
        free(errptr);
        return NULL;
    }

    if (value == NULL) {
        log_print(LOG_DEBUG, "stat_cache_value_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct stat_cache_value)) {
        log_print(LOG_ERR, "Length %lu is not expected length %lu.", vallen, sizeof(struct stat_cache_value));
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
            directory = strip_trailing_slash(ne_path_parent(path), &is_dir);
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

    /*
    if ((f = file_cache_get(path))) {
        value->st.st_size = file_cache_get_size(f);
        file_cache_unref(cache, f);
    }
    */

    //print_stat(&value->st, "CGET");

    return value;
}

int stat_cache_updated_children(stat_cache_t *cache, const char *path, time_t timestamp) {
    leveldb_writeoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;
    int r = 0;

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_writeoptions_create();
    if (timestamp == 0)
        leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    else
        leveldb_put(cache, options, key, strlen(key) + 1, (char *) &timestamp, sizeof(time_t), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_set error: %s", errptr);
        free(errptr);
        r = -1;
    }

    return r;
}

time_t stat_cache_read_updated_children(stat_cache_t *cache, const char *path) {
    leveldb_readoptions_t *options;
    char *key = NULL;
    char *errptr = NULL;
    time_t *value = NULL;
    time_t r;
    size_t vallen;

    asprintf(&key, "updated_children:%s", path);

    options = leveldb_readoptions_create();
    value = (time_t *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_get error: %s", errptr);
        free(errptr);
        r = 0;
    }

    free(key);

    if (value == NULL) return 0;

    r = *value;

    //log_print(LOG_DEBUG, "Children for directory %s were updated at timestamp %lu.", path, r);

    free(value);
    return r;
}

int stat_cache_value_set(stat_cache_t *cache, const char *path, struct stat_cache_value *value) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;
    int r = 0;

    assert(value);

    value->updated = time(NULL);
    value->local_generation = stat_cache_get_local_generation();

    key = path2key(path, false);
    log_print(LOG_DEBUG, "CSET: %s (mode %04o)", key, value->st.st_mode);
    //print_stat(&value->st, "CSET");

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) value, sizeof(struct stat_cache_value), &errptr);
    leveldb_writeoptions_destroy(options);

    //log_print(LOG_DEBUG, "Setting key: %s", key);

    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_set error: %s", errptr);
        free(errptr);
        r = -1;
    }

    return r;
}

int stat_cache_delete(stat_cache_t *cache, const char *path) {
    leveldb_writeoptions_t *options;
    char *key;
    int r = 0;
    char *errptr = NULL;

    key = path2key(path, false);

    log_print(LOG_DEBUG, "stat_cache_delete: %s", key);

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_delete error: %s", errptr);
        free(errptr);
        r = -1;
    }

    return r;
}

int stat_cache_delete_parent(stat_cache_t *cache, const char *path) {
    char *p;

    log_print(LOG_DEBUG, "stat_cache_delete_parent: %s", path);
    if ((p = ne_path_parent(path))) {
        int l = strlen(p);

        if (strcmp(p, "/") && l) {
            if (p[l-1] == '/')
                p[l-1] = 0;
        }

        stat_cache_delete(cache, p);
        stat_cache_updated_children(cache, p, time(NULL) - CACHE_TIMEOUT - 1);
        free(p);
    }
    else {
        stat_cache_delete(cache, path);
        stat_cache_updated_children(cache, path, time(NULL) - CACHE_TIMEOUT - 1);
    }
    return 0;
}

static void stat_cache_iterator_free(struct stat_cache_iterator *iter) {
    leveldb_iter_destroy(iter->ldb_iter);
    leveldb_readoptions_destroy(iter->ldb_options);
    free(iter->key_prefix);
    free(iter);
}

static struct stat_cache_iterator *stat_cache_iter_init(stat_cache_t *cache, const char *path_prefix) {
    struct stat_cache_iterator *iter = NULL;

    iter = malloc(sizeof(struct stat_cache_iterator));
    iter->key_prefix = path2key(path_prefix, true); // Handles allocating the duplicate.
    iter->key_prefix_len = strlen(iter->key_prefix) + 1;

    //log_print(LOG_DEBUG, "creating leveldb iterator for prefix %s", iter->key_prefix);
    iter->ldb_options = leveldb_readoptions_create();
    iter->ldb_iter = leveldb_create_iterator(cache, iter->ldb_options);

    //log_print(LOG_DEBUG, "checking iterator validity");

    //if (!leveldb_iter_valid(iter->ldb_iter)) {
    //    log_print(LOG_ERR, "Initial LevelDB iterator is not valid.");
    //    return NULL;
    //}

    //log_print(LOG_DEBUG, "seeking");
    leveldb_iter_seek(iter->ldb_iter, iter->key_prefix, iter->key_prefix_len);

    return iter;
}

static struct stat_cache_entry *stat_cache_iter_current(struct stat_cache_iterator *iter) {
    struct stat_cache_entry *entry;
    const struct stat_cache_value *value;
    const char *key;
    size_t klen, vlen;

    assert(iter);

    //log_print(LOG_DEBUG, "checking iterator validity");

    // If we've gone beyond the end of the dataset, quit.
    if (!leveldb_iter_valid(iter->ldb_iter)) {
        return NULL;
    }

    //log_print(LOG_DEBUG, "fetching the key");

    key = leveldb_iter_key(iter->ldb_iter, &klen);
    // log_print(LOG_DEBUG, "fetched key: %s", key);

    //log_print(LOG_DEBUG, "fetched the key");

    // If we've gone beyond the end of the prefix range, quit.
    // Use (iter->key_prefix_len - 1) to exclude the NULL at the prefix end.
    if (strncmp(key, iter->key_prefix, iter->key_prefix_len - 1) != 0) {
        log_print(LOG_DEBUG, "Key %s does not match prefix %s for %lu characters. Ending iteration.", key, iter->key_prefix, iter->key_prefix_len);
        return NULL;
    }

    //log_print(LOG_DEBUG, "fetching the value");

    value = (const struct stat_cache_value *) leveldb_iter_value(iter->ldb_iter, &vlen);

    entry = malloc(sizeof(struct stat_cache_entry));
    entry->key = key;
    entry->value = value;
    // log_print(LOG_DEBUG, "iter_current: key = %s; value = %s", key, value);
    return entry;
}

static void stat_cache_iter_next(struct stat_cache_iterator *iter) {
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

    log_print(LOG_DEBUG, "stat_cache_enumerate(%s)", path_prefix);

    //stat_cache_list_all(cache, path_prefix);
    if (!force) {
        timestamp = stat_cache_read_updated_children(cache, path_prefix);

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
    //log_print(LOG_DEBUG, "iterator initialized with prefix: %s", iter->key_prefix);

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

    return 0;
}

int stat_cache_delete_older(stat_cache_t *cache, const char *path_prefix, unsigned int minimum_local_generation) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;

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

    return 0;
}

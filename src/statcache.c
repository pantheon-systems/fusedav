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

#include "statcache.h"
#include "filecache.h"
#include "fusedav.h"

#include <ne_uri.h>

#include <systemd/sd-journal.h>

#define CACHE_TIMEOUT 60

struct stat_cache_entry {
    const char *key;
    const struct stat_cache_value *value;
};

int print_stat(struct stat *stbuf, const char *title) {
    if (debug) {
        sd_journal_print(LOG_DEBUG, "stat: %s", title);
        sd_journal_print(LOG_DEBUG, "  .st_mode=%o", stbuf->st_mode);
        sd_journal_print(LOG_DEBUG, "  .st_nlink=%ld", stbuf->st_nlink);
        sd_journal_print(LOG_DEBUG, "  .st_uid=%d", stbuf->st_uid);
        sd_journal_print(LOG_DEBUG, "  .st_gid=%d", stbuf->st_gid);
        sd_journal_print(LOG_DEBUG, "  .st_size=%ld", stbuf->st_size);
        sd_journal_print(LOG_DEBUG, "  .st_blksize=%ld", stbuf->st_blksize);
        sd_journal_print(LOG_DEBUG, "  .st_blocks=%ld", stbuf->st_blocks);
        sd_journal_print(LOG_DEBUG, "  .st_atime=%ld", stbuf->st_atime);
        sd_journal_print(LOG_DEBUG, "  .st_mtime=%ld", stbuf->st_mtime);
        sd_journal_print(LOG_DEBUG, "  .st_ctime=%ld", stbuf->st_ctime);
    }
    return 0;
}

void stat_cache_value_free(struct stat_cache_value *value) {
    leveldb_free(value);
}

int stat_cache_open(stat_cache_t **c, char *storage_path) {
#ifdef HAVE_LIBLEVELDB
    char *error = NULL;
    leveldb_cache_t *ldb_cache;
    leveldb_options_t *options;

    // Check that a directory is set.
    if (!storage_path) {
        // @TODO: Use a mkdtemp-based path.
        sd_journal_print(LOG_WARNING, "No cache path specified.");
        return -EINVAL;
    }

    options = leveldb_options_create();

    // Initialize LevelDB's own cache.
    ldb_cache = leveldb_cache_create_lru(100 * 1048576); // 100MB
    leveldb_options_set_cache(options, ldb_cache);

    // Create the database if missing.
    leveldb_options_set_create_if_missing(options, true);
    leveldb_options_set_error_if_exists(options, false);

    // Use a fusedav logger.
    leveldb_options_set_info_log(options, NULL);

    *c = leveldb_open(options, storage_path, &error);
    if (error) {
        sd_journal_print(LOG_ERR, "ERROR opening db: %s", error);
        return -1;
    }
#endif
    return 0;
}

int stat_cache_close(stat_cache_t *c) {
#ifdef HAVE_LIBLEVELDB
    if (c != NULL)
        leveldb_close(c);
#endif
    return 0;
}

struct timespec stat_cache_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        sd_journal_print(LOG_ERR, "clock_gettime error: %d", -errno);
        // @TODO: Something to do here?
    }
    return now;
}

struct stat_cache_value *stat_cache_value_get(stat_cache_t *cache, const char *key) {
    struct stat_cache_value *value = NULL;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;
    void *f;
    struct timespec now;

    if (debug)
        sd_journal_print(LOG_DEBUG, "CGET: %s", key);

    options = leveldb_readoptions_create();
    value = (struct stat_cache_value *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);

    if (errptr != NULL) {
        sd_journal_print(LOG_ERR, "leveldb_get error: %s", errptr);
        free(errptr);
        return NULL;
    }

    if (!value) {
        if (debug)
            sd_journal_print(LOG_DEBUG, "stat_cache_get miss on key: %s", key);
        return NULL;
    }

    now = stat_cache_now();

    if (value->local_generation.tv_sec >= now.tv_sec - CACHE_TIMEOUT) {
        // @TODO: Don't rely on file cache for this.
        if ((f = file_cache_get(key))) {
            value->st.st_size = file_cache_get_size(f);
            file_cache_unref(cache, f);
        }
    }

    return value;
}

int stat_cache_value_set(stat_cache_t *cache, const char *key, struct stat_cache_value *value) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    int r = 0;

    assert(value);

    if (debug)
        sd_journal_print(LOG_DEBUG, "CSET: %s", key);
        print_stat(&value->st, "CSET");

    if (clock_gettime(CLOCK_MONOTONIC, &value->local_generation) < 0) {
        sd_journal_print(LOG_ERR, "clock_gettime error: %d", -errno);
        r = -errno;
    }

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) value, sizeof(value), &errptr);
    leveldb_writeoptions_destroy(options);
    
    if (errptr != NULL) {
        sd_journal_print(LOG_ERR, "leveldb_set error: %s", errptr);
        free(errptr);
        r = -1;
    }

    value = stat_cache_value_get(cache, key);
    if (value == NULL)
        sd_journal_print(LOG_ERR, "item just written not readable");

    return r;
}

int stat_cache_delete(stat_cache_t *cache, const char *key) {
    leveldb_writeoptions_t *options;
    int r = 0;
    char *errptr = NULL;

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);

    if (errptr != NULL) {
        sd_journal_print(LOG_ERR, "leveldb_delete error: %s", errptr);
        free(errptr);
        r = -1;
    }

    return r;
}

int stat_cache_delete_parent(stat_cache_t *cache, const char *key) {
    char *p;

    if ((p = ne_path_parent(key))) {
        int l = strlen(p);

        if (strcmp(p, "/") && l) {
            if (p[l-1] == '/')
                p[l-1] = 0;
        }
        
        stat_cache_delete(cache, p);
        free(p);
    } else
        stat_cache_delete(cache, key);
    return 0;
}

static void stat_cache_iterator_free(struct stat_cache_iterator *iter) {
    free(iter->key_prefix);
    free(iter);
}

static struct stat_cache_iterator *stat_cache_iter_init(stat_cache_t *cache, const char *key_prefix_arg) {
    struct stat_cache_iterator *iter = NULL;
    leveldb_readoptions_t *options;

    iter = malloc(sizeof(struct stat_cache_iterator));
    iter->key_prefix = strdup(key_prefix_arg);
    iter->key_prefix_len = strlen(iter->key_prefix) + 1;

    sd_journal_print(LOG_DEBUG, "creating leveldb iterator");
    options = leveldb_readoptions_create();
    iter->ldb_iter = leveldb_create_iterator(cache, options);
    leveldb_readoptions_destroy(options);

    //sd_journal_print(LOG_DEBUG, "checking iterator validity");

    //if (!leveldb_iter_valid(iter->ldb_iter)) {
    //    sd_journal_print(LOG_ERR, "Initial LevelDB iterator is not valid.");
    //    return NULL;
    //}

    sd_journal_print(LOG_DEBUG, "seeking");
    leveldb_iter_seek(iter->ldb_iter, iter->key_prefix, iter->key_prefix_len);

    return iter;
}

static struct stat_cache_entry *stat_cache_iter_pop(struct stat_cache_iterator *iter) {
    struct stat_cache_entry *entry;
    const struct stat_cache_value *value;
    const char *key;
    size_t klen, vlen;

    assert(iter);

    sd_journal_print(LOG_DEBUG, "checking iterator validity");

    // If we've gone beyond the end of the dataset, quit.
    if (!leveldb_iter_valid(iter->ldb_iter)) {
        leveldb_iter_destroy(iter->ldb_iter);
        return NULL;
    }

    sd_journal_print(LOG_DEBUG, "fetching the key");

    key = leveldb_iter_key(iter->ldb_iter, &klen);
    sd_journal_print(LOG_DEBUG, "key: %s", key);

    sd_journal_print(LOG_DEBUG, "fetched the key");

    // If we've gone beyond the end of the prefix range, quit.
    if (strncmp(key, iter->key_prefix, iter->key_prefix_len) != 0) {
        leveldb_iter_destroy(iter->ldb_iter);
        return NULL;
    }

    sd_journal_print(LOG_DEBUG, "fetching the value");

    value = (const struct stat_cache_value *) leveldb_iter_value(iter->ldb_iter, &vlen);

    entry = malloc(sizeof(struct stat_cache_entry));
    entry->key = key;
    entry->value = value;
    leveldb_iter_next(iter->ldb_iter);
    return entry;
}

int stat_cache_enumerate(stat_cache_t *cache, const char *key_prefix, void (*f) (const char *key, const char *child_key, void *user), void *user) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    bool found_entries = false;

    if (debug)
        sd_journal_print(LOG_DEBUG, "stat_cache_enumerate(%s)", key_prefix);

    iter = stat_cache_iter_init(cache, key_prefix);
    sd_journal_print(LOG_DEBUG, "iterator initialized");

    while (entry = stat_cache_iter_pop(iter)) {
        f(entry->key, entry->key, user);
        found_entries = true;
        free(entry);
    }
    stat_cache_iterator_free(iter);
    sd_journal_print(LOG_DEBUG, "done iterating");

    if (!found_entries)
        return -1;

    return 0;
}

int stat_cache_delete_older(stat_cache_t *cache, const char *key_prefix, struct timespec min_time) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;

    iter = stat_cache_iter_init(cache, key_prefix);
    entry = stat_cache_iter_pop(iter);
    while (entry != NULL) {
        if (memcmp(&min_time, &entry->value->local_generation, sizeof(struct timespec)) > 0) {
            stat_cache_delete(cache, entry->key);
        }
        free(entry);
        entry = stat_cache_iter_pop(iter);
    }
    stat_cache_iterator_free(iter);

    return 0;
}

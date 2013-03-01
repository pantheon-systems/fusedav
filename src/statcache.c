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

#include <ne_uri.h>

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

// Allocates a new string via path2key
static char *updated_children2canonicalkey(const char *keyin) {
    char * path = strchr(keyin, '/');
    return path2key(path, false);
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
    leveldb_readoptions_set_fill_cache(options, false);
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
    if (timestamp == 0) {
        log_print(LOG_DEBUG, "stat_cache_updated_children: Children for directory %s were deleted at timestamp %lu; key = %s", path, timestamp, key);
        leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    }
    else {
        log_print(LOG_DEBUG, "stat_cache_updated_children: Children for directory %s were updated at timestamp %lu; key = %s", path, timestamp, key);
        leveldb_put(cache, options, key, strlen(key) + 1, (char *) &timestamp, sizeof(time_t), &errptr);
    }
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
    leveldb_readoptions_set_fill_cache(options, false);
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

    log_print(LOG_DEBUG, "stat_cache_delete: exit %s", path);

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
    leveldb_readoptions_set_fill_cache(iter->ldb_options, false);
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

bool stat_cache_dir_has_child(stat_cache_t *cache, const char *path) {
    struct stat_cache_iterator *iter;
    struct stat_cache_entry *entry;
    bool has_children = false;

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

int stat_cache_delete_older(stat_cache_t *cache, const char *path_prefix, unsigned long minimum_local_generation) {
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

    log_print(LOG_DEBUG, "stat_cache_delete_older: %s; calling stat_cache_prune", path_prefix);
    stat_cache_prune(cache);

    return 0;
}

// Initial and resize increment of array to hold current and previous depth's directory names for next iteration
#define MAX_DIRS 64
// Because of alphabetic order, 10, 11, 12 etc appear earlier in list than 5, 6, 7, so we
// process in 2 phases. If we need a directory depth greater than 99, god forbid, make this 3
#define PHASES 2

// We are checking for orphaned paths. During the iteration at the previous
// depth, we collected the names of all directories existing at that depth.
// Now we are at the next depth, and seeing if the immediate directory that
// we find this file in actually exists, by checking that it was present
// at the previous depth.
// By passing in pbasename as a char * when it really mirrors a two-dimensional
// array, we have effectively squashed the array into a single dimension. This
// requires us to actively increment the address by the size of the second
// dimension, i.e. PATH_MAX
// If we found a match when idx was, say, 2, it means that it matched the
// 2nd entry in the pbasename. We keep track of this (*pdx = idx). The next
// call to this function for the next iterkey will be alphabetically the same
// or later than this call, so there is no need to start from 0 again, since
// these entries alphabetically precede all subsequent entries.
static int check_for_dir_match(char *dirname, char **basename, int *pdx, int depth) {
    int result;
    int found = 0;
    log_print(LOG_DEBUG, "Entering check_for_dir_match: dir: %s :: base: %s :: pdx:%d ; depth = %d", dirname, basename[*pdx], *pdx, depth);
    for (; *pdx < MAX_DIRS; (*pdx)++) {
        if (basename[*pdx][0] == '\0') break;
        log_print(LOG_DEBUG, "processing check_for_dir_match: dn: %s :: pn: %s :: %d", dirname, basename[*pdx], *pdx);
        result = strncmp(dirname, basename[*pdx], PATH_MAX);

        // if strncmp is 0, we have a match
        if (result == 0) {
            found = 1;
            log_print(LOG_DEBUG, "check_for_dir_match: found; %s :: %d ; depth = %d", dirname, *pdx, depth);
            break;
        }
        // if strncmp is less than 0, then we have already passed lexicographically the entry we would match at.
        // All further entries are also greater than the current one, and we will not match on them
        else if (result < 0) {
            log_print(LOG_DEBUG, "check_for_dir_match: break; strncmp < 0; %s -- %s :: %d ; depth = %d", dirname, basename[*pdx], *pdx, depth);
            break;
        }
        else {
            log_print(LOG_DEBUG, "check_for_dir_match: strncmp > 0; still looking... : %s -- %s :: %d ; depth = %d", dirname, basename[*pdx], *pdx, depth);
        }
    }
    return found;
}

// Function to prune unreachable, aka orphaned, items from the stat cache.
// If a directory and its files and subdirectories disappears, they might
// remain as orphans in the stat cache. We want to prune them.
void stat_cache_prune(stat_cache_t *cache) {
    // leveldb stuff
    leveldb_readoptions_t *roptions;
    leveldb_writeoptions_t *woptions;
    struct leveldb_iterator_t *iter;
    const char *iterkey;
    char *derivedkey = NULL;
    const struct stat_cache_value *itervalue;
    size_t klen;
    size_t vlen;
    int idx, jdx;

    char *errptr = NULL;
    int depth;
    int prev_depth = 0;
    // from the end of the iterkey we pick of dirname/filename, and store them here
    char dirname[PATH_MAX] = "";
    char filename[PATH_MAX] = "";
    // For traversing the iterkey
    const char *slash = NULL;
    int len;
    // Iterating through one depth, basename0 will contain the directories
    // from iterating the previous depth, and we populate basename1 with the
    // directories at this depth, for use on iterating the next depth.
    // When we switch depths, we swap these two. We use pbasename (p for previous)
    // and nbasename (n for next) to keep track of what each one represents.
    char **basename[2];
    // phase tells us whether basename[0] is p and basename[1] is n, or vice-versa
    // When phase is 0, basename[0] is p or previous
    // Since we change phase the first time, start with 1, so it will be 0 for the first time
    int phase = 1;
    // The keys are sorted alphabetically, so 10 comes before 6. We just make 2 passes through
    // the db, once processing only depths less than 10, then only depths greater than or
    // equal to 10. pass keeps track of which pass we are in.
    int pass = 0;
    // Since entries are in alphabetical order, during iteration of a given depth,
    // we don't need to start over with each new key, since it can't match items
    // which have already been seen, since they precede it in the alphabet. We use
    // pdx to keep track of which entry in pbasename we can start at when
    // searching for a directory when we get a new key
    int pdx = 0;
    // We use ndx to ensure we don't write more entries into nbasename than the array holds (MAX_DIRS)
    int ndx = 0;
    // Skip standard treatment on some entries, the first one, and updated_children which hit ldb
    bool skip = true;
    int max_dirs = MAX_DIRS;
    int tphase;
    int deleted_entries = 0;
    int visited_entries = 0;

    log_print(LOG_DEBUG, "stat_cache_prune(cache %p)", cache);

    for (idx = 0; idx < 2; idx++) {
        basename[idx] = calloc(MAX_DIRS, sizeof(char *));
        for (jdx = 0; jdx < MAX_DIRS; jdx++) {
            basename[idx][jdx] = calloc(1, PATH_MAX);
        }
    }

    roptions = leveldb_readoptions_create();
    iter = leveldb_create_iterator(cache, roptions);
    leveldb_readoptions_destroy(roptions);

    // Entries are in alphabetical order, so 10 is before 6;
    // on the first pass, find the first depth less than 10, and process to the end;
    // on the second pass, process depth greater than 10
    for (pass = 0; pass < PHASES; pass++) {
        log_print(LOG_DEBUG, "stat_cache_prune: Changing pass:%d", pass);
        leveldb_iter_seek_to_first(iter);

        while (leveldb_iter_valid(iter)) {
            iterkey = leveldb_iter_key(iter, &klen);
            itervalue = (const struct stat_cache_value *) leveldb_iter_value(iter, &vlen);
            log_print(LOG_DEBUG, "stat_cache_prune: ITERKEY: \'%s\')", iterkey);
            ++visited_entries;

            // We control what kinds of entries are in the leveldb db.
            // Those beginning with a number are stat cache entries and
            // will be alphabetically first. As soon as we find an entry that
            // strtol cannot turn into a number, we know we have passed beyond
            // the normal stat cache entries into something else (e.g. filecache).
            // However, we also have to handle "updated_children" entries. We
            // handle them separately below.
            errno = 0;
            depth = strtol(iterkey, NULL, 10);
            log_print(LOG_DEBUG, "stat_cache_prune: Got depth:%d, %d", depth, errno);

            // @TODO seems not to set errno on returning 0
            if (depth == 0 /*&& errno != 0*/) {
                log_print(LOG_DEBUG, "stat_cache_prune: break:%d, %d", depth, errno);
                break;
            }

            if (depth != 0 && ((pass == 0 && depth < 10) || (pass == 1 && depth >= 10))) {
                if (depth > prev_depth) {
                    if (phase) phase = 0;
                    else phase = 1;
                    pdx = 0;
                    ndx = 0;
                    log_print(LOG_DEBUG, "stat_cache_prune: Changing depth:%d, %d", depth, prev_depth, phase);
                    prev_depth = depth;
                    // null-out next phase
                    tphase = phase ? 0 : 1;
                    basename[tphase][0][0] = '\0';
                    basename[tphase][1][0] = '\0';
                }
                slash = iterkey + strlen(iterkey);
                while (slash[0] != '/') --slash;
                strncpy(filename, slash + 1, PATH_MAX);
                len = 0;
                --slash;
                while (slash[0] != '/') --slash, ++len;
                strncpy(dirname, slash + 1, len);
                dirname[len] = '\0';

                log_print(LOG_DEBUG, "stat_cache_prune: calling check_for_dir_match: %s %s %d %d  :: %s", dirname, basename[phase][pdx], pdx, depth, filename);
                if (skip || check_for_dir_match(dirname, basename[phase], &pdx, depth)) {
                    skip = false;
                    log_print(LOG_DEBUG, "stat_cache_prune: keeping %s", iterkey);
                    if (S_ISDIR(itervalue->st.st_mode)) {
                        log_print(LOG_DEBUG, "stat_cache_prune: new file is dir: %s", filename);
                        // If we're about to run off the end of the array, double the size
                        if (ndx >= (max_dirs - 1)) {
                            log_print(LOG_WARNING, "stat_cache_prune: exceeded max_dirs (%d): %s", ndx, filename);
                            for (idx = 0; idx < PHASES; idx++) {
                                basename[idx] = realloc(basename[idx], max_dirs * PHASES * sizeof(char *));
                                for (jdx = max_dirs; jdx < max_dirs * PHASES; jdx++) {
                                    basename[idx][jdx] = calloc(1, PATH_MAX);
                                }
                            }
                            max_dirs *= 2;
                        }
                        // We use phase for the previous; since this is the "next", use the opposite of phase
                        tphase = phase ? 0 : 1;
                        strncpy(basename[tphase][ndx], filename, PATH_MAX);
                        log_print(LOG_DEBUG, "stat_cache_prune: added filename %s to nbasename[%d] at %d", filename, tphase, ndx);
                        // Set next to empty string; use this elsewhere as sentinel to stop iterating
                        basename[tphase][ndx + 1][0] = '\0';
                        ++ndx;
                    }
                    else {
                        log_print(LOG_DEBUG, "stat_cache_prune: filename %s is NOT dir", filename);
                    }
                }
                else {
                    // delete this item
                    log_print(LOG_DEBUG, "stat_cache_prune: deleting %s", iterkey);
                    ++deleted_entries;
                    woptions = leveldb_writeoptions_create();
                    leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
                    leveldb_writeoptions_destroy(woptions);
                    if (errptr != NULL) {
                        log_print(LOG_ERR, "leveldb_delete error: %s", errptr);
                        free(errptr);
                    }
                    else {
                        // JB DEBUG code
                        struct stat_cache_value *value;
                        value = stat_cache_value_get(cache, key2path(iterkey), true);
                        if (value) {
                            log_print(LOG_DEBUG, "stat_cache_prune: still there after delete: %s", iterkey);
                            free(value);
                        }
                        else {
                            log_print(LOG_DEBUG, "stat_cache_prune: no longer there after delete: %s", iterkey);
                        }
                    }
                }
            }
            leveldb_iter_next(iter);
        }
    }
    leveldb_iter_destroy(iter);

    for (idx = 0; idx < PHASES; idx++) {
        for (jdx=0; jdx < MAX_DIRS; jdx++) {
            free(basename[idx][jdx]);
        }
        free(basename[idx]);
    }

    // Handle updated_children entries
    roptions = leveldb_readoptions_create();
    iter = leveldb_create_iterator(cache, roptions);
    leveldb_readoptions_destroy(roptions);
    leveldb_iter_seek(iter, "updated_children:", 17);

    while (leveldb_iter_valid(iter)) {
        struct stat_cache_value *value;
        iterkey = leveldb_iter_key(iter, &klen);
        derivedkey = updated_children2canonicalkey(iterkey);
        value = stat_cache_value_get(cache, key2path(derivedkey), true);
        // We handle all updated_children here, but set skip to cause correct iteration
        if (value) {
            log_print(LOG_DEBUG, "stat_cache_prune: keeping: derivedkey %s (%s)", derivedkey, iterkey);
            free(value);
        }
        else {
            log_print(LOG_DEBUG, "stat_cache_prune: deleting: derivedkey %s (%s)", derivedkey, iterkey);
            ++deleted_entries;
            woptions = leveldb_writeoptions_create();
            leveldb_delete(cache, woptions, iterkey, strlen(iterkey) + 1, &errptr);
            leveldb_writeoptions_destroy(woptions);
            if (errptr != NULL) {
                log_print(LOG_ERR, "leveldb_delete error: %s", errptr);
                free(errptr);
            }
        }
        free(derivedkey);
        leveldb_iter_next(iter);
    }
    leveldb_iter_destroy(iter);
    log_print(LOG_INFO, "stat_cache_prune: visited %d cache entries; deleted %d", visited_entries, deleted_entries);
}

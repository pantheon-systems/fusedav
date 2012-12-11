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

#include "ldb-filecache.h"
#include "filecache.h"
#include "fusedav.h"
#include "log.h"

#include <ne_uri.h>

struct ldb_filecache_entry {
    const char *key;
    const struct ldb_filecache_persistent_value *value;
};

static char *path2key(const char *path);
static const char *key2path(const char *key);
static int ldb_filecache_delete(ldb_filecache_t *cache, const char *path);
static int ldb_filecache_close(struct ldb_filecache_sdata *sdata);
// static int range_to_file (struct ldb_filecache_value *value, const char *path, ne_off_t l);
static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path);
static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, struct ldb_filecache_pdata *pdata);

/*
int ldb_filecache_opencache(ldb_filecache_t **c, char *storage_path) {
#ifdef HAVE_LIBLEVELDB
    char *error = NULL;
    leveldb_cache_t *ldb_cache;
    leveldb_options_t *options;

    // Check that a directory is set.
    if (!storage_path) {
        // @TODO: Use a mkdtemp-based path.
        log_print(LOG_WARNING, "No cache path specified.");
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
        log_print(LOG_ERR, "ERROR opening db: %s", error);
        return -1;
    }
#endif
    return 0;
}

int ldb_filecache_closecache(ldb_filecache_t *c) {
#ifdef HAVE_LIBLEVELDB
    if (c != NULL)
        leveldb_close(c);
#endif
    return 0;
}
*/

int ldb_filecache_open(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    char tempfile[PATH_MAX];
    ne_request *req = NULL;
    ne_session *session;
    struct ldb_filecache_pdata *pdata;
    struct ldb_filecache_sdata *sdata;
    int ret = -1;
    int flags = info->flags;

    if (!(session = session_get(1))) {
        errno = EIO;
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_open:Failed to get session");
        goto fail;
    }

    info->fh = (struct ldb_filecache_sdata *)malloc(sizeof(struct ldb_filecache_sdata));
    sdata = info->fh;

    if (sdata == NULL) {
        log_print(LOG_ERR, "ldb_filecache_open:Failed to malloc sdata");
        goto fail;
    }

    if (debug) {
        log_print(LOG_DEBUG, "ldb_filecache_open: sdata=%p :: %p", sdata, info->fh);
    }
    // If we already have the file, return success
    if ((pdata = ldb_filecache_pdata_get(cache, path))) {
        if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
        if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;
        return 0;
    }

    // Get a new cache entry here!
    pdata = (struct ldb_filecache_pdata *) malloc(sizeof(struct ldb_filecache_pdata));
    if (!pdata) {
        log_print(LOG_ERR, "ldb_filecache_open:Failed to malloc pdata");
        goto fail;
    }

    sdata->fd = -1;

    snprintf(tempfile, sizeof(tempfile), "%s/fusedav-cache-XXXXXX", "/tmp");
    if ((sdata->fd = mkstemp(tempfile)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_open:Failed mkstemp");
        goto fail;
    }

    strncpy(pdata->filename, tempfile, PATH_MAX);

    req = ne_request_create(session, "HEAD", path);
    if (!req) {
        log_print(LOG_ERR, "ldb_filecache_open:Failed ne_request_create");
        goto fail;
    }

    if (ne_request_dispatch(req) != NE_OK) {
        log_print(LOG_ERR, "HEAD failed: %s", ne_get_error(session));
        errno = ENOENT;
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_open:Failed ne_request_dispatch");
        goto fail;
    }

    // MUST TODO! Get file here through something like range_to_file

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    ret = ldb_filecache_pdata_set(cache, path, pdata);

    if (ret) {
        log_print(LOG_ERR, "ldb_filecache_open:Failed ldb_filecache_pdata_set");
        goto fail;
    }

    return 0;

fail:

    if (pdata) ldb_filecache_close(sdata);

    return ret;
}

int ldb_filecache_read(struct fuse_file_info *info, char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    // TODO How do we check that we got a legitimate info->fh?

    if ((ret = pread(sdata->fd, buf, size, offset)) < 0) {
        goto finish;
    }

    ret = 0;

finish:

    return ret;
}

static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path) {
    struct ldb_filecache_pdata *pdata = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;

    key = path2key(path);

    options = leveldb_readoptions_create();
    pdata = (struct ldb_filecache_pdata *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &errptr);
    leveldb_readoptions_destroy(options);
    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_get error: %s", errptr);
        free(errptr);
        return NULL;
    }

    if (!pdata) {
        if (debug)
            log_print(LOG_DEBUG, "ldb_filecache_pdata_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct ldb_filecache_pdata)) {
        log_print(LOG_ERR, "Length %lu is not expected length %lu.", vallen, sizeof(struct ldb_filecache_pdata));
    }

    return pdata;
}


int ldb_filecache_write(struct fuse_file_info *info, const char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    if (!sdata->writable) {
        errno = EBADF;
        ret = 0;
        goto finish;
    }

    if ((ret = pwrite(sdata->fd, buf, size, offset)) < 0)
        goto finish;

    sdata->modified = true;

    ret = 0;

finish:

    return ret;
}

static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, struct ldb_filecache_pdata *pdata) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;
    int r = 0;

    assert(pdata);

    key = path2key(path);

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) pdata, sizeof(struct ldb_filecache_pdata), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_set error: %s", errptr);
        free(errptr);
        r = -1;
    }

    return r;
}

int ldb_filecache_truncate(struct fuse_file_info *info, ne_off_t s) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    ret = ftruncate(sdata->fd, s);

    return ret;
}

int ldb_filecache_unref(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    if (debug) {
        log_print(LOG_DEBUG, "ldb_filecache_unref: before ldb_filecache_sync");
    }

    ret = ldb_filecache_sync(cache, path, info);
    if (debug) {
        log_print(LOG_DEBUG, "ldb_filecache_unref: after ldb_filecache_unref");
    }

    if (ret < 0) {
        log_print(LOG_ERR, "ldb_filecache_unref: return from ldb_filecache_sync: %d", ret);
        goto finish;
    }

    ldb_filecache_close(sdata);

    ret = 0;

finish:

    return ret;
}

int ldb_filecache_sync(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;
    ne_session *session;

    if (debug) {
        log_print(LOG_DEBUG, "ldb_filecache_sync: entered; sdata = %p", sdata);
    }

    if (!sdata->writable) {
        errno = EBADF;
        ret = 0;
        if (debug) {
            log_print(LOG_ERR, "ldb_filecache_sync: not writable");
        }
        goto finish;
    }

    if (!sdata->modified) {
        ret = 0;
        if (debug) {
            log_print(LOG_DEBUG, "ldb_filecache_sync: not modified");
        }
        goto finish;
    }

    if (lseek(sdata->fd, 0, SEEK_SET) == (ne_off_t)-1) {
        if (debug) {
            log_print(LOG_ERR, "ldb_filecache_sync: failed lseek");
        }
        goto finish;
    }

    if (!(session = session_get(1))) {
        errno = EIO;
        if (debug) {
            log_print(LOG_ERR, "ldb_filecache_sync: failed session");
        }
        goto finish;
    }

    if (ne_put(session, path, sdata->fd)) {
        log_print(LOG_ERR, "PUT failed: %s", ne_get_error(session));
        errno = ENOENT;
        goto finish;
    }

    if (debug) {
        log_print(LOG_ERR, "ldb_filecache_sync: about to call stat_cache stuff");
    }

    // Is this correct? If not modified or not writable, we don't call these.
    // Should these be in unref instead?
    stat_cache_delete(cache, path);
    stat_cache_delete_parent(cache, path);

    if (debug) {
        log_print(LOG_ERR, "ldb_filecache_sync: about to exit");
    }
    ret = 0;

finish:

    return ret;
}

/*
static int range_to_file (struct ldb_filecache_value *value, const char *path, ne_off_t l) {
    int ret = -1;
    ne_content_range range;
    ne_session *session;

    if (value == NULL) {
        goto finish;
    }

    if (!(session = session_get(1))) {
        errno = EIO;
        goto finish;
    }

    if (l > value->server_length)
        l = value->server_length;

    if (l <= value->present) {
        ret = 0;
        goto finish;
    }

    if (lseek(value->fd, value->present, SEEK_SET) != value->present) {
        goto finish;
    }

    range.start = value->present;
    range.end = l - 1;
    range.total = 0;

    if (ne_get_range(session, path, &range, value->fd) != NE_OK) {
        log_print(LOG_ERR, "GET failed: %s", ne_get_error(session));
        errno = ENOENT;
        goto finish;
    }

    value->present = l;

    ret = 0;
finish:

    return ret;
}
*/

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;
    asprintf(&key, "%s%s", "fc:", path);
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

// Not Used.
static int ldb_filecache_delete(ldb_filecache_t *cache, const char *path) {
    leveldb_writeoptions_t *options;
    char *key;
    int r = 0;
    char *errptr = NULL;

    key = path2key(path);
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

static int ldb_filecache_close(struct ldb_filecache_sdata *sdata) {

    if (sdata->fd >= 0)
        close(sdata->fd);

    return 0;
}

#define DEBUG 0
#if DEBUG
// Used opaquely outside this library.
struct ldb_filecache_iterator {
    leveldb_iterator_t *ldb_iter;
    char *key_prefix;
    size_t key_prefix_len;
};

static void ldb_filecache_iterator_free(struct ldb_filecache_iterator *iter) {
    free(iter->key_prefix);
    free(iter);
}

static struct ldb_filecache_iterator *ldb_filecache_iter_init(ldb_filecache_t *cache, const char *path_prefix) {
    struct ldb_filecache_iterator *iter = NULL;
    leveldb_readoptions_t *options;

    iter = malloc(sizeof(struct ldb_filecache_iterator));
    iter->key_prefix = path2key(path_prefix); // Handles allocating the duplicate.
    iter->key_prefix_len = strlen(iter->key_prefix) + 1;

    //log_print(LOG_DEBUG, "creating leveldb iterator for prefix %s", iter->key_prefix);
    options = leveldb_readoptions_create();
    iter->ldb_iter = leveldb_create_iterator(cache, options);
    leveldb_readoptions_destroy(options);

    //log_print(LOG_DEBUG, "checking iterator validity");

    //if (!leveldb_iter_valid(iter->ldb_iter)) {
    //    log_print(LOG_ERR, "Initial LevelDB iterator is not valid.");
    //    return NULL;
    //}

    //log_print(LOG_DEBUG, "seeking");
    leveldb_iter_seek(iter->ldb_iter, iter->key_prefix, iter->key_prefix_len);

    return iter;
}

static struct ldb_filecache_entry *ldb_filecache_iter_current(struct ldb_filecache_iterator *iter) {
    struct ldb_filecache_entry *entry;
    const struct ldb_filecache_value *value;
    const char *key;
    size_t klen, vlen;

    assert(iter);

    //log_print(LOG_DEBUG, "checking iterator validity");

    // If we've gone beyond the end of the dataset, quit.
    if (!leveldb_iter_valid(iter->ldb_iter)) {
        leveldb_iter_destroy(iter->ldb_iter);
        return false;
    }

    //log_print(LOG_DEBUG, "fetching the key");

    key = leveldb_iter_key(iter->ldb_iter, &klen);
    //log_print(LOG_DEBUG, "fetched key: %s", key);

    //log_print(LOG_DEBUG, "fetched the key");

    // If we've gone beyond the end of the prefix range, quit.
    // Use (iter->key_prefix_len - 1) to exclude the NULL at the prefix end.
    if (strncmp(key, iter->key_prefix, iter->key_prefix_len - 1) != 0) {
        //log_print(LOG_DEBUG, "Key %s does not match prefix %s for %lu characters. Ending iteration.", key, iter->key_prefix, iter->key_prefix_len);
        leveldb_iter_destroy(iter->ldb_iter);
        return NULL;
    }

    //log_print(LOG_DEBUG, "fetching the value");

    value = (const struct ldb_filecache_value *) leveldb_iter_value(iter->ldb_iter, &vlen);

    entry = malloc(sizeof(struct ldb_filecache_entry));
    entry->key = key;
    entry->value = value;
    return entry;
}

static void ldb_filecache_iter_next(struct ldb_filecache_iterator *iter) {
    leveldb_iter_next(iter->ldb_iter);
}

/*
static void ldb_filecache_list_all(ldb_filecache_t *cache, const char *path) {
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *options;
    const struct ldb_filecache_value *itervalue;
    struct ldb_filecache_value *value;
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

        itervalue = (const struct ldb_filecache_value *) leveldb_iter_value(iter, &vlen);
        if (S_ISDIR(itervalue->st.st_mode)) {
            iterkey = leveldb_iter_key(iter, &klen);
            log_print(LOG_DEBUG, "Listing directory: %s", iterkey);

            value = ldb_filecache_value_get(cache, key2path(iterkey));
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

static int ldb_filecache_enumerate(ldb_filecache_t *cache, const char *path_prefix, void (*f) (const char *path, const char *child_path, void *user), void *user, __unused bool force) {
    struct ldb_filecache_iterator *iter;
    struct ldb_filecache_entry *entry;
    unsigned found_entries = 0;
    //time_t timestamp;
    //time_t current_time;

    //if (debug)
    //    log_print(LOG_DEBUG, "ldb_filecache_enumerate(%s)", path_prefix);

    //ldb_filecache_list_all(cache, path_prefix);

    iter = ldb_filecache_iter_init(cache, path_prefix);
    //log_print(LOG_DEBUG, "iterator initialized with prefix: %s", iter->key_prefix);

    while ((entry = ldb_filecache_iter_current(iter))) {
        //log_print(LOG_DEBUG, "key: %s", entry->key);
        //log_print(LOG_DEBUG, "fn: %s", entry->key + iter->key_prefix_len);
        f(path_prefix, entry->key + iter->key_prefix_len, user);
        ++found_entries;
        free(entry);
        ldb_filecache_iter_next(iter);
    }
    ldb_filecache_iterator_free(iter);
    //log_print(LOG_DEBUG, "Done iterating: %u items.", found_entries);

    // Ignore the entry that exactly matches the key prefix.
    // @TODO: Remove this?
    if (found_entries == 0)
        return -STAT_CACHE_NO_DATA;

    return 0;
}
#endif

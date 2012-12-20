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
#include "statcache.h"
#include "fusedav.h"
#include "log.h"

#include <ne_uri.h>

#define REFRESH_INTERVAL 3

typedef int fd_t;

// Session data
struct ldb_filecache_sdata {
    fd_t fd;
    char filename[PATH_MAX]; // Only used for new replacement files.
    bool readable;
    bool writable;
    bool modified;
};

// @TODO Where to find ETAG_MAX?
#define ETAG_MAX 256

// Persistent data stored in leveldb
struct ldb_filecache_pdata {
    char filename[PATH_MAX];
    char etag[ETAG_MAX + 1];
    time_t last_server_update;
};

static int new_cache_file(const char *cache_path, char *cache_file_path, fd_t *fd) {

    log_print(LOG_DEBUG, "enter: new_cache_file(%s,%s,)", cache_path, cache_file_path);

    snprintf(cache_file_path, PATH_MAX, "%s/files/fusedav-cache-XXXXXX", cache_path);
    log_print(LOG_DEBUG, "Using pattern %s", cache_file_path);
    if ((*fd = mkstemp(cache_file_path)) < 0) {
        log_print(LOG_ERR, "new_cache_file: Failed mkstemp");
        return -1;
    }

    log_print(LOG_DEBUG, "new_cache_file: mkstemp fd=%d :: %s", *fd, cache_file_path);
    return 0;
}

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;

    log_print(LOG_DEBUG, "enter: path2key(%s)", path);

    asprintf(&key, "fc:%s", path);
    return key;
}

static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path) {
    struct ldb_filecache_pdata *pdata = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;

    log_print(LOG_DEBUG, "enter:ldb_filecache_pdata_get(,%s)", path);

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
        log_print(LOG_DEBUG, "ldb_filecache_pdata_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct ldb_filecache_pdata)) {
        log_print(LOG_ERR, "Length %lu is not expected length %lu.", vallen, sizeof(struct ldb_filecache_pdata));
    }

    return pdata;
}

static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, const struct ldb_filecache_pdata *pdata) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;
    int ret = -1;

    log_print(LOG_DEBUG, "enter: ldb_filecache_pdata_set(,%s,)", path);

    if (!pdata) {
        log_print(LOG_ERR, "ldb_filecache_pdata_set NULL pdata");
        goto finish;
    }

    key = path2key(path);

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (const char *) pdata, sizeof(struct ldb_filecache_pdata), &errptr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_set error: %s", errptr);
        free(errptr);
        goto finish;
    }

    ret = 0;

finish:

    return ret;
}

// Get a file descriptor pointing to the latest full copy of the file.
static fd_t ldb_get_fresh_fd(ne_session *session, ldb_filecache_t *cache, const char *cache_path, const char *path, int flags) {
    struct ldb_filecache_pdata *pdata;
    fd_t ret_fd = -1;
    int code;
    ne_request *req = NULL;
    int ne_ret;

    log_print(LOG_DEBUG, "enter: ldb_get_fresh_fd(,,%s,%s", cache_path, path);

    pdata = ldb_filecache_pdata_get(cache, path);

    // Grab the rd/wr flags from the flags variable and or in O_APPEND
    flags = (flags & O_RDONLY) | (flags & O_WRONLY) | (flags & O_RDWR) | O_APPEND;

    if (pdata != NULL)
        log_print(LOG_DEBUG, "ldb_get_fresh_fd: file found in cache: %s::%s", path, pdata->filename);

    // If we have a cache entry and it is still fresh, we can just proceed after getting a new fd
    if (pdata != NULL && (time(NULL) - pdata->last_server_update) <= REFRESH_INTERVAL) {
        ret_fd = open(pdata->filename, flags);
        goto finish;
    }

    req = ne_request_create(session, "GET", path);
    if (!req) {
        log_print(LOG_ERR, "ldb_get_fresh_fd: Failed ne_request_create on GET");
        goto finish;
    }

    // If we have stale cache data, set a header to aim for a 304.
    if (pdata)
        ne_add_request_header(req, "If-None-Match", pdata->etag);

    do {
        ne_ret = ne_begin_request(req);
        if (ne_ret != NE_OK) {
            goto finish;
        }

        code = ne_get_status(req)->code;
        if (code == 304) {
            log_print(LOG_DEBUG, "Got 304 on %s", path);

            // Gobble up any remaining data in the response.
            ne_discard_response(req);

            // Mark the cache item as revalidated at the current time.
            pdata->last_server_update = time(NULL);
            ldb_filecache_pdata_set(cache, path, pdata);

            ret_fd = open(pdata->filename, flags);
            goto finish;
        }
        else if (code == 200) {
            // Archive the old temp file path for unlinking after replacement.
            char old_filename[PATH_MAX];
            bool unlink_old = false;
            const char *etag = NULL;

            if (pdata == NULL) {
                pdata = calloc(1, sizeof(struct ldb_filecache_pdata));

                // Fill in ETag.
                etag = ne_get_response_header(req, "ETag");
                log_print(LOG_DEBUG, "Got ETag: %s", etag);
                strncpy(pdata->etag, etag, ETAG_MAX);
            }
            else {
                strncpy(old_filename, pdata->filename, PATH_MAX);
                unlink_old = true;
            }

            // Create a new temp file and read the file content into it.
            new_cache_file(cache_path, pdata->filename, &ret_fd);
            ne_read_response_to_fd(req, ret_fd);

            // Point the persistent cache to the new file content.
            pdata->last_server_update = time(NULL);
            ldb_filecache_pdata_set(cache, path, pdata);

            // Unlink the old cache file, which the persistent cache
            // no longer references. This will cause the file to be
            // deleted once no more file descriptors reference it.
            if (unlink_old)
                unlink(old_filename);
            goto finish;
        }

        ne_ret = ne_end_request(req);
    } while (ne_ret == NE_RETRY);

    finish:
        if (req != NULL)
            ne_request_destroy(req);
        if (pdata != NULL)
            free(pdata);
        return ret_fd;
}

int ldb_filecache_open(char *cache_path, ldb_filecache_t *cache, const char *path, struct fuse_file_info *info, bool replace) {
    ne_session *session;
    struct ldb_filecache_sdata *sdata;
    int ret = -1;
    int flags = info->flags;
    struct stat_cache_value value;

    log_print(LOG_DEBUG, "enter: ldb_filecache_open(%s,,%s,,%d", cache_path, path, replace);

    if (!(session = session_get(1))) {
        ret = -EIO;
        log_print(LOG_ERR, "ldb_filecache_open: Failed to get session");
        goto fail;
    }

    // Allocate and zero-out a session data structure.
    sdata = calloc(1, sizeof(struct ldb_filecache_sdata));
    if (sdata == NULL) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed to calloc sdata");
        goto fail;
    }

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    if (replace) {
        // Create a new file to write into.
        sdata->modified = true;
        if (new_cache_file(cache_path, sdata->filename, &sdata->fd) < 0) {
            goto fail;
        }

        value.st.st_mode = 0660 | S_IFREG;
        value.st.st_nlink = 1;
        value.st.st_size = 0;
        value.st.st_atime = time(NULL);
        value.st.st_mtime = value.st.st_atime;
        value.st.st_ctime = value.st.st_mtime;
        value.st.st_blksize = 0;
        value.st.st_blocks = 8;
        value.st.st_uid = getuid();
        value.st.st_gid = getgid();
        value.prepopulated = false;
        stat_cache_value_set(cache, path, &value);
        log_print(LOG_DEBUG, "Updated stat cache on open.");
    }
    else {
        // Get a file descriptor pointing to a guaranteed-fresh file.
        sdata->fd = ldb_get_fresh_fd(session, cache, cache_path, path, flags);
    }

    if (sdata->fd > 0) {
        log_print(LOG_DEBUG, "Setting fh to session data structure with fd %d.", sdata->fd);
        info->fh = (uint64_t) sdata;
        ret = 0;
        goto finish;
    }

fail:
    log_print(LOG_ERR, "No valid fd set for path %s. Setting fh structure to NULL.", path);
    info->fh = (uint64_t) NULL;

    if (sdata != NULL)
        free(sdata);

finish:
    return ret;
}


static int ldb_filecache_close(struct ldb_filecache_sdata *sdata) {

    log_print(LOG_DEBUG, "enter: ldb_filecache_close(,)");

    if (sdata->fd >= 0)
        close(sdata->fd);

    return 0;
}

#ifdef NE_LFS
#define ne_fstat fstat64
typedef struct stat64 struct_stat;
#else
#define ne_fstat fstat
typedef struct stat struct_stat;
#endif
/* PUT's from fd to URI */
static int ne_put_return_etag(ne_session *session, const char *path, int fd, char *etag)
{
    ne_request *req;
    struct stat st;
    int ret;
    const char *value;

    log_print(LOG_DEBUG, "enter: ne_put_return_etag(,%s,,)", path);

    if (ne_fstat(fd, &st)) {
        int errnum = errno;
        char buf[200];
        char msg[256];
        char *error;

        error = ne_strerror(errnum, buf, sizeof buf);
        sprintf(msg, "Could not determine file size: %s", error);
        ne_set_error(session, msg);
        return NE_ERROR;
    }

    req = ne_request_create(session, "PUT", path);

#ifdef NE_HAVE_DAV
    ne_lock_using_resource(req, path, 0);
    ne_lock_using_parent(req, path);
#endif

    ne_set_request_body_fd(req, fd, 0, st.st_size);

    ret = ne_request_dispatch(req);

    if (ret == NE_OK && ne_get_status(req)->klass != 2) {
        ret = NE_ERROR;
    }

    // We continue to PUT the file if etag happens to be NULL; it just
    // means ultimately that it won't go into the filecache
    if (etag) {
        value = ne_get_response_header(req, "etag");
        strncpy(etag, value, ETAG_MAX);
        log_print(LOG_DEBUG, "PUT returns etag: %s", etag);
    }
    ne_request_destroy(req);

    return ret;
}

int ldb_filecache_sync(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;
    char *etag;
    struct ldb_filecache_pdata *pdata = NULL;
    ne_session *session;
    struct stat_cache_value value;

    assert(sdata);

    log_print(LOG_DEBUG, "enter: ldb_filecache_sync(,%s,)", path);

    if (!sdata->writable) {
        // errno = EBADF; why?
        ret = 0;
        log_print(LOG_DEBUG, "ldb_filecache_sync: not writable");
        goto finish;
    }

    if (!sdata->modified) {
        ret = 0;
        log_print(LOG_DEBUG, "ldb_filecache_sync: not modified");
        goto finish;
    }

    if (lseek(sdata->fd, 0, SEEK_SET) == (ne_off_t)-1) {
        log_print(LOG_ERR, "ldb_filecache_sync: failed lseek");
        ret = -1;
        goto finish;
    }

    if (!(session = session_get(1))) {
        errno = EIO;
        ret = -1;
        log_print(LOG_ERR, "ldb_filecache_sync: failed session");
        goto finish;
    }


    // Write this data to the persistent cache.
    // Update the file cache
    pdata = ldb_filecache_pdata_get(cache, path);
    if (pdata == NULL) {
        pdata = calloc(1, sizeof(struct ldb_filecache_pdata));
        if (pdata == NULL) {
            log_print(LOG_ERR, "calloc of pdata failed");
        }
        strncpy(pdata->filename, sdata->filename, PATH_MAX);
    }

    if (pdata) {
        etag = pdata->etag;
    }
    else {
        etag = NULL;
    }
    if (ne_put_return_etag(session, path, sdata->fd, etag)) {
        log_print(LOG_ERR, "PUT failed: %s", ne_get_error(session));
        errno = ENOENT;
        ret = -1;
        goto finish;
    }

    if (pdata) {
        // Point the persistent cache to the new file content.
        pdata->last_server_update = time(NULL);
        ldb_filecache_pdata_set(cache, path, pdata);
        log_print(LOG_DEBUG, "PUT: etag = %s", pdata->etag);
    }

    // Update stat cache.
    // @TODO: Use actual mode.
    value.st.st_mode = 0660 | S_IFREG;
    value.st.st_nlink = 1;
    value.st.st_size = lseek(sdata->fd, 0, SEEK_END);
    value.st.st_atime = time(NULL);
    value.st.st_mtime = value.st.st_atime;
    value.st.st_ctime = value.st.st_mtime;
    value.st.st_blksize = 0;
    value.st.st_blocks = 8;
    value.st.st_uid = getuid();
    value.st.st_gid = getgid();
    value.prepopulated = false;
    stat_cache_value_set(cache, path, &value);
    log_print(LOG_DEBUG, "Updated stat cache.");

    ret = 0;

finish:

    log_print(LOG_DEBUG, "Done syncing file.");

    return ret;
}

ssize_t ldb_filecache_read(struct fuse_file_info *info, char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

    log_print(LOG_DEBUG, "enter: ldb_filecache_read(,,,)");

    // ensure data is present and fresh
    // ETAG exchange
    //

    if ((ret = pread(sdata->fd, buf, size, offset)) < 0) {
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_read: error %d; %d %s %d %ld", ret, sdata->fd, buf, size, offset);
        goto finish;
    }

finish:

    // ret is bytes read, or error
    log_print(LOG_DEBUG, "Done reading.");

    return ret;
}

ssize_t ldb_filecache_write(struct fuse_file_info *info, const char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

    log_print(LOG_DEBUG, "enter: ldb_filecache_write(,,,)");

    if (!sdata->writable) {
        errno = EBADF;
        ret = 0;
        log_print(LOG_DEBUG, "ldb_filecache_write: not writable");
        goto finish;
    }

    if ((ret = pwrite(sdata->fd, buf, size, offset)) < 0) {
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_write: error %d %d %s::%d %d %ld", ret, errno, strerror(errno), sdata->fd, size, offset);
        goto finish;
    }

    sdata->modified = true;

finish:

    // ret is bytes written

    return ret;
}

int ldb_filecache_release(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    assert(sdata);

    log_print(LOG_DEBUG, "enter: ldb_filecache_release(,%s,)", path);

    if ((ret = ldb_filecache_sync(cache, path, info)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_unref: ldb_filecache_sync returns error %d", ret);
        goto finish;
    }

    ldb_filecache_close(sdata);

    ret = 0;

finish:

    log_print(LOG_DEBUG, "Done releasing file.");

    return ret;
}

int ldb_filecache_truncate(struct fuse_file_info *info, ne_off_t s) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    log_print(LOG_DEBUG, "enter: ldb_filecache_truncate(,,)");

    if ((ret = ftruncate(sdata->fd, s)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_truncate: error on ftruncate %d", ret);
    }

    return ret;
}

int ldb_filecache_delete(ldb_filecache_t *cache, const char *path) {
    leveldb_writeoptions_t *options;
    char *key;
    int ret = 0;
    char *errptr = NULL;

    log_print(LOG_DEBUG, "enter: ldb_filecache_delete(,%s)", path);

    key = path2key(path);
    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (errptr != NULL) {
        log_print(LOG_ERR, "leveldb_delete error: %s", errptr);
        free(errptr);
        ret = -1;
    }

    return ret;
}

int ldb_filecache_init(char *cache_path) {
    char path[PATH_MAX];

    log_print(LOG_DEBUG, "enter: ldb_filecache_init(%s)", cache_path);

    snprintf(path, PATH_MAX, "%s/files", cache_path);
    if (mkdir(path, 0770) == -1) {
        if (errno != EEXIST) {
            log_print(LOG_ERR, "Path %s could not be created.", path);
            return -1;
        }
    }
    return 0;
}


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
#include "fusedav.h"
#include "log.h"

#include <ne_uri.h>

#define REFRESH_INTERVAL 3

// Session data
struct ldb_filecache_sdata {
    int fd;
    bool readable;
    bool writable;
    bool modified;
};

// FIX ME Where to find ETAG_MAX?
#define ETAG_MAX 256

// Persistent data stored in leveldb
struct ldb_filecache_pdata {
    char filename[PATH_MAX];
    char etag[ETAG_MAX + 1];
    time_t last_server_update;
};

static char *path2key(const char *path);
static void generate_etag(char *dest, int fd);
static int ldb_filecache_close(struct ldb_filecache_sdata *sdata);
static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path);
static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, struct ldb_filecache_pdata *pdata);

int ldb_filecache_open(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    char tempfile[PATH_MAX];
    char *check_etag_path = NULL;
    ne_request *req = NULL;
    ne_session *session;
    struct ldb_filecache_pdata *pdata;
    struct ldb_filecache_sdata *sdata;
    int ret = -1;
    int flags = info->flags;

    if (!(session = session_get(1))) {
        errno = EIO;
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_open: Failed to get session");
        goto fail;
    }

    info->fh = malloc(sizeof(struct ldb_filecache_sdata));
    sdata = (struct ldb_filecache_sdata *) info->fh;

    if (sdata == NULL) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed to malloc sdata");
        goto fail;
    }

    // If we already have the file, get a new fd
    if ((pdata = ldb_filecache_pdata_get(cache, path))) {
        int newflags = 0;
        int fd;

        if (debug) {
            log_print(LOG_DEBUG, "ldb_filecache_open: file already in cache: %s::%s", path, pdata->filename);
        }
        strncpy(tempfile, pdata->filename, PATH_MAX);
        newflags = (flags & O_RDONLY) | (flags & O_WRONLY) | O_APPEND; // is APPEND correct?
        if ((fd = open(tempfile, newflags)) < 0) {
            log_print(LOG_DEBUG, "ldb_filecache_open: reopen fails (%d): %s:::%s", fd, path, tempfile);
            ret = fd;
            goto fail;
        } else {
            sdata->fd = fd;
            if (debug) {
                log_print(LOG_DEBUG, "ldb_filecache_open: reopen new fd=%d", fd);
            }
        }
    } else {

        // Get a new cache entry here!
        pdata = (struct ldb_filecache_pdata *) malloc(sizeof(struct ldb_filecache_pdata));
        if (!pdata) {
            log_print(LOG_ERR, "ldb_filecache_open: Failed to malloc pdata");
            goto fail;
        }

        pdata->last_server_update = time(NULL);
        // Initialize with the character '0' so we send all ETAG_MAX bytes
        memset(pdata->etag, '0', ETAG_MAX);
        pdata->last_server_update = 0;
        sdata->fd = -1;

        snprintf(tempfile, sizeof(tempfile), "%s/fusedav-cache-XXXXXX", "/tmp");
        if ((sdata->fd = mkstemp(tempfile)) < 0) {
            log_print(LOG_ERR, "ldb_filecache_open: Failed mkstemp");
            goto fail;
        }

        if (debug) {
            log_print(LOG_ERR, "ldb_filecache_open: mkstemp fd=%d :: %s", sdata->fd, tempfile);
        }

        strncpy(pdata->filename, tempfile, PATH_MAX);
    }

    req = ne_request_create(session, "HEAD", path);
    if (!req) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed ne_request_create");
        goto fail;
    }

    if (ne_request_dispatch(req) != NE_OK) {
        log_print(LOG_ERR, "HEAD failed: %s", ne_get_error(session));
        errno = ENOENT;
        ret = -errno;
        log_print(LOG_ERR, "ldb_filecache_open: Failed ne_request_dispatch");
        goto fail;
    }

    asprintf(&check_etag_path, "%s?If-None-Match=%s", path, pdata->etag);

    if ((time(NULL) - pdata->last_server_update) > REFRESH_INTERVAL) {
        // Get the file from the server into the tmp cache file
        if ((ne_get(session, check_etag_path, sdata->fd)) != NE_OK) {
            log_print(LOG_ERR, "GET failed: %s", ne_get_error(session));
            errno = ENOENT;
            ret = -errno;
            log_print(LOG_ERR, "ldb_filecache_open: Failed ne_get");
            goto fail;
        }
    }
    free(check_etag_path);

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    ret = ldb_filecache_pdata_set(cache, path, pdata);

    if (ret) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed ldb_filecache_pdata_set");
        goto fail;
    }

    return 0;

fail:

    if (pdata) ldb_filecache_close(sdata);
    if (check_etag_path) free(check_etag_path);

    return ret;
}

ssize_t ldb_filecache_read(struct fuse_file_info *info, char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

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

    return ret;
}

static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path) {
    struct ldb_filecache_pdata *pdata = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;

    if (debug) {
        log_print(LOG_DEBUG, "Entered ldb_filecache_pdata_get: path=%s", path);
    }

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


ssize_t ldb_filecache_write(struct fuse_file_info *info, const char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

    if (!sdata->writable) {
        errno = EBADF;
        ret = 0;
        if (debug) {
            log_print(LOG_DEBUG, "ldb_filecache_write: not writable");
        }
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

static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, struct ldb_filecache_pdata *pdata) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;
    int ret = -1;

    if (!pdata) {
        if (debug) {
            log_print(LOG_ERR, "ldb_filecache_pdata_set NULL pdata");
        }
        goto finish;
    }

    key = path2key(path);

    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (char *) pdata, sizeof(struct ldb_filecache_pdata), &errptr);
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

int ldb_filecache_truncate(struct fuse_file_info *info, ne_off_t s) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    if ((ret = ftruncate(sdata->fd, s)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_truncate: error on ftruncate %d", ret);
    }

    return ret;
}

int ldb_filecache_release(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    if ((ret = ldb_filecache_sync(cache, path, info)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_unref: ldb_filecache_sync returns error %d", ret);
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
    struct ldb_filecache_pdata *pdata = NULL;
    ne_session *session;

    if (!sdata->writable) {
        // errno = EBADF; why?
        ret = 0;
        if (debug) {
            log_print(LOG_DEBUG, "ldb_filecache_sync: not writable");
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

    pdata = ldb_filecache_pdata_get(cache, path);

    // JB FIXME replace ne_put with our own version which also returns the
    // ETAG information.
    pdata->last_server_update = time(NULL);
    // FIXME! Generate ETAG. Or rewrite ne_put to put file, and get etag back
    generate_etag(pdata->etag, sdata->fd);

    if (ne_put(session, path, sdata->fd)) {
        log_print(LOG_ERR, "PUT failed: %s", ne_get_error(session));
        errno = ENOENT;
        ret = -1;
        goto finish;
    }

    ret = 0;

finish:

    return ret;
}

int ldb_filecache_delete(ldb_filecache_t *cache, const char *path) {
    leveldb_writeoptions_t *options;
    char *key;
    int ret = 0;
    char *errptr = NULL;

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

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;
    asprintf(&key, "%s%s", "fc:", path);
    return key;
}

static int ldb_filecache_close(struct ldb_filecache_sdata *sdata) {

    if (sdata->fd >= 0)
        close(sdata->fd);

    return 0;
}

static void generate_etag(char *dest, int fd) {
    memset(dest, '0', ETAG_MAX);
}


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
#include <sys/file.h>

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

// FIX ME Where to find ETAG_MAX?
#define ETAG_MAX 256

// Persistent data stored in leveldb
struct ldb_filecache_pdata {
    char filename[PATH_MAX];
    char etag[ETAG_MAX + 1];
    time_t last_server_update;
};

int ldb_filecache_init(char *cache_path) {
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "%s/files", cache_path);
    if (mkdir(cache_path, 0770) == -1) {
        if (errno != EEXIST) {
            log_print(LOG_ERR, "Cache Path %s could not be created.", cache_path);
            return -1;
        }
    }
    if (mkdir(path, 0770) == -1) {
        if (errno != EEXIST) {
            log_print(LOG_ERR, "Path %s could not be created.", path);
            return -1;
        }
    }
    return 0;
}

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;
    asprintf(&key, "fc:%s", path);
    return key;
}

// creates a new cache file
static int new_cache_file(const char *cache_path, char *cache_file_path, fd_t *fd) {
    snprintf(cache_file_path, PATH_MAX, "%s/files/fusedav-cache-XXXXXX", cache_path);
    log_print(LOG_DEBUG, "Using pattern %s", cache_file_path);
    if ((*fd = mkstemp(cache_file_path)) < 0) {
        log_print(LOG_ERR, "new_cache_file: Failed mkstemp");
        return -1;
    }

    log_print(LOG_DEBUG, "new_cache_file: mkstemp fd=%d :: %s", *fd, cache_file_path);
    return 0;
}

// adds an entry to the ldb cache
static int ldb_filecache_pdata_set(ldb_filecache_t *cache, const char *path, const struct ldb_filecache_pdata *pdata) {
    leveldb_writeoptions_t *options;
    char *errptr = NULL;
    char *key;
    int ret = -1;

    if (!pdata) {
        log_print(LOG_ERR, "ldb_filecache_pdata_set NULL pdata");
        goto finish;
    }

    log_print(LOG_INFO, "ldb_filecache_pdata_set: path=%s ; cachefile=%s", path, pdata->filename);

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

// Create a new file to write into and set values
static int create_file(struct ldb_filecache_sdata *sdata, const char *cache_path,
        ldb_filecache_t *cache, const char *path) {

    struct stat_cache_value value;
    struct ldb_filecache_pdata *pdata;

    log_print(LOG_DEBUG, "create_file: on %s", path);
    sdata->modified = true;
    sdata->writable = true;
    if (new_cache_file(cache_path, sdata->filename, &sdata->fd) < 0) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed on new_cache_file");
        return -1;
    }

    // Prepopulate stat cache.
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
    log_print(LOG_INFO, "create_file: Updated stat cache for %d : %s : %s.", sdata->fd, path, sdata->filename);

    // Prepopulate filecache.
    pdata = malloc(sizeof(struct ldb_filecache_pdata));
    if (pdata == NULL) {
        log_print(LOG_ERR, "create_file: malloc returns NULL for pdata");
        return -1;
    }
    memset(pdata, 0, sizeof(struct ldb_filecache_pdata));
    strncpy(pdata->filename, sdata->filename, sizeof(pdata->filename));
    pdata->last_server_update = time(NULL);
    log_print(LOG_INFO, "create_file: Updating file cache for %d : %s : %s : %s.", sdata->fd, path, sdata->filename, pdata->filename);
    ldb_filecache_pdata_set(cache, path, pdata);
    free(pdata);

    return 0;
}

// get an entry from the ldb cache
static struct ldb_filecache_pdata *ldb_filecache_pdata_get(ldb_filecache_t *cache, const char *path) {
    struct ldb_filecache_pdata *pdata = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *errptr = NULL;

    log_print(LOG_DEBUG, "Entered ldb_filecache_pdata_get: path=%s", path);

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

    log_print(LOG_DEBUG, "Returning from ldb_filecache_pdata_get: path=%s :: cachefile=%s", path, pdata->filename);

    return pdata;
}

// Get a file descriptor pointing to the latest full copy of the file.
static fd_t ldb_get_fresh_fd(ne_session *session, ldb_filecache_t *cache,
        const char *cache_path, const char *path, int flags) {
    struct ldb_filecache_pdata *pdata;
    bool cached_file_is_fresh = false;
    fd_t ret_fd = -EBADFD;
    int code;
    ne_request *req = NULL;
    int ne_ret;

    pdata = ldb_filecache_pdata_get(cache, path);

    if (pdata != NULL)
        log_print(LOG_INFO, "ldb_get_fresh_fd: file found in cache: %s::%s", path, pdata->filename);

    // Is it usable as-is?
    if ((flags & O_TRUNC) || (pdata != NULL && (time(NULL) - pdata->last_server_update) <= REFRESH_INTERVAL)) {
        cached_file_is_fresh = true;
    }

    if (cached_file_is_fresh) {
        log_print(LOG_INFO, "ldb_get_fresh_fd: file is fresh or being truncated: %s::%s", path, pdata->filename);
        ret_fd = open(pdata->filename, flags);
        if (ret_fd < 0) {
            log_print(LOG_ERR, "ldb_get_fresh_fd: open returns < 0 on \"%s\": errno: %d, %s", pdata->filename, errno, strerror(errno));
        }
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
            log_print(LOG_ERR, "ldb_get_fresh_fd: ne_begin_request is not NE_OK: %d %s",
                ne_ret, ne_get_error(session));
            goto finish;
        }

        code = ne_get_status(req)->code;
        if (code == 304) {
            log_print(LOG_DEBUG, "Got 304 on %s with etag %s", path, pdata->etag);

            // Gobble up any remaining data in the response.
            ne_discard_response(req);

            if (pdata != NULL) {
                // Mark the cache item as revalidated at the current time.
                pdata->last_server_update = time(NULL);
                log_print(LOG_INFO, "ldb_get_fresh_fd: Updating file cache on 304 for %s : %s.", path, pdata->filename);
                ldb_filecache_pdata_set(cache, path, pdata);
    
                // @TODO: Set proper flags? Or enforce in fusedav.c?
                ret_fd = open(pdata->filename, flags);
                if (ret_fd < 0) {
                    log_print(LOG_ERR, "ldb_get_fresh_fd: open for 304 on %s with flags %d returns < 0", pdata->filename, flags);
                }
            }
            else {
                log_print(LOG_WARNING, "ldb_get_fresh_fd: Got 304 without If-None-Match");
            }
        }
        else if (code == 200) {
            // Archive the old temp file path for unlinking after replacement.
            char old_filename[PATH_MAX];
            bool unlink_old = false;
            const char *etag = NULL;

            if (pdata == NULL) {
                pdata = malloc(sizeof(struct ldb_filecache_pdata));
                if (pdata != NULL) {
                    log_print(LOG_ERR, "ldb_get_fresh_fd: malloc returns NULL for pdata");
                    ne_end_request(req);
                    goto finish;
                }
                memset(pdata, 0, sizeof(struct ldb_filecache_pdata));
            }
            else {
                strncpy(old_filename, pdata->filename, PATH_MAX);
                unlink_old = true;
            }

            // Fill in ETag.
            etag = ne_get_response_header(req, "ETag");
            if (etag != NULL) {
                log_print(LOG_DEBUG, "Got ETag: %s", etag);
                strncpy(pdata->etag, etag, ETAG_MAX);
                pdata->etag[ETAG_MAX] = '\0'; // length of etag is ETAG_MAX + 1 to accomodate this null terminator
            }
            else {
                log_print(LOG_DEBUG, "Got no ETag in response.");
                pdata->etag[0] = '\0';
            }

            // Create a new temp file and read the file content into it.
            // @TODO: Set proper flags? Or enforce in fusedav.c?
            if (new_cache_file(cache_path, pdata->filename, &ret_fd) < 0) {
                log_print(LOG_ERR, "ldb_get_fresh_fd: new_cache_file returns < 0");
                ne_end_request(req);
                goto finish;
            }
            ne_read_response_to_fd(req, ret_fd);

            // Point the persistent cache to the new file content.
            pdata->last_server_update = time(NULL);
            log_print(LOG_INFO, "ldb_get_fresh_fd: Updating file cache on 200 for %s : %s.", path, pdata->filename);
            ldb_filecache_pdata_set(cache, path, pdata);

            // Unlink the old cache file, which the persistent cache
            // no longer references. This will cause the file to be
            // deleted once no more file descriptors reference it.
            if (unlink_old) {
                unlink(old_filename);
                log_print(LOG_DEBUG, "ldb_get_fresh_fd: 200: unlink old filename %s", old_filename);
            }
        }
        else if (code == 404) {
            log_print(LOG_WARNING, "ldb_get_fresh_fd: File expected to exist returns 404.");
            ret_fd = -ENOENT;
        }
        else {
            // Not sure what to do here; goto finish, or try the loop another time?
            log_print(LOG_WARNING, "ldb_get_fresh_fd: returns %d; expected 304 or 200", code);
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

// top-level open call
int ldb_filecache_open(char *cache_path, ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    ne_session *session;
    struct ldb_filecache_sdata *sdata = NULL;
    int ret = -EBADF;
    int flags = info->flags;

    log_print(LOG_DEBUG, "ldb_filecache_open: %s", path);

    if (!(session = session_get(1))) {
        ret = -EIO;
        log_print(LOG_ERR, "ldb_filecache_open: Failed to get session");
        goto fail;
    }

    // Allocate and zero-out a session data structure.
    sdata = malloc(sizeof(struct ldb_filecache_sdata));
    if (sdata == NULL) {
        log_print(LOG_ERR, "ldb_filecache_open: Failed to malloc sdata");
        goto fail;
    }
    memset(sdata, 0, sizeof(struct ldb_filecache_sdata));

    if (flags & O_CREAT) {
        ret = create_file(sdata, cache_path, cache, path);
        if (ret < 0) {
            log_print(LOG_ERR, "ldb_filecache_open: Failed on create for %s", path);
            goto fail;
        }
    }
    else {
        // Get a file descriptor pointing to a guaranteed-fresh file.
        sdata->fd = ldb_get_fresh_fd(session, cache, cache_path, path, flags);
        if (sdata->fd < 0) {
            log_print(LOG_ERR, "ldb_filecache_open: Failed on ldb_get_fresh_fd");
            ret = sdata->fd;
            goto fail;
        }
    }

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    if (sdata->fd >= 0) {
        log_print(LOG_DEBUG, "Setting fd to session data structure with fd %d for %s.", sdata->fd, path);
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

// top-level read call
ssize_t ldb_filecache_read(struct fuse_file_info *info, char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

    log_print(LOG_DEBUG, "ldb_filecache_read: fd=%d", sdata->fd);

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

// top-level write call
ssize_t ldb_filecache_write(struct fuse_file_info *info, const char *buf, size_t size, ne_off_t offset) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    ssize_t ret = -1;

    log_print(LOG_DEBUG, "ldb_filecache_write: fd=%d", sdata->fd);

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

    log_print(LOG_INFO, "ldb_filecache_write: acquiring shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_SH)) {
        log_print(LOG_WARNING, "ldb_filecache_write: error acquiring shared file lock on fd %d", sdata->fd);
    }
    sdata->modified = true;

finish:

    // ret is bytes written

    return ret;
}

// close the file
static int ldb_filecache_close(struct ldb_filecache_sdata *sdata) {
    int ret = -1;
    struct stat cache_file_stat;

    log_print(LOG_DEBUG, "ldb_filecache_close: fd (%d).", sdata->fd);

    fstat(sdata->fd, &cache_file_stat);
    log_print(LOG_INFO, "ldb_filecache_close: Cache file has length %lu", cache_file_stat.st_size);

    if (sdata->fd >= 0)
        ret = close(sdata->fd);

    log_print(LOG_DEBUG, "ldb_filecache_close: close returns %d %s", ret, strerror(ret));

    if (sdata != NULL)
        free(sdata);

    return 0;
}

// top-level close/release call
int ldb_filecache_release(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    assert(sdata);

    log_print(LOG_DEBUG, "ldb_filecache_release: %s : %d", path, sdata->fd);

    if ((ret = ldb_filecache_sync(cache, path, info, true)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_release: ldb_filecache_sync returns error %d", ret);
        goto finish;
    }

    log_print(LOG_DEBUG, "Done syncing file (%s) for release, calling ldb_filecache_close.", path);

    ret = 0;

finish:

    // close, even on error
    ldb_filecache_close(sdata);

    log_print(LOG_DEBUG, "ldb_filecache_release: Done releasing file (%s).", path);

    return ret;
}

/* PUT's from fd to URI */
/* Our modification to include etag support on put */
static int ne_put_return_etag(ne_session *session, const char *path, int fd, char *etag)
{
    ne_request *req;
    struct stat st;
    int ret;
    const char *value;

    log_print(LOG_DEBUG, "enter: ne_put_return_etag(,%s,,)", path);

    assert(etag);

    if (fstat(fd, &st)) {
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

    ne_lock_using_resource(req, path, 0);
    ne_lock_using_parent(req, path);

    ne_set_request_body_fd(req, fd, 0, st.st_size);

    ret = ne_request_dispatch(req);

    if (ret != NE_OK) {
        log_print(LOG_WARNING, "ne_put_return_etag: ne_request_dispatch returns error (%d:%s: fd=%d)", ret, ne_get_error(session), fd);
    }

    if (ret == NE_OK && ne_get_status(req)->klass != 2) {
        ret = NE_ERROR;
    }

    // We continue to PUT the file if etag happens to be NULL; it just
    // means ultimately that it won't trigger a 304 on next access
    if (ret == NE_OK) {
        value = ne_get_response_header(req, "etag");
        if (value) {
            strncpy(etag, value, ETAG_MAX);
            etag[ETAG_MAX] = '\0';
        }
        log_print(LOG_DEBUG, "PUT returns etag: %s", etag);
    }
    else {
        etag[0] = '\0';
    }
    ne_request_destroy(req);

    return ret;
}

static void unlock(int fd) {
    log_print(LOG_INFO, "ldb_filecache_sync: releasing shared file lock on fd %d", fd);
    if (flock(fd, LOCK_UN)) {
        log_print(LOG_WARNING, "ldb_filecache_sync: error releasing shared file lock on fd %d", fd);
    }
}

// top-level sync call
int ldb_filecache_sync(ldb_filecache_t *cache, const char *path, struct fuse_file_info *info, bool do_put) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;
    struct ldb_filecache_pdata *pdata = NULL;
    ne_session *session;
    struct stat_cache_value value;
    struct stat cache_file_stat;

    assert(sdata);

    log_print(LOG_DEBUG, "ldb_filecache_sync(%s, fd=%d)", path, sdata->fd);

    log_print(LOG_DEBUG, "Checking if file (%s) was writable.", path);
    if (!sdata->writable) {
        // errno = EBADF; why?
        ret = 0;
        log_print(LOG_DEBUG, "ldb_filecache_sync: not writable");
        goto finish;
    }

    // Write this data to the persistent cache.
    // Update the file cache
    pdata = ldb_filecache_pdata_get(cache, path);
    if (pdata == NULL) {
        log_print(LOG_DEBUG, "ldb_filecache_sync(%s, fd=%d): pdata is NULL", path, sdata->fd);
        pdata = calloc(1, sizeof(struct ldb_filecache_pdata));
        if (pdata == NULL) {
            log_print(LOG_ERR, "ldb_filecache_sync: calloc of pdata failed");
            goto finish;
        }
        strncpy(pdata->filename, sdata->filename, PATH_MAX);
        log_print(LOG_INFO, "ldb_filecache_sync:: filename %s : %s : %s", path, sdata->filename, pdata->filename);
    }
    else {
        log_print(LOG_DEBUG, "ldb_filecache_sync(%s, fd=%d): cachefile=%s", path, sdata->fd, pdata->filename);
    }

    if (do_put) {
        log_print(LOG_DEBUG, "Checking if file (%s) was modified.", path);
        if (!sdata->modified) {
            ret = 0;
            log_print(LOG_DEBUG, "ldb_filecache_sync: not modified");
            goto finish;
        }

        log_print(LOG_DEBUG, "Seeking fd=%d", sdata->fd);
        if (lseek(sdata->fd, 0, SEEK_SET) == (ne_off_t)-1) {
            log_print(LOG_ERR, "ldb_filecache_sync: failed lseek :: %d %d %s", sdata->fd, errno, strerror(errno));
            ret = -1;
            unlock(sdata->fd);
            goto finish;
        }

        log_print(LOG_DEBUG, "Getting libneon session.");
        if (!(session = session_get(1))) {
            errno = EIO;
            ret = -1;
            log_print(LOG_ERR, "ldb_filecache_sync: failed session");
            unlock(sdata->fd);
            goto finish;
        }

        log_print(LOG_DEBUG, "About to PUT file (%s, fd=%d).", path, sdata->fd);

        if (ne_put_return_etag(session, path, sdata->fd, pdata->etag)) {
            log_print(LOG_ERR, "ne_put PUT failed: %s: fd=%d", ne_get_error(session), sdata->fd);
            errno = ENOENT;
            ret = -1;
            unlock(sdata->fd);
            goto finish;
        }

        log_print(LOG_DEBUG, "PUT: etag = %s", pdata->etag);

        // If the PUT succeeded, the file isn't locally modified.
        sdata->modified = false;

        unlock(sdata->fd);
    }
    else {
        // If we don't PUT the file, we don't have an etag, so zero it out
        strncpy(pdata->etag, "", 1);
    }

    // Point the persistent cache to the new file content.
    pdata->last_server_update = time(NULL);

    fstat(sdata->fd, &cache_file_stat);
    log_print(LOG_INFO, "ldb_filecache_sync: Updating file cache for %s : %s (size %lu)", path, pdata->filename, cache_file_stat.st_size);
    ldb_filecache_pdata_set(cache, path, pdata);

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
    log_print(LOG_INFO, "ldb_filecache_sync: Updated stat cache %d:%s:%s", sdata->fd, path, pdata->filename);

    free(pdata);
    ret = 0;

finish:

    log_print(LOG_DEBUG, "ldb_filecache_sync: Done syncing file (%s, fd=%d).", path, sdata->fd);

    return ret;
}

// top-level truncate call
int ldb_filecache_truncate(struct fuse_file_info *info, ne_off_t s) {
    struct ldb_filecache_sdata *sdata = (struct ldb_filecache_sdata *)info->fh;
    int ret = -1;

    if ((ret = ftruncate(sdata->fd, s)) < 0) {
        log_print(LOG_ERR, "ldb_filecache_truncate: error on ftruncate %d", ret);
    }

    return ret;
}

int ldb_filecache_fd(ldb_filecache_t *cache, const char *path) {
    int fd;
    struct ldb_filecache_pdata *pdata = NULL;

    log_print(LOG_INFO, "ldb_filecache_fd(%s)", path);

    pdata = ldb_filecache_pdata_get(cache, path);
    if (!pdata) return -1;
    log_print(LOG_INFO, "ldb_filecache_fd(cachefile = %s)", pdata->filename);

    fd = open(pdata->filename, O_RDONLY);
    return fd;
}

// deletes entry from ldb cache
int ldb_filecache_delete(ldb_filecache_t *cache, const char *path) {
    struct ldb_filecache_pdata *pdata = NULL;
    leveldb_writeoptions_t *options;
    char *key;
    int ret = 0;
    char *errptr = NULL;

    log_print(LOG_DEBUG, "ldb_filecache_delete: path (%s).", path);

    pdata = ldb_filecache_pdata_get(cache, path);

    key = path2key(path);

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &errptr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (pdata) {
        unlink(pdata->filename);
        log_print(LOG_DEBUG, "ldb_filecache_delete: unlinking %s", pdata->filename);
        free(pdata);
    }

    if (errptr != NULL) {
        log_print(LOG_ERR, "ERROR: leveldb_delete: %s", errptr);
        free(errptr);
        ret = -1;
    }

    return ret;
}

int ldb_filecache_pdata_move(ldb_filecache_t *cache, const char *old_path, const char *new_path) {
    struct ldb_filecache_pdata *pdata = NULL;
    int ret = -1;

    pdata = ldb_filecache_pdata_get(cache, old_path);

    if (pdata == NULL) {
        log_print(LOG_INFO, "ldb_filecache_pdata_move: Path %s does not exist.", old_path);
        goto finish;
    }

    pdata->last_server_update = time(NULL);

    if (ldb_filecache_pdata_set(cache, new_path, pdata) < 0) {
        log_print(LOG_ERR, "ldb_filecache_pdata_move: Moving entry from path %s to %s failed. Could not write new entry.", old_path, new_path);
        goto finish;
    }

    ldb_filecache_delete(cache, old_path);

finish:
    if (pdata != NULL)
        free(pdata);
    return ret;
}

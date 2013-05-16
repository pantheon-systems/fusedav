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
#include <inttypes.h>
#include <time.h>
#include <utime.h>
#include <dirent.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdlib.h>
#include <ctype.h>

#include "filecache.h"
#include "statcache.h"
#include "fusedav.h"
#include "log.h"
#include "log_sections.h"
#include "util.h"

#define REFRESH_INTERVAL 3
#define CACHE_FILE_ENTROPY 20

// Remove filecache files older than 8 days
#define AGE_OUT_THRESHOLD 691200

// Entries for stat and file cache are in the ldb cache; fc: designates filecache entries
static const char * filecache_prefix = "fc:";

typedef int fd_t;

// Session data
struct filecache_sdata {
    fd_t fd; // LOCK_SH for write/truncation; LOCK_EX during PUT
    bool readable;
    bool writable;
    bool modified;
};

// FIX ME Where to find ETAG_MAX?
#define ETAG_MAX 256

// Persistent data stored in leveldb
struct filecache_pdata {
    char filename[PATH_MAX];
    char etag[ETAG_MAX + 1];
    time_t last_server_update;
};

struct statistics {
    unsigned cache_file;
    unsigned pdata_set;
    unsigned create_file;
    unsigned pdata_get;
    unsigned fresh_fd;
    unsigned open;
    unsigned read;
    unsigned write;
    unsigned close;
    unsigned return_etag;
    unsigned sync;
    unsigned truncate;
    unsigned delete;
    unsigned pdata_move;
    unsigned orphans;
    unsigned cleanup;
    unsigned get_fd;
    unsigned init;
    unsigned path2key;
    unsigned key2path;
};

static struct statistics stats;

#define BUMP(op) __sync_fetch_and_add(&stats.op, 1)
#define FETCH(c) __sync_fetch_and_or(&stats.c, 0)

void filecache_print_stats(void) {
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "Filecache Operations:");
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  cache_file:  %u", FETCH(cache_file));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_set:   %u", FETCH(pdata_set));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  create_file: %u", FETCH(create_file));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_get:   %u", FETCH(pdata_get));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  fresh_fd:    %u", FETCH(fresh_fd));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  open:        %u", FETCH(open));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  read:        %u", FETCH(read));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  write:       %u", FETCH(write));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  close:       %u", FETCH(close));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  return_etag: %u", FETCH(return_etag));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  sync:        %u", FETCH(sync));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  truncate:    %u", FETCH(truncate));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  delete:      %u", FETCH(delete));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  pdata_move:  %u", FETCH(pdata_move));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  orphans:     %u", FETCH(orphans));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  cleanup:     %u", FETCH(cleanup));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  get_fd:      %u", FETCH(get_fd));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  init:        %u", FETCH(init));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  path2key:    %u", FETCH(path2key));
    log_print(LOG_NOTICE, SECTION_FILECACHE_OUTPUT, "  key2path:    %u", FETCH(key2path));

}

// GError mechanisms
G_DEFINE_QUARK(FC, filecache)
G_DEFINE_QUARK(SYS, system)
G_DEFINE_QUARK(LDB, leveldb)
G_DEFINE_QUARK(CURL, curl)

// error injection routines
// This routine is here because it is easier to update if one adds a new call to <>_inject_error() than if it were in util.c
int filecache_errors(void) {
    const int inject_errors = 38; // Number of places we call filecache_inject_error(). Update when changed.
    return inject_errors;
}

void filecache_init(char *cache_path, GError **gerr) {
    char path[PATH_MAX];

    BUMP(init);

    snprintf(path, PATH_MAX, "%s/files", cache_path);
    if (mkdir(cache_path, 0770) == -1) {
        if (errno != EEXIST || filecache_inject_error(0)) {
            g_set_error (gerr, system_quark(), errno, "filecache_init: Cache Path %s could not be created.", cache_path);
            return;
        }
    }
    if (mkdir(path, 0770) == -1) {
        if (errno != EEXIST || filecache_inject_error(1)) {
            g_set_error (gerr, system_quark(), errno, "filecache_init: Path %s could not be created.", path);
            return;
        }
    }
    return;
}

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;

    BUMP(path2key);

    asprintf(&key, "%s%s", filecache_prefix, path);
    return key;
}

// creates a new cache file
static void new_cache_file(const char *cache_path, char *cache_file_path, fd_t *fd, GError **gerr) {
    char entropy[CACHE_FILE_ENTROPY + 1];

    BUMP(cache_file);

    for (size_t pos = 0; pos <= CACHE_FILE_ENTROPY; ++pos) {
        entropy[pos] = 65 + rand() % 26;
    }
    entropy[CACHE_FILE_ENTROPY] = '\0';

    snprintf(cache_file_path, PATH_MAX, "%s/files/fusedav-cache-%s-XXXXXX", cache_path, entropy);
    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "new_cache_file: Using pattern %s", cache_file_path);
    if ((*fd = mkstemp(cache_file_path)) < 0 || filecache_inject_error(2)) {
        g_set_error (gerr, system_quark(), errno, "new_cache_file: Failed mkstemp");
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "new_cache_file: mkstemp fd=%d :: %s", *fd, cache_file_path);
    return;
}

// adds an entry to the ldb cache
static void filecache_pdata_set(filecache_t *cache, const char *path,
        const struct filecache_pdata *pdata, GError **gerr) {
    leveldb_writeoptions_t *options;
    char *ldberr = NULL;
    char *key;

    BUMP(pdata_set);

    if (!pdata || filecache_inject_error(3)) {
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_pdata_set NULL pdata");
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_pdata_set: path=%s ; cachefile=%s", path, pdata->filename);

    key = path2key(path);
    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (const char *) pdata, sizeof(struct filecache_pdata), &ldberr);
    leveldb_writeoptions_destroy(options);

    free(key);

    if (ldberr != NULL || filecache_inject_error(4)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_pdata_set: leveldb_put error %s", ldberr);
        free(ldberr);
        return;
    }

    return;
}

// Create a new file to write into and set values
static void create_file(struct filecache_sdata *sdata, const char *cache_path,
        filecache_t *cache, const char *path, GError **gerr) {

    struct filecache_pdata *pdata;
    GError *tmpgerr = NULL;

    BUMP(create_file);

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "create_file: on %s", path);

    pdata = calloc(1, sizeof(struct filecache_pdata));
    if (pdata == NULL || filecache_inject_error(5)) {
        g_set_error(gerr, system_quark(), errno, "create_file: calloc returns NULL for pdata");
        return;
    }

    sdata->modified = true;
    sdata->writable = true;
    new_cache_file(cache_path, pdata->filename, &sdata->fd, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "create_file: ");
        goto finish;
    }

    // The local copy currently trumps the server one, no matter how old.
    pdata->last_server_update = 0;

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "create_file: Updating file cache for %d : %s : %s : timestamp %ul.", sdata->fd, path, pdata->filename, pdata->last_server_update);
    filecache_pdata_set(cache, path, pdata, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "create_file: ");
        goto finish;
    }

finish:

    free(pdata);

    return;
}

// get an entry from the ldb cache
static struct filecache_pdata *filecache_pdata_get(filecache_t *cache, const char *path, GError **gerr) {
    struct filecache_pdata *pdata = NULL;
    char *key;
    leveldb_readoptions_t *options;
    size_t vallen;
    char *ldberr = NULL;

    BUMP(pdata_get);

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "Entered filecache_pdata_get: path=%s", path);

    key = path2key(path);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    pdata = (struct filecache_pdata *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &ldberr);
    leveldb_readoptions_destroy(options);
    free(key);

    if (ldberr != NULL || filecache_inject_error(6)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_pdata_get: leveldb_get error %s", ldberr);
        free(ldberr);
        free(pdata);
        return NULL;
    }

    if (!pdata) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_pdata_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct filecache_pdata)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "Length %lu is not expected length %lu.", vallen, sizeof(struct filecache_pdata));
        free(pdata);
        return NULL;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "Returning from filecache_pdata_get: path=%s :: cachefile=%s", path, pdata->filename);

    return pdata;
}

// Stores the header value into into *userdata if it's "ETag."
static size_t capture_etag(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    char *header = (char *) ptr;
    char *etag = (char *) userdata; // Allocated to ETAG_MAX length.
    char *value;

    value = strstr(header, ":");

    if (value == NULL)
        goto finish;

    // Skip the colon and whitespace.
    ++value;
    while(isspace(value[0]))
        ++value;

    // Is it an ETag? If so, store it.
    if (strncasecmp(header, "ETag", 4) == 0) {
        size_t value_len = strlen(value);

        // If the ETag is too long, bail.
        if (value_len > ETAG_MAX)
            goto finish;

        strncpy(etag, value, value_len);
        etag[value_len - 1] = '\0';
    }

finish:
    return real_size;
}

static size_t write_response_to_fd(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    fd_t *fdp = (fd_t *) userdata;
    fd_t myfd = *fdp;
    ssize_t res;
    res = write(myfd, ptr, size * nmemb);
    if ((size_t) res != real_size)
        return 0;
    return real_size;
}

// Get a file descriptor pointing to the latest full copy of the file.
static void get_fresh_fd(filecache_t *cache,
        const char *cache_path, const char *path, struct filecache_sdata *sdata,
        struct filecache_pdata **pdatap, int flags, bool skip_validation, GError **gerr) {
    CURL *session;
    GError *tmpgerr = NULL;
    long code;
    CURLcode res;
    struct filecache_pdata *pdata;
    char etag[ETAG_MAX];
    char response_filename[PATH_MAX] = "\0";
    int response_fd = -1;
    bool close_response_fd = true;

    BUMP(fresh_fd);

    assert(pdatap);
    pdata = *pdatap;

    if (pdata != NULL)
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: file found in cache: %s::%s", path, pdata->filename);

    // Do we need to go out to the server, or just serve from the file cache
    // We should have guaranteed that if O_TRUNC is specified and pdata is NULL we don't get here.
    // For O_TRUNC, we just want to open a truncated cache file and not bother getting a copy from
    // the server.
    // If not O_TRUNC, but the cache file is fresh, just reuse it without going to the server.
    // If the file is in-use (last_server_update = 0) or we are in grace or saint mode (skip_validation)
    // we use the local file and don't go to the server.
    if (pdata != NULL && ( (flags & O_TRUNC) || (pdata->last_server_update == 0 || (time(NULL) - pdata->last_server_update) <= REFRESH_INTERVAL || skip_validation))) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: file is fresh or being truncated: %s::%s", path, pdata->filename);

        // Open first with O_TRUNC off to avoid modifying the file without holding the right lock.
        sdata->fd = open(pdata->filename, flags & ~O_TRUNC);
        if (sdata->fd < 0 || filecache_inject_error(7)) {
            log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "get_fresh_fd: < 0, %s with flags %x returns < 0: errno: %d, %s : ENOENT=%d", path, flags, errno, strerror(errno), ENOENT);
            // If the cachefile named in pdata->filename does not exist, or any other error occurs...
            g_set_error(gerr, system_quark(), errno, "get_fresh_fd: open failed: %s", strerror(errno));
            goto finish;
        }

        if (flags & O_TRUNC) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: truncating fd %d:%s::%s", sdata->fd, path, pdata->filename);

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: acquiring shared file lock on fd %d", sdata->fd);
            if (flock(sdata->fd, LOCK_SH) || filecache_inject_error(8)) {
                g_set_error(gerr, system_quark(), errno, "get_fresh_fd: error acquiring shared file lock");
                goto finish;
            }
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: acquired shared file lock on fd %d", sdata->fd);

            if (ftruncate(sdata->fd, 0) || filecache_inject_error(9)) {
                g_set_error(gerr, system_quark(), errno, "get_fresh_fd: ftruncate failed");
                log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "get_fresh_fd: ftruncate failed; %d:%s:%s :: %s", sdata->fd, path, pdata->filename, g_strerror(errno));
                // Fall through to release the lock
            }

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: releasing shared file lock on fd %d", sdata->fd);
            if (flock(sdata->fd, LOCK_UN) || filecache_inject_error(10)) {
                // If we didn't get an error from ftruncate, then set gerr here from flock on error;
                // If ftruncate did get an error, it will take precedence and we will ignore this error
                if (!gerr) {
                    g_set_error(gerr, system_quark(), errno, "get_fresh_fd: error releasing shared file lock");
                }
                else {
                    // If we got an error from ftruncate so don't set one for flock, still report
                    // that releasing the lock failed.
                    log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "get_fresh_fd: error releasing shared file lock :: %s", strerror(errno));
                }
                goto finish;
            }

            // We've fallen through to flock from ftruncate; if ftruncate returns an error, return here
            if (gerr) goto finish;

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: released shared file lock on fd %d", sdata->fd);

            sdata->modified = true;
        }
        else {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: O_TRUNC not specified on fd %d:%s::%s", sdata->fd, path, pdata->filename);
        }

        // We're done; no need to access the server...
        goto finish;
    }

    session = session_request_init(path);
    if (!session || filecache_inject_error(11)) {
        g_set_error(gerr, curl_quark(), E_FC_CURLERR, "get_fresh_fd: Failed session_request_init on GET");
        goto finish;
    }

    if (pdata) {
        char *header = NULL;
        struct curl_slist *slist = NULL;

        // In case we have stale cache data, set a header to aim for a 304.
        asprintf(&header, "If-None-Match: %s", pdata->etag);
        slist = curl_slist_append(slist, header);
        free(header);
        curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);
    }

    // Set an ETag header capture path.
    etag[0] = '\0';
    curl_easy_setopt(session, CURLOPT_HEADERFUNCTION, capture_etag);
    curl_easy_setopt(session, CURLOPT_WRITEHEADER, etag);

    // Create a new temp file in case cURL needs to write to one.
    new_cache_file(cache_path, response_filename, &response_fd, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "get_fresh_fd: ");
        // REVIEW: @TODO: Should we delete path from cache and/or null-out pdata?
        goto finish;
    }

    // Give cURL the fd and callback for handling the response body.
    curl_easy_setopt(session, CURLOPT_WRITEDATA, &response_fd);
    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, write_response_to_fd);

    do {
        res = curl_easy_perform(session);
        if (res != CURLE_OK || filecache_inject_error(12)) {
            g_set_error(gerr, curl_quark(), E_FC_CURLERR, "get_fresh_fd: curl_easy_perform is not CURLE_OK: %s",
                curl_easy_strerror(res));
            goto finish;
        }

        // If we get a 304, the cache file has the same contents as the file on the server, so
        // just open the cache file without bothering to re-GET the contents from the server.
        // If we get a 200, the cache file is stale and we need to update its contents from
        // the server.
        // We should not get a 404 here; either the open included O_CREAT and we create a new
        // file, or the getattr/get_stat calls in fusedav.c should have detected the file was
        // missing and handled it there.
        curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &code);
        if (code == 304) {
            // This should never happen with a well-behaved server.
            if (pdata == NULL) {
                g_set_error(gerr, system_quark(), E_FC_PDATANULL, "get_fresh_fd: Should not get HTTP 304 from server when pdata is NULL because etag is empty.");
                goto finish;
            }

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "Got 304 on %s with etag %s", path, pdata->etag);

            // Mark the cache item as revalidated at the current time.
            pdata->last_server_update = time(NULL);

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: Updating file cache on 304 for %s : %s : timestamp: %ul.", path, pdata->filename, pdata->last_server_update);
            filecache_pdata_set(cache, path, pdata, &tmpgerr);
            if (tmpgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "get_fresh_fd on 304: ");
                goto finish;
            }

            sdata->fd = open(pdata->filename, flags);

            if (sdata->fd < 0 || filecache_inject_error(13)) {
                // If the cachefile named in pdata->filename does not exist ...
                if (errno == ENOENT) {
                    // delete pdata from cache, we can't trust its values.
                    // We see one site continually failing on the same non-existent cache file.
                    filecache_delete(cache, path, true, &tmpgerr);
                }
                g_set_error(gerr, system_quark(), errno, "get_fresh_fd: open for 304 failed: %s", strerror(errno));
                log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "get_fresh_fd: open for 304 on %s with flags %x and etag %s returns < 0: errno: %d, %s", pdata->filename, flags, pdata->etag, errno, strerror(errno));
                goto finish;
            }
            else {
                log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: open for 304 on %s with flags %x succeeded; fd %d", pdata->filename, flags, sdata->fd);
            }
        }
        else if (code == 200) {
            // Archive the old temp file path for unlinking after replacement.
            char old_filename[PATH_MAX];
            bool unlink_old = false;

            if (pdata == NULL) {
                *pdatap = calloc(1, sizeof(struct filecache_pdata));
                pdata = *pdatap;
                if (pdata == NULL || filecache_inject_error(14)) {
                    g_set_error(gerr, system_quark(), errno, "get_fresh_fd: ");
                    goto finish;
                }
            }
            else {
                strncpy(old_filename, pdata->filename, PATH_MAX);
                unlink_old = true;
            }

            // Fill in ETag.
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "Saving ETag: %s", etag);
            strncpy(pdata->etag, etag, ETAG_MAX);
            pdata->etag[ETAG_MAX] = '\0'; // length of etag is ETAG_MAX + 1 to accomodate this null terminator

            // Point the persistent cache to the new file content.
            pdata->last_server_update = time(NULL);
            strncpy(pdata->filename, response_filename, PATH_MAX);

            sdata->fd = response_fd;

            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: Updating file cache on 200 for %s : %s : timestamp: %ul.", path, pdata->filename, pdata->last_server_update);
            filecache_pdata_set(cache, path, pdata, &tmpgerr);
            if (tmpgerr) {
                memset(sdata, 0, sizeof(struct filecache_sdata));
                g_propagate_prefixed_error(gerr, tmpgerr, "get_fresh_fd on 200: ");
                goto finish;
            }

            close_response_fd = false;

            // Unlink the old cache file, which the persistent cache
            // no longer references. This will cause the file to be
            // deleted once no more file descriptors reference it.
            if (unlink_old) {
                unlink(old_filename);
                log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "get_fresh_fd: 200: unlink old filename %s", old_filename);
            }
        }
        else if (code == 404 || filecache_inject_error(15)) {
            g_set_error(gerr, filecache_quark(), ENOENT, "get_fresh_fd: File expected to exist returns 404.");
            /* we get a 404 because the stat_cache returned that the file existed, but it
             * was not on the server. Deleting it from the stat_cache makes the stat_cache
             * consistent, so the next access to the file will be handled correctly.
             */

            if (stat_cache_value_get(cache, path, true, NULL)) {
                log_print(LOG_NOTICE, SECTION_FILECACHE_OPEN, "get_fresh_fd: 404 on file in cache %s; deleting...", path);
                stat_cache_delete(cache, path, &tmpgerr);

                /* We do not propagate this error, it is just informational */
                if (tmpgerr || filecache_inject_error(16)) {
                    log_print(LOG_NOTICE, SECTION_FILECACHE_OPEN, "get_fresh_fd: on 404 stat_cache_delete failed on %s", path);
                }
            }
            goto finish;
        }
        else {
            // Not sure what to do here; goto finish, or try the loop another time?
            log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "get_fresh_fd: returns %d; expected 304 or 200", code);
        }
    } while (false); // @TODO: Retry here with cURL?

    // No check for O_TRUNC here because we skip server access and just
    // truncate.
    assert(!(flags & O_TRUNC));

finish:
    if (close_response_fd) {
        if (response_fd >= 0) close(response_fd);
        if (response_filename[0] != '\0') unlink(response_filename);
    }
}

// top-level open call
void filecache_open(char *cache_path, filecache_t *cache, const char *path,
        struct fuse_file_info *info, unsigned grace_level, bool *used_grace, GError **gerr) {
    struct filecache_pdata *pdata = NULL;
    struct filecache_sdata *sdata = NULL;
    GError *tmpgerr = NULL;
    int flags = info->flags;
    const unsigned max_retries = 2;
    bool skip_validation = false;
    unsigned retries;

    BUMP(open);
    assert(used_grace);
    *used_grace = false;

    if (grace_level >= 2)
        skip_validation = true;

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: %s", path);

    // Allocate and zero-out a session data structure.
    sdata = calloc(1, sizeof(struct filecache_sdata));
    if (sdata == NULL || filecache_inject_error(17)) {
        g_set_error(gerr, system_quark(), errno, "filecache_open: Failed to calloc sdata");
        goto fail;
    }

    for (retries = 0; true; ++retries) {
        // If open is called twice, both times with O_CREAT, fuse does not pass O_CREAT
        // the second time. (Unlike on a linux file system, where the second time open
        // is called with O_CREAT, the flag is there but is ignored.) So O_CREAT here
        // means new file.

        // If O_TRUNC is called, it is possible that there is no entry in the filecache.
        // I believe the use-case for this is: prior to conversion to fusedav, a file
        // was on the server. After conversion to fusedav, on first access, it is not
        // in the cache, so we need to create a new cache file for it (or it has aged
        // out of the cache.) If it is in the cache, we let get_fresh_fd handle it.

        if (pdata == NULL)
            pdata = filecache_pdata_get(cache, path, NULL);

        if ((flags & O_CREAT) || ((flags & O_TRUNC) && (pdata == NULL))) {
            if ((flags & O_CREAT) && (pdata != NULL)) {
                // This will orphan the previous filecache file
                log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "filecache_open: creating a file that already has a cache entry: %s", path);
            }
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: calling create_file on %s", path);
            create_file(sdata, cache_path, cache, path, &tmpgerr);
            if (tmpgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "filecache_open: ");
                goto fail;
            }
            break;
        }

        // Get a file descriptor pointing to a guaranteed-fresh file.
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: calling get_fresh_fd on %s", path);
        get_fresh_fd(cache, cache_path, path, sdata, &pdata, flags, skip_validation, &tmpgerr);
        if (tmpgerr) {
            if (tmpgerr->domain == curl_quark() && grace_level >= 1 && retries < max_retries) {
                log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "filecache_open: Falling back with grace mode for path %s. Error: %s", path, tmpgerr->message);
                g_clear_error(&tmpgerr);
                skip_validation = true;
                *used_grace = true;
                continue;
            }
            else if (tmpgerr->domain == system_quark() && retries < max_retries) {
                log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "filecache_open: Retrying with reset pdata for path %s. Error: %s", path, tmpgerr->message);
                g_clear_error(&tmpgerr);
                filecache_delete(cache, path, true, &tmpgerr);
                // Now that we've gotten rid of cache entry, free pdata
                free(pdata);
                pdata = NULL;
                continue;
            }

            g_propagate_prefixed_error(gerr, tmpgerr, "filecache_open: Failed on get_fresh_fd: ");
            goto fail;
        }

        // If we've reached here, it's successful, and we don't want to retry.
        break;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: success on %s", path);

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    if (sdata->fd >= 0) {
        if (pdata) log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: Setting fd to session data structure with fd %d for %s :: %s:%ul.", sdata->fd, path, pdata->filename, pdata->last_server_update);
        else log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: Setting fd to session data structure with fd %d for %s :: (no pdata).", sdata->fd, path);
        info->fh = (uint64_t) sdata;
        goto finish;
    }

fail:
    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "filecache_open: No valid fd set for path %s. Setting fh structure to NULL.", path);
    info->fh = (uint64_t) NULL;

    free(sdata);

finish:
    free(pdata);
}

// top-level read call
ssize_t filecache_read(struct fuse_file_info *info, char *buf, size_t size, off_t offset, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;
    ssize_t bytes_read;

    BUMP(read);

    if (sdata == NULL) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_close: sdata is NULL");
        return -1;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_read: fd=%d", sdata->fd);

    bytes_read = pread(sdata->fd, buf, size, offset);
    if (bytes_read < 0 || filecache_inject_error(18)) {
        g_set_error(gerr, system_quark(), errno, "filecache_read: pread failed: ");
        log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_read: %ld %d %s %lu %ld::%s", bytes_read, sdata->fd, buf, size, offset, g_strerror(errno));
        return 0;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "Done reading: %d from %d.", bytes_read, sdata->fd);

    return bytes_read;
}

// top-level write call
ssize_t filecache_write(struct fuse_file_info *info, const char *buf, size_t size, off_t offset, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;
    ssize_t bytes_written;

    BUMP(write);

    if (sdata == NULL) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_close: sdata is NULL");
        return -1;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: fd=%d", sdata->fd);

    if (!sdata->writable || filecache_inject_error(19)) {
        g_set_error(gerr, system_quark(), EBADF, "filecache_write: not writable");
        return -1;
    }

    // Don't write to a file while it is being PUT
    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: acquiring shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_SH) || filecache_inject_error(20)) {
        g_set_error(gerr, system_quark(), errno, "filecache_write: error acquiring shared file lock");
        return -1;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: acquired shared file lock on fd %d", sdata->fd);

    bytes_written = pwrite(sdata->fd, buf, size, offset);
    if (bytes_written < 0 || filecache_inject_error(21)) {
        g_set_error(gerr, system_quark(), errno, "filecache_write: pwrite failed");
        log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_write: %ld::%d %lu %ld :: %s", bytes_written, sdata->fd, size, offset, strerror(errno));
    } else {
        sdata->modified = true;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: releasing shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_UN) || filecache_inject_error(22)) {
        g_set_error(gerr, system_quark(), errno, "filecache_write: error releasing shared file lock");
        // Since we've already written (or not), just fall through and return bytes_written
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: released shared file lock on fd %d", sdata->fd);

    return bytes_written;
}

// close the file
void filecache_close(struct fuse_file_info *info, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(close);

    if (sdata == NULL) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_close: sdata is NULL");
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_close: fd (%d :: %d).", sdata->fd, sdata->fd);

    if (sdata->fd < 0 || filecache_inject_error(23))  {
        g_set_error(gerr, system_quark(), EBADF, "filecache_close got bad file descriptor");
    }
    else {
        if (close(sdata->fd) < 0 || filecache_inject_error(24)) {
            g_set_error(gerr, system_quark(), errno, "filecache_close: close failed");
        }
        else {
            log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_close: closed fd (%d).", sdata->fd);
        }
    }

    free(sdata);

    return;
}

/* PUT's from fd to URI */
/* Our modification to include etag support on put */
static void put_return_etag(const char *path, int fd, char *etag, GError **gerr) {
    CURL *session;
    CURLcode res;
    struct stat st;
    long response_code;

    BUMP(return_etag);

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "enter: put_return_etag(,%s,%d,,)", path, fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "put_return_etag: acquiring exclusive file lock on fd %d", fd);
    if (flock(fd, LOCK_EX)) {
        g_set_error(gerr, system_quark(), errno, "put_return_etag: error acquiring exclusive file lock");
        return;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "put_return_etag: acquired exclusive file lock on fd %d", fd);

    assert(etag);

    if (fstat(fd, &st) || filecache_inject_error(25)) {
        g_set_error(gerr, system_quark(), errno, "put_return_etag: fstat failed");
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "put_return_etag: file size %d", st.st_size);

    session = session_request_init(path);

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(session, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(session, CURLOPT_INFILESIZE, st.st_size);
    curl_easy_setopt(session, CURLOPT_READDATA, (void *) fdopen(fd, "r"));

    // Set a header capture path.
    etag[0] = '\0';
    curl_easy_setopt(session, CURLOPT_HEADERFUNCTION, capture_etag);
    curl_easy_setopt(session, CURLOPT_WRITEHEADER, etag);

    res = curl_easy_perform(session);
    if (res != CURLE_OK || filecache_inject_error(26)) {
        g_set_error(gerr, curl_quark(), E_FC_CURLERR, "put_return_etag: curl_easy_perform is not CURLE_OK: %s", curl_easy_strerror(res));
        goto finish;
    }
    else {
        log_print(LOG_INFO, SECTION_FILECACHE_COMM, "put_return_etag: curl_easy_perform succeeds (fd=%d)", fd);

        // Ensure that it's a 2xx response code.
        curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);

        log_print(LOG_INFO, SECTION_FILECACHE_COMM, "put_return_etag: Request got HTTP status code %lu", response_code);
        if (!(response_code >= 200 && response_code < 300) || filecache_inject_error(27)) {
            g_set_error(gerr, curl_quark(), E_FC_CURLERR, "put_return_etag: curl_easy_perform error response %ld: %s: ",
                response_code, curl_easy_strerror(res));
            goto finish;
        }
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "PUT returns etag: %s", etag);

finish:

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "put_return_etag: releasing exclusive file lock on fd %d", fd);
    if (flock(fd, LOCK_UN) || filecache_inject_error(28)) {
        g_set_error(gerr, system_quark(), errno, "put_return_etag: error releasing exclusive file lock");
    }
    else {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "put_return_etag: released exclusive file lock on fd %d", fd);
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "exit: put_return_etag");

    return;
}

// top-level sync call
void filecache_sync(filecache_t *cache, const char *path, struct fuse_file_info *info, bool do_put, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;
    struct filecache_pdata *pdata = NULL;
    GError *tmpgerr = NULL;

    BUMP(sync);

    if (sdata == NULL) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_sync: sdata is NULL");
        goto finish;
    }

    // We only do the sync if we have a path
    // If we are accessing a bare file descriptor (open/unlink/read|write),
    // path will be NULL, so just return without doing anything
    if (path == NULL) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(NULL path, returning, fd=%d)", sdata->fd);
        return;
    }
    else {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(%s, fd=%d)", path, sdata->fd);
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Checking if file (%s) was writable.", path);
    if (!sdata->writable) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: not writable");
        goto finish;
    }

    // Write this data to the persistent cache
    // Update the file cache
    pdata = filecache_pdata_get(cache, path, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: ");
        goto finish;
    }
    if (pdata == NULL || filecache_inject_error(29)) {
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_sync: pdata is NULL");
        goto finish;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(%s, fd=%d): cachefile=%s", path, sdata->fd, pdata->filename);

    if (sdata->modified) {
        if (do_put) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Seeking fd=%d", sdata->fd);
            if ((lseek(sdata->fd, 0, SEEK_SET) == (off_t)-1) || filecache_inject_error(30)) {
                g_set_error(gerr, system_quark(), errno, "filecache_sync: failed lseek");
                goto finish;
            }

            log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "About to PUT file (%s, fd=%d).", path, sdata->fd);

            put_return_etag(path, sdata->fd, pdata->etag, &tmpgerr);
            if (tmpgerr || filecache_inject_error(31)) {
                g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: put_return_etag PUT failed: ");
                goto finish;
            }

            log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: PUT successful: %s : %s : old-timestamp: %ul: etag = %s", path, pdata->filename, pdata->last_server_update, pdata->etag);

            // If the PUT succeeded, the file isn't locally modified.
            sdata->modified = false;
            pdata->last_server_update = time(NULL);
        }
        else {
            // If we don't PUT the file, we don't have an etag, so zero it out
            strncpy(pdata->etag, "", 1);

            // The local copy currently trumps the server one, no matter how old.
            pdata->last_server_update = 0;
        }
    }

    // Point the persistent cache to the new file content.
    filecache_pdata_set(cache, path, pdata, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: ");
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Updated stat cache %d:%s:%s:%ul", sdata->fd, path, pdata->filename, pdata->last_server_update);

finish:

    free(pdata);

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Done syncing file (%s, fd=%d).", path, sdata ? sdata->fd : -1);

    return;
}

// top-level truncate call
void filecache_truncate(struct fuse_file_info *info, off_t s, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(truncate);

    if (sdata == NULL) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_close: sdata is NULL");
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_truncate(%d)", sdata->fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_truncate: acquiring shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_SH) || filecache_inject_error(32)) {
        g_set_error(gerr, system_quark(), errno, "filecache_truncate: error acquiring shared file lock");
        return;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_truncate: acquired shared file lock on fd %d", sdata->fd);

    if ((ftruncate(sdata->fd, s) < 0) || filecache_inject_error(33)) {
        g_set_error(gerr, system_quark(), errno, "filecache_truncate: ftruncate failed");
        // fall through to release lock ...
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_truncate: releasing shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_UN) || filecache_inject_error(34)) {
        if (!gerr) {
            g_set_error(gerr, system_quark(), errno, "filecache_truncate: error releasing shared file lock");
        }
        else {
            log_print(LOG_WARNING, SECTION_FILECACHE_FILE, "filecache_truncate: error releasing shared file lock :: %s", g_strerror(errno));
        }
        return;
    }

    // If we got an error on ftruncate, we fell through to flock. If we didn't get an error there, we need
    // to return before setting sdata modified.
    if (gerr) return;

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_truncate: released shared file lock on fd %d", sdata->fd);

    sdata->modified = true;

    return;
}

int filecache_fd(struct fuse_file_info *info) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(get_fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_fd: %d", sdata->fd);
    return sdata->fd;
}

// deletes entry from ldb cache
void filecache_delete(filecache_t *cache, const char *path, bool unlink_cachefile, GError **gerr) {
    struct filecache_pdata *pdata;
    leveldb_writeoptions_t *options;
    GError *tmpgerr = NULL;
    char *key;
    char *ldberr = NULL;

    BUMP(delete);

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_delete: path (%s).", path);

    pdata = filecache_pdata_get(cache, path, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_delete: ");
        return;
    }

    if (!pdata) return;

    key = path2key(path);

    options = leveldb_writeoptions_create();
    leveldb_delete(cache, options, key, strlen(key) + 1, &ldberr);
    leveldb_writeoptions_destroy(options);
    free(key);

    if (unlink_cachefile && pdata) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_delete: unlinking %s", pdata->filename);
        if (unlink(pdata->filename)) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_delete: error unlinking %s", pdata->filename);
        }
    }

    if (ldberr != NULL || filecache_inject_error(35)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_delete: leveldb_delete: %s", ldberr);
        free(ldberr);
    }

    free(pdata);

    return;
}

void filecache_pdata_move(filecache_t *cache, const char *old_path, const char *new_path, GError **gerr) {
    struct filecache_pdata *pdata = NULL;
    GError *tmpgerr = NULL;

    BUMP(pdata_move);

    pdata = filecache_pdata_get(cache, old_path, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_pdata_move: ");
        return;
    }

    if (pdata == NULL || filecache_inject_error(36)) {
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_pdata_move: Old path %s does not exist.", old_path);
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_pdata_move: Update last_server_update on %s: timestamp: %ul", pdata->filename, pdata->last_server_update);

    filecache_pdata_set(cache, new_path, pdata, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_pdata_move: Moving entry from path %s to %s failed: ", old_path, new_path);
        goto finish;
    }

    // We don't want to unlink the cachefile for 'old' since we use it for 'new'
    filecache_delete(cache, old_path, false, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_pdata_move: ");
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_pdata_move: new cachefile is %s", pdata->filename);

finish:

    free(pdata);

    return;
}

// Does *not* allocate a new string.
static const char *key2path(const char *key) {
    char *prefix;

    BUMP(key2path);

    prefix = strstr(key, filecache_prefix);
    // Looking for "fc:" (filecache_prefix) at the beginning of the key
    if (prefix == key) {
        return key + strlen(filecache_prefix);
    }
    return NULL;
}

static int cleanup_orphans(const char *cache_path, time_t stamped_time, GError **gerr) {
    struct dirent *diriter;
    DIR *dir;
    char cachefile_path[PATH_MAX + 1]; // path to file in the cache
    char filecache_path[PATH_MAX + 1]; // path to the file cache itself
    int ret = 0;
    int visited = 0;
    int unlinked = 0;

    BUMP(orphans);

    cachefile_path[PATH_MAX] = '\0';
    filecache_path[PATH_MAX] = '\0';

    // JB @TODO bug here, looks for path /tmp/...
    snprintf(filecache_path, PATH_MAX, "%s/files", cache_path);
    dir = opendir(filecache_path);
    if (dir == NULL || filecache_inject_error(37)) {
        g_set_error(gerr, system_quark(), errno, "cleanup_orphans: Can't open filecache directory %s", filecache_path);
        return -1;
    }

    while ((diriter = readdir(dir)) != NULL) {
        struct stat stbuf;
        snprintf(cachefile_path, PATH_MAX , "%s/%s", filecache_path, diriter->d_name) ;
        if (stat(cachefile_path, &stbuf) == -1)
        {
            log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "cleanup_orphans: Unable to stat file: %s", cachefile_path);
            --ret;
            continue;
        }

        if ((stbuf.st_mode & S_IFMT ) == S_IFDIR) {
            // We don't expect directories, but skip them
            if ((strcmp(diriter->d_name, ".") == 0) || (strcmp(diriter->d_name, "..") == 0)) {
                log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "cleanup_orphans: found . or .. directory: %s", cachefile_path);
            }
            else {
                log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "cleanup_orphans: unexpected directory in filecache: %s", cachefile_path);
                --ret;
            }
        }
        else if ((stbuf.st_mode & S_IFMT ) != S_IFREG) {
            log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "cleanup_orphans: found and ignoring non-regular file: %s", cachefile_path);
            --ret;
        }
        else {
            ++visited;
            if (stbuf.st_mtime < stamped_time) {
                if (unlink(cachefile_path)) {
                    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "cleanup_orphans: failed to unlink %s: %d %s", cachefile_path, errno, strerror(errno));
                    --ret;
                }
                log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "cleanup_orphans: unlinked %s", cachefile_path);
                ++unlinked;
            }
            else {
                log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "cleanup_orphans: didn't unlink %s: %d %d", cachefile_path, stamped_time, stbuf.st_mtime);
            }
        }
    }
    closedir(dir);
    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "cleanup_orphans: visited %d files, unlinked %d, and had %d issues", visited, unlinked, ret);

    // ret is effectively the number of unexpected issues we encountered
    return ret;
}

void filecache_cleanup(filecache_t *cache, const char *cache_path, bool first, GError **gerr) {
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *options;
    GError *tmpgerr = NULL;

    size_t klen;
    char fname[PATH_MAX];
    time_t starttime;
    int ret;
    // Statistics
    int cached_files = 0;
    int unlinked_files = 0;
    int issues = 0;
    int pruned_files = 0;

    BUMP(cleanup);

    log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "enter: filecache_cleanup(cache %p)", cache);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    iter = leveldb_create_iterator(cache, options);

    leveldb_iter_seek(iter, filecache_prefix, strlen(filecache_prefix));

    starttime = time(NULL);

    while (leveldb_iter_valid(iter)) {
        const struct filecache_pdata *pdata;
        const char *iterkey;
        const char *path;
        // We need the key to get the path in case we need to remove the entry from the filecache
        iterkey = leveldb_iter_key(iter, &klen);
        path = key2path(iterkey);
        // if path is null, we've gone past the filecache entries
        if (path == NULL) break;
        pdata = (const struct filecache_pdata *)leveldb_iter_value(iter, &klen);
        log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "filecache_cleanup: Visiting %s :: %s", path, pdata ? pdata->filename : "no pdata");
        if (pdata) {
            ++cached_files;
            // We delete the entry, making pdata invalid, before we might need the filename to unlink,
            // so store it in fname
            strncpy(fname, pdata->filename, PATH_MAX);

            // If the cache file doesn't exist, delete the entry from the level_db cache
            ret = access(fname, F_OK);
            if (ret) {
                filecache_delete(cache, path, true, &tmpgerr);
                if (tmpgerr) {
                    g_propagate_prefixed_error(gerr, tmpgerr, "filecache_cleanup on failed call to access: ");
                    ++issues;
                    goto finish;
                }
                else {
                    ++pruned_files;
                }
            }
            else if ((first && pdata->last_server_update == 0) ||
                     ((pdata->last_server_update != 0) && (starttime - pdata->last_server_update > AGE_OUT_THRESHOLD))) {
                log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "filecache_cleanup: Unlinking %s", fname);
                filecache_delete(cache, path, true, &tmpgerr);
                if (tmpgerr) {
                    g_propagate_prefixed_error(gerr, tmpgerr, "filecache_cleanup on aged out: ");
                    ++issues;
                    goto finish;
                }
                else {
                    // Not specifically true. We could succeed at unlink in filecache_delete
                    // but return non-zero; still, close enough.
                    ++unlinked_files;
                }
            }
            else {
                // put a timestamp on the file
                ret = utime(fname, NULL);
                if (ret) {
                    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "filecache_cleanup: failed to update timestamp on \"%s\" for \"%s\" from ldb cache: %d - %s", fname, path, errno, strerror(errno));
                }
            }
        }
        else {
            log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "filecache_cleanup: pulled NULL pdata out of cache for %s", path);
        }
        leveldb_iter_next(iter);
    }

    leveldb_iter_destroy(iter);
    leveldb_readoptions_destroy(options);

    // check filestamps on each file in directory. Set back a second to avoid unlikely but
    // possible race where we are updating a file inside the window where we are starting the cache cleanup
    ret = cleanup_orphans(cache_path, (starttime - 1), &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_cleanup: ");
    }

finish:
    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "filecache_cleanup: visited %d cache entries; unlinked %d, pruned %d, had %d issues; cleanup_orphans had %d issues",
        cached_files, unlinked_files, pruned_files, issues, ret);
}

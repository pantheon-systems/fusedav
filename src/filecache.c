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

#include <unistd.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdbool.h>
#include <sys/file.h>
#include <stdlib.h>
#include <ctype.h>
#include <curl/curl.h>

#include "filecache.h"
#include "statcache.h"
#include "log.h"
#include "log_sections.h"
#include "util.h"
#include "stats.h"
#include "session.h"
#include "fusedav_config.h"
#include "fusedav-statsd.h"

#define REFRESH_INTERVAL 3
#define CACHE_FILE_ENTROPY 20

// Remove filecache files older than 8 days
#define AGE_OUT_THRESHOLD 691200

// Keeping track of file sizes processed
#define XLG 100 * 1024 * 1024
#define LG 10 * 1024 * 1024
#define MED 1024 * 1024
#define SM 100 * 1024
#define XSM 10 * 1024

// Entries for stat and file cache are in the ldb cache; fc: designates filecache entries
static const char * filecache_prefix = "fc:";

// Name of forensic haven directory
static const char * forensic_haven_dir = "forensic-haven";

typedef int fd_t;

// Session data
struct filecache_sdata {
    fd_t fd; // LOCK_SH for write/truncation; LOCK_EX during PUT
    bool readable;
    bool writable;
    bool modified;
    int error_code;
};

// @TODO Where to find ETAG_MAX?
#define ETAG_MAX 256

// Persistent data stored in leveldb
struct filecache_pdata {
    char filename[PATH_MAX];
    char etag[ETAG_MAX + 1];
    time_t last_server_update;
};

// GError mechanisms
static G_DEFINE_QUARK(FC, filecache)
static G_DEFINE_QUARK(SYS, system)
static G_DEFINE_QUARK(LDB, leveldb)
static G_DEFINE_QUARK(CURL, curl)

void filecache_init(char *cache_path, GError **gerr) {
    char path[PATH_MAX];

    BUMP(filecache_init);

    if (mkdir(cache_path, 0770) == -1) {
        if (errno != EEXIST || inject_error(filecache_error_init1)) {
            g_set_error (gerr, system_quark(), errno, "filecache_init: Cache Path %s could not be created.", cache_path);
            return;
        }
    }

    snprintf(path, PATH_MAX, "%s/files", cache_path);
    if (mkdir(path, 0770) == -1) {
        if (errno != EEXIST || inject_error(filecache_error_init2)) {
            g_set_error (gerr, system_quark(), errno, "filecache_init: Path %s could not be created.", path);
            return;
        }
    }

    snprintf(path, PATH_MAX, "%s/%s", cache_path, forensic_haven_dir);
    if (mkdir(path, 0770) == -1) {
        if (errno != EEXIST || inject_error(filecache_error_init3)) {
            g_set_error (gerr, system_quark(), errno, "filecache_init: Path %s could not be created.", path);
            return;
        }
    }
    return;
}

// Allocates a new string.
static char *path2key(const char *path) {
    char *key = NULL;

    BUMP(filecache_path2key);

    asprintf(&key, "%s%s", filecache_prefix, path);
    return key;
}

/* By default, fusedav logs LOG_NOTICE (5) and lower messages.
 * If we change fusedav.conf to up the logging to LOG_INFO or LOG_DEBUG
 * and restart fusedav, this enhanced_logging will be triggered.
 * This will tell the fileserver to log its messages to the journal.
 * We don't otherwise want the fileserver to do this, because it generates too
 * many log messages.
 * We trigger this mechanism by adding "Log-To-Journal" to the header;
 * we also add the "Instance-Identifier", aka binding id, to the header
 * so we can coordinate fusedav/fileserver messages by binding id. When
 * the fileserver detects Log-To-Journal in the header, it will log its message
 * to the journal.
 * We also have the ability to use the inject_error mechanism to test this.
 * We do this by turning the default LOG_INFO level which is passed in
 * to enhanced logging to LOG_NOTICE.
 */
struct curl_slist* enhanced_logging(struct curl_slist *slist, int log_level, int section, const char *format, ...) {

    // If we are injecting errors, we can trigger enhanced logging by decrementing
    // the log level (LOG_INFO -> LOG_NOTICE)
    if (inject_error(filecache_error_enhanced_logging)) {
        log_level -= 1;
    }
    if (logging(log_level, section)) {
        va_list ap;
        char *user_agent = NULL;
        char msg[81] = {0};
        slist = curl_slist_append(slist, "Log-To-Journal: true");
        asprintf(&user_agent, "User-Agent: %s", get_user_agent());
        slist = curl_slist_append(slist, user_agent);
        free(user_agent);
        va_start(ap, format);
        vsnprintf(msg, 80, format, ap);
        log_print(log_level, section, msg);
        va_end(ap);
    }
    return slist;
}

// creates a new cache file
static void new_cache_file(const char *cache_path, char *cache_file_path, fd_t *fd, GError **gerr) {
    char entropy[CACHE_FILE_ENTROPY + 1];

    BUMP(filecache_cache_file);

    for (size_t pos = 0; pos <= CACHE_FILE_ENTROPY; ++pos) {
        entropy[pos] = 65 + rand() % 26;
    }
    entropy[CACHE_FILE_ENTROPY] = '\0';

    snprintf(cache_file_path, PATH_MAX, "%s/files/fusedav-cache-%s-XXXXXX", cache_path, entropy);
    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "new_cache_file: Using pattern %s", cache_file_path);
    if ((*fd = mkstemp(cache_file_path)) < 0 || inject_error(filecache_error_newcachefile)) {
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

    BUMP(filecache_pdata_set);

    // null pdata will cause file to go to forensic haven.
    if (!pdata || inject_error(filecache_error_setpdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_pdata_set NULL pdata");
        return;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "filecache_pdata_set: path=%s ; cachefile=%s", path, pdata->filename);

    key = path2key(path);
    options = leveldb_writeoptions_create();
    leveldb_put(cache, options, key, strlen(key) + 1, (const char *) pdata, sizeof(struct filecache_pdata), &ldberr);
    leveldb_writeoptions_destroy(options);

    free(key);

    // ldb error will cause file to go to forensic haven.
    if (ldberr != NULL || inject_error(filecache_error_setldb)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_pdata_set: leveldb_put error %s", ldberr ? ldberr : "inject-error");
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

    BUMP(filecache_create_file);

    log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "create_file: on %s", path);

    pdata = calloc(1, sizeof(struct filecache_pdata));
    if (pdata == NULL || inject_error(filecache_error_createcalloc)) {
        g_set_error(gerr, system_quark(), errno, "create_file: calloc returns NULL for pdata");
        free(pdata); // If we get here via inject_error, pdata might in fact have been allocated
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

    log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "create_file: Updating file cache for %d : %s : %s : timestamp %lu.", sdata->fd, path, pdata->filename, pdata->last_server_update);
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

    BUMP(filecache_pdata_get);

    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "Entered filecache_pdata_get: path=%s", path);

    key = path2key(path);

    options = leveldb_readoptions_create();
    leveldb_readoptions_set_fill_cache(options, false);
    pdata = (struct filecache_pdata *) leveldb_get(cache, options, key, strlen(key) + 1, &vallen, &ldberr);
    leveldb_readoptions_destroy(options);
    free(key);

    if (ldberr != NULL || inject_error(filecache_error_getldb)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_pdata_get: leveldb_get error %s", ldberr ? ldberr : "inject-error");
        free(ldberr);
        free(pdata);
        return NULL;
    }

    if (!pdata) {
        log_print(LOG_INFO, SECTION_FILECACHE_CACHE, "filecache_pdata_get miss on path: %s", path);
        return NULL;
    }

    if (vallen != sizeof(struct filecache_pdata) || inject_error(filecache_error_getvallen)) {
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
        struct filecache_pdata **pdatap, int flags, bool use_local_copy, GError **gerr) {
    static const char *funcname = "get_fresh_fd";
    GError *tmpgerr = NULL;
    struct filecache_pdata *pdata;
    char etag[ETAG_MAX];
    char response_filename[PATH_MAX] = "\0";
    int response_fd = -1;
    bool close_response_fd = true;
    struct timespec start_time;
    long response_code = 500; // seed it as bad so we can enter the loop
    CURLcode res = CURLE_OK;
    // Not to exceed time for operation, else it's an error. Allow large files a longer time
    // Somewhat arbitrary
    static const unsigned small_time_allotment = 2000; // 2 seconds
    static const unsigned large_time_allotment = 8000; // 8 seconds

    BUMP(filecache_fresh_fd);

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    assert(pdatap);
    pdata = *pdatap;

    if (pdata != NULL) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: file found in cache: %s::%s", funcname, path, pdata->filename);
    }

    // Do we need to go out to the server, or just serve from the file cache
    // We should have guaranteed that if O_TRUNC is specified and pdata is NULL we don't get here.
    // For O_TRUNC, we just want to open a truncated cache file and not bother getting a copy from
    // the server.
    // If not O_TRUNC, but the cache file is fresh, just reuse it without going to the server.
    // If the file is in-use (last_server_update = 0) we use the local file and don't go to the server.
    // If we're in saint mode, don't go to the server
    if (pdata != NULL &&
            ((flags & O_TRUNC) || use_local_copy ||
            (pdata->last_server_update == 0) || (time(NULL) - pdata->last_server_update) <= REFRESH_INTERVAL)) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: file is fresh or being truncated: %s::%s", 
                funcname, path, pdata->filename);

        // Open first with O_TRUNC off to avoid modifying the file without holding the right lock.
        sdata->fd = open(pdata->filename, flags & ~O_TRUNC);
        if (sdata->fd < 0 || inject_error(filecache_error_freshopen1)) {
            log_print(LOG_DYNAMIC, SECTION_FILECACHE_OPEN, "%s: < 0, %s with flags %x returns < 0: errno: %d, %s : ENOENT=%d", 
                    funcname, path, flags, errno, strerror(errno), ENOENT);
            // If the cachefile named in pdata->filename does not exist, or any other error occurs...
            g_set_error(gerr, system_quark(), errno, "%s: open failed: %s", funcname, strerror(errno));
            goto finish;
        }

        if (flags & O_TRUNC) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: truncating fd %d:%s::%s",
                funcname, sdata->fd, path, pdata->filename);

            log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: acquiring shared file lock on fd %d",
                funcname, sdata->fd);
            if (flock(sdata->fd, LOCK_SH) || inject_error(filecache_error_freshflock1)) {
                g_set_error(gerr, system_quark(), errno, "%s: error acquiring shared file lock", funcname);
                goto finish;
            }
            log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: acquired shared file lock on fd %d", funcname, sdata->fd);

            if (ftruncate(sdata->fd, 0) || inject_error(filecache_error_freshftrunc)) {
                g_set_error(gerr, system_quark(), errno, "%s: ftruncate failed", funcname);
                log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "%s: ftruncate failed; %d:%s:%s :: %s",
                    funcname, sdata->fd, path, pdata->filename, g_strerror(errno));
                // Fall through to release the lock
            }

            log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: releasing shared file lock on fd %d",
                funcname, sdata->fd);
            if (flock(sdata->fd, LOCK_UN) || inject_error(filecache_error_freshflock2)) {
                // If we didn't get an error from ftruncate, then set gerr here from flock on error;
                // If ftruncate did get an error, it will take precedence and we will ignore this error
                if (!gerr) {
                    g_set_error(gerr, system_quark(), errno, "%s: error releasing shared file lock", funcname);
                }
                else {
                    // If we got an error from ftruncate so don't set one for flock, still report
                    // that releasing the lock failed.
                    log_print(LOG_CRIT, SECTION_FILECACHE_OPEN, "%s: error releasing shared file lock :: %s",
                        funcname, strerror(errno));
                }
                goto finish;
            }

            // We've fallen through to flock from ftruncate; if ftruncate returns an error, return here
            if (gerr) goto finish;

            log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: released shared file lock on fd %d", funcname, sdata->fd);

            sdata->modified = true;
        }
        else {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: O_TRUNC not specified on fd %d:%s::%s",
                funcname, sdata->fd, path, pdata->filename);
        }

        // We're done; no need to access the server...
        goto finish;
    }

    for (int idx = 0; idx < num_filesystem_server_nodes && (res != CURLE_OK || response_code >= 500); idx++) {
        long elapsed_time = 0;
        CURL *session;
        struct curl_slist *slist = NULL;

        // These will be -1 and [0] = '\0' on idx 0; but subsequent iterations we need to clean up from previous time
        if (response_fd >= 0) close(response_fd);
        if (response_filename[0] != '\0') unlink(response_filename);

        session = session_request_init(path, NULL, false);
        if (!session || inject_error(filecache_error_freshsession)) {
            g_set_error(gerr, curl_quark(), E_FC_CURLERR, "%s: Failed session_request_init on GET", funcname);
            // TODO(kibra): Manually cleaning up this lock sucks. We should make sure this happens in a better way.
            try_release_request_outstanding();
            goto finish;
        }

        if (pdata) {
            char *header = NULL;

            // In case we have stale cache data, set a header to aim for a 304.
            asprintf(&header, "If-None-Match: %s", pdata->etag);
            slist = curl_slist_append(slist, header);
            free(header);
        }
        slist = enhanced_logging(slist, LOG_INFO, SECTION_FILECACHE_OPEN, "get_fresh_id: %s", path);
        if (slist) curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

        // Set an ETag header capture path.
        etag[0] = '\0';
        curl_easy_setopt(session, CURLOPT_HEADERFUNCTION, capture_etag);
        curl_easy_setopt(session, CURLOPT_WRITEHEADER, etag);

        // Create a new temp file in case cURL needs to write to one.
        new_cache_file(cache_path, response_filename, &response_fd, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "%s: ", funcname);
            // @TODO: Should we delete path from cache and/or null-out pdata?
            // @TODO: Punt. Revisit when we add curl retry to open
            if (slist) curl_slist_free_all(slist);
            goto finish;
        }

        // Give cURL the fd and callback for handling the response body.
        curl_easy_setopt(session, CURLOPT_WRITEDATA, &response_fd);
        curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, write_response_to_fd);

        timed_curl_easy_perform(session, &res, &response_code, &elapsed_time);

        if (slist) curl_slist_free_all(slist);

        process_status(funcname, session, res, response_code, elapsed_time, idx, path, false);
    }

    if ((res != CURLE_OK || response_code >= 500) || inject_error(filecache_error_freshcurl1)) {
        trigger_saint_event(CLUSTER_FAILURE);
        set_dynamic_logging();
        g_set_error(gerr, curl_quark(), E_FC_CURLERR, "%s: curl_easy_perform is not CURLE_OK or 500: %s",
            funcname, curl_easy_strerror(res));
        goto finish;
    } else {
        trigger_saint_event(CLUSTER_SUCCESS);
    }

    // If we get a 304, the cache file has the same contents as the file on the server, so
    // just open the cache file without bothering to re-GET the contents from the server.
    // If we get a 200, the cache file is stale and we need to update its contents from
    // the server.
    // We should not get a 404 here; either the open included O_CREAT and we create a new
    // file, or the getattr/get_stat calls in fusedav.c should have detected the file was
    // missing and handled it there.
    // Update on unexpected 404: one theoretical path is that a file gets opened and written to,
    // but on the close (dav_flush/release), the PUT fails and the file never makes it to the server.
    // On opening again, the server will deliver this unexpected 404. Changes for forensic-haven
    // should prevent these errors in the future (2013-08-29)
    if (inject_error(filecache_error_fresh404)) response_code = 400;
    if (response_code == 304) {
        // This should never happen with a well-behaved server.
        if (pdata == NULL || inject_error(filecache_error_freshcurl2)) {
            g_set_error(gerr, system_quark(), E_FC_PDATANULL, 
                    "%s: Should not get HTTP 304 from server when pdata is NULL because etag is empty.", funcname);
            goto finish;
        }

        // Mark the cache item as revalidated at the current time.
        pdata->last_server_update = time(NULL);

        log_print(LOG_INFO, SECTION_FILECACHE_OPEN, 
                "%s: Updating file cache on 304 for %s : %s : timestamp: %lu : etag %s.", 
                funcname, path, pdata->filename, pdata->last_server_update, pdata->etag);
        filecache_pdata_set(cache, path, pdata, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "%s on 304: ", funcname);
            goto finish;
        }

        sdata->fd = open(pdata->filename, flags);

        if (sdata->fd < 0 || inject_error(filecache_error_freshopen2)) {
            // If the cachefile named in pdata->filename does not exist ...
            if (errno == ENOENT) {
                // delete pdata from cache, we can't trust its values.
                // We see one site continually failing on the same non-existent cache file.
                filecache_delete(cache, path, true, NULL);
            }
            g_set_error(gerr, system_quark(), errno, "%s: open for 304 failed: %s", funcname, strerror(errno));
            log_print(LOG_DYNAMIC, SECTION_FILECACHE_OPEN, 
                    "%s: open for 304 on %s with flags %x and etag %s returns < 0: errno: %d, %s", 
                    funcname, pdata->filename, flags, pdata->etag, errno, strerror(errno));
            goto finish;
        }
        else {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: open for 304 on %s with flags %x succeeded; fd %d", 
                    funcname, pdata->filename, flags, sdata->fd);
            BUMP(filecache_get_304_count);
        }
    }
    else if (response_code == 200) {
        struct stat st;
        long elapsed_time;
        struct timespec now;
        unsigned long latency;
        unsigned long count;
        // Archive the old temp file path for unlinking after replacement.
        char old_filename[PATH_MAX];
        const char *sz;
        bool unlink_old = false;

        if (pdata == NULL) {
            *pdatap = calloc(1, sizeof(struct filecache_pdata));
            pdata = *pdatap;
            if (pdata == NULL || inject_error(filecache_error_freshpdata)) {
                g_set_error(gerr, system_quark(), errno, "%s: ", funcname);
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

        log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "%s: Updating file cache on 200 for %s : %s : timestamp: %lu.", 
                funcname, path, pdata->filename, pdata->last_server_update);
        filecache_pdata_set(cache, path, pdata, &tmpgerr);
        if (tmpgerr) {
            memset(sdata, 0, sizeof(struct filecache_sdata));
            g_propagate_prefixed_error(gerr, tmpgerr, "%s on 200: ", funcname);
            goto finish;
        }

        close_response_fd = false;

        // Unlink the old cache file, which the persistent cache
        // no longer references. This will cause the file to be
        // deleted once no more file descriptors reference it.
        if (unlink_old) {
            unlink(old_filename);
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: 200: unlink old filename %s", funcname, old_filename);
        }

        if (fstat(sdata->fd, &st)) {
             log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "put_return_etag: fstat failed on %s", path);
            goto finish;
        }

        /* Get the time into now.
         * Subtract seconds since start_time and multiply by 1000 to get ms.
         * Subtract nanoseconds since start_time and divide by a million to get ms.
         * ns count might be negative (now is 3s and 100 million ns, start was 1 sec and 800 million ns.
         * Seconds is now 2 (*1000);
         * ns is now -700 (800 million ns - 100 million ns divided by a million.
         * 2000 - 700 = 1300 ms, or 1s 300ms, which is correct for 3.1 - 1.8)
         */
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_time = ((now.tv_sec - start_time.tv_sec) * 1000) + ((now.tv_nsec - start_time.tv_nsec) / (1000 * 1000));

        if (st.st_size > XLG) {
            TIMING(filecache_get_xlg_timing, elapsed_time);
            BUMP(filecache_get_xlg_count);
            latency = FETCH(filecache_get_xlg_timing);
            count = FETCH(filecache_get_xlg_count);
            sz = "XLG";
            stats_counter("large-gets", 1);
            stats_timer("large-get-latency", elapsed_time);
        }
        else if (st.st_size > LG) {
            TIMING(filecache_get_lg_timing, elapsed_time);
            BUMP(filecache_get_lg_count);
            latency = FETCH(filecache_get_lg_timing);
            count = FETCH(filecache_get_lg_count);
            sz = "LG";
            stats_counter("large-gets", 1);
            stats_timer("large-get-latency", elapsed_time);
         }
        else if (st.st_size > MED) {
            TIMING(filecache_get_med_timing, elapsed_time);
            BUMP(filecache_get_med_count);
            latency = FETCH(filecache_get_med_timing);
            count = FETCH(filecache_get_med_count);
            sz = "MED";
            stats_counter("large-gets", 1);
            stats_timer("large-get-latency", elapsed_time);
        }
        else if (st.st_size > SM) {
            TIMING(filecache_get_sm_timing, elapsed_time);
            BUMP(filecache_get_sm_count);
            latency = FETCH(filecache_get_sm_timing);
            count = FETCH(filecache_get_sm_count);
            sz = "SM";
            stats_counter("small-gets", 1);
            stats_timer("small-get-latency", elapsed_time);
        }
        else if (st.st_size > XSM) {
            TIMING(filecache_get_xsm_timing, elapsed_time);
            BUMP(filecache_get_xsm_count);
            latency = FETCH(filecache_get_xsm_timing);
            count = FETCH(filecache_get_xsm_count);
            sz = "XSM";
            stats_counter("small-gets", 1);
            stats_timer("small-get-latency", elapsed_time);
        }
        else {
            TIMING(filecache_get_xxsm_timing, elapsed_time);
            BUMP(filecache_get_xxsm_count);
            latency = FETCH(filecache_get_xxsm_timing);
            count = FETCH(filecache_get_xxsm_count);
            sz = "XXSM";
            stats_counter("small-gets", 1);
            stats_timer("small-get-latency", elapsed_time);
        }
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "put_fresh_fd: GET on size %s (%lu) for %s -- Current:Average latency %lu :: %lu",
            sz, st.st_size, path, elapsed_time, (latency / count));

        if (st.st_size >= LG && elapsed_time > large_time_allotment) {
            log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "put_fresh_fd: large (%lu) GET for %s exceeded time allotment %lu with %lu",
                st.st_size, path, large_time_allotment, elapsed_time);
            stats_counter("exceeded-time-large-GET-count", 1);
            stats_timer("exceeded-time-large-GET-latency", elapsed_time);
        }
        else if (st.st_size < LG && elapsed_time > small_time_allotment) {
            log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "put_fresh_fd: small (%lu) GET for %s exceeded time allotment %lu with %lu",
                st.st_size, path, small_time_allotment, elapsed_time);
            stats_counter("exceeded-time-small-GET-count", 1);
            stats_timer("exceeded-time-small-GET-latency", elapsed_time);
        }
    }
    else if (response_code == 404) {
        /*  If two bindings are in a race condition on the same file, this 
         *  can occur. Binding A does a propfind; Binding B does a propfind
         *  and the file is shown to exist. Binding A deletes the file
         *  then Binding B tries to access it and the server returns 404.
         *  Not sure how to remediate without doing way more work and
         *  introducing way more problems than the fix will fix.
         */
        struct stat_cache_value *value;
        g_set_error(gerr, filecache_quark(), ENOENT, "%s: File expected to exist returns 404.", funcname);
        /* we get a 404 because the stat_cache returned that the file existed, but it
         * was not on the server. Deleting it from the stat_cache makes the stat_cache
         * consistent, so the next access to the file will be handled correctly.
         */

        value = stat_cache_value_get(cache, path, true, NULL);
        if (value) {
            // Collect some additional information to give some hints about the file
            // which might help uncover why this error is happening.
            time_t lsu = 0;
            time_t atime = value->st.st_atime;
            off_t sz = value->st.st_size;
            unsigned long lg = value->local_generation;

            // If we have a pdata, it is out of date, since the server doesn't have the file,
            // meaning it must have been deleted.
            if (pdata) lsu = pdata->last_server_update;

            log_print(LOG_ERR, SECTION_FILECACHE_OPEN, "%s: 404 on file in cache %s, (lg sz tm lsu %lu %lu %lu %lu); deleting...",
                funcname, path, lg, sz, atime, lsu);

            stat_cache_delete(cache, path, NULL);

            free(value);
        }
        // Delete it from the filecache too
        filecache_delete(cache, path, true, NULL);
        goto finish;
    }
    else {
        // Not sure what to do here; goto finish, or try the loop another time?
        log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "%s: returns %d; expected 304 or 200; err: %s", funcname, response_code, curl_errorbuffer(response_code));
    }

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
void filecache_open(char *cache_path, filecache_t *cache, const char *path, struct fuse_file_info *info, bool grace, GError **gerr) {
    struct filecache_pdata *pdata = NULL;
    struct filecache_sdata *sdata = NULL;
    GError *tmpgerr = NULL;
    int max_retries = 2;
    int flags = info->flags;
    bool use_local_copy = false;

    BUMP(filecache_open);

    log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "filecache_open: %s", path);

    // Don't bother going to server if already in cluster saint mode
    if (use_saint_mode()) {
        use_local_copy = true;
        max_retries = 1; // Only try once if already in saint mode
        log_print(LOG_INFO, SECTION_FILECACHE_OPEN,
            "filecache_open: already in saint mode, using local copy: %s", path);
    }

    // Allocate and zero-out a session data structure.
    sdata = calloc(1, sizeof(struct filecache_sdata));
    if (sdata == NULL || inject_error(filecache_error_opencalloc)) {
        g_set_error(gerr, system_quark(), errno, "filecache_open: Failed to calloc sdata");
        goto fail;
    }

    // NB. We call get_fresh_fd; it tries each of the servers. If they all fail
    // we try again but force it to use the local copy. This should make saint mode
    // work on first access in the face of network errors, but seems not to be.
    for (int retries = 0; retries < max_retries; retries++) {
        // If open is called twice, both times with O_CREAT, fuse does not pass O_CREAT
        // the second time. (Unlike on a linux file system, where the second time open
        // is called with O_CREAT, the flag is there but is ignored.) So O_CREAT here
        // means new file.

        // If O_TRUNC is called, it is possible that there is no entry in the filecache.
        // If it is in the cache, we let get_fresh_fd handle it.

        if (pdata == NULL) {
            pdata = filecache_pdata_get(cache, path, NULL);
        }

        if ((flags & O_CREAT) || ((flags & O_TRUNC) && (pdata == NULL))) {
            if ((flags & O_CREAT) && (pdata != NULL)) {
                // This will orphan the previous filecache file
                // If on 'file expected to exist returns 404' we don't delete
                // the entry from the filecache, when we create a new file
                // of the same name, this outdated entry will still be in the
                // filecache. Since it's out of date, it's ok to overwrite it.
                log_print(LOG_INFO, SECTION_FILECACHE_OPEN,
                    "filecache_open: creating a file that already has a cache entry: %s", path);
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
        get_fresh_fd(cache, cache_path, path, sdata, &pdata, flags, use_local_copy, &tmpgerr);
        if (tmpgerr) {
            // If we got a network error (curl_quark is a marker) and we 
            // are using grace, try again but use the local copy
            // If we are already in saint mode (use_local_copy already true)
            // don't retry
            if (tmpgerr->domain == curl_quark() && grace && !use_local_copy) {
                log_print(LOG_WARNING, SECTION_FILECACHE_OPEN,
                    "filecache_open: Retry in saint mode for path %s. Error: %s", path, tmpgerr->message);
                g_clear_error(&tmpgerr);
                use_local_copy = true;
                continue;
            }
            g_propagate_prefixed_error(gerr, tmpgerr, "filecache_open: Failed on get_fresh_fd: ");
            goto fail;
        }

        // If we've reached here, it's successful, and we don't want to retry.
        break;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_OPEN, "filecache_open: success on %s", path);

    if (flags & O_RDONLY || flags & O_RDWR) sdata->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) sdata->writable = 1;

    if (sdata->fd >= 0) {
        if (pdata) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN,
            "filecache_open: Setting fd to session data structure with fd %d for %s :: %s:%lu.",
            sdata->fd, path, pdata->filename, pdata->last_server_update);
        }
        else {
            log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN,
            "filecache_open: Setting fd to session data structure with fd %d for %s :: (no pdata).", sdata->fd, path);
        }
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

    BUMP(filecache_read);

    if (sdata == NULL || inject_error(filecache_error_readsdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_read: sdata is NULL");
        return -1;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_read: fd=%d", sdata->fd);

    bytes_read = pread(sdata->fd, buf, size, offset);
    if (bytes_read < 0 || inject_error(filecache_error_readread)) {
        g_set_error(gerr, system_quark(), errno, "filecache_read: pread failed: ");
        log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_read: %ld %d %s %lu %ld::%s", bytes_read, sdata->fd, buf, size, offset, g_strerror(errno));
        return 0;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "Done reading: %d from %d.", bytes_read, sdata->fd);

    return bytes_read;
}

static void set_error(struct filecache_sdata *sdata, int error_code) {
    if (sdata->error_code == 0) {
        sdata->error_code = error_code;
        log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "set_error: %d.", error_code);
    }
    else {
        log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "set_error: not changing %d to %d.", sdata->error_code, error_code);
    }
}

// top-level write call
ssize_t filecache_write(struct fuse_file_info *info, const char *buf, size_t size, off_t offset, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;
    ssize_t bytes_written;

    BUMP(filecache_write);

    if (sdata == NULL || inject_error(filecache_error_writesdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_write: sdata is NULL");
        return -1;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_IO, "filecache_write: fd=%d", sdata->fd);

    if (!sdata->writable || inject_error(filecache_error_writewriteable)) {
        g_set_error(gerr, system_quark(), EBADF, "filecache_write: not writable");
        return -1;
    }

    // Don't write to a file while it is being PUT
    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_write: acquiring shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_SH) || inject_error(filecache_error_writeflock1)) {
        g_set_error(gerr, system_quark(), errno, "filecache_write: error acquiring shared file lock");
        return -1;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_write: acquired shared file lock on fd %d", sdata->fd);

    bytes_written = pwrite(sdata->fd, buf, size, offset);

    // If pwrite fails, file goes to forensic haven
    if (bytes_written < 0 || inject_error(filecache_error_writewrite)) {
        set_error(sdata, errno);
        g_set_error(gerr, system_quark(), errno, "filecache_write: pwrite failed");
        log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_write: %ld::%d %lu %ld :: %s", bytes_written, sdata->fd, size, offset, strerror(errno));
    } else {
        sdata->modified = true;
        log_print(LOG_INFO, SECTION_FILECACHE_IO, "filecache_write: wrote %d bytes on fd %d", bytes_written, sdata->fd);
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_write: releasing shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_UN) || inject_error(filecache_error_writeflock2)) {
        g_set_error(gerr, system_quark(), errno, "filecache_write: error releasing shared file lock");
        // Since we've already written (or not), just fall through and return bytes_written
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_write: released shared file lock on fd %d", sdata->fd);

    return bytes_written;
}

// close the file
void filecache_close(struct fuse_file_info *info, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(filecache_close);

    if (sdata == NULL || inject_error(filecache_error_closesdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_close: sdata is NULL");
        return;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_FILE, "filecache_close: fd (%d).", sdata->fd);

    if (sdata->fd <= 0 || inject_error(filecache_error_closefd))  {
        g_set_error(gerr, system_quark(), EBADF, "filecache_close doesn't have legitimate file descriptor");
    }
    else {
        if (close(sdata->fd) < 0 || inject_error(filecache_error_closeclose)) {
            g_set_error(gerr, system_quark(), errno, "filecache_close: close failed on fd (%d)", sdata->fd);
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
    static const char *funcname = "put_return_etag";
    struct stat st;
    struct timespec start_time;
    long response_code = 500; // seed it as bad so we can enter the loop
    CURLcode res = CURLE_OK;
    // Not to exceed time for operation, else it's an error. Allow large files a longer time
    // Somewhat arbitrary
    static const unsigned small_time_allotment = 2000; // 2 seconds
    static const unsigned large_time_allotment = 8000; // 8 seconds

    BUMP(filecache_return_etag);

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "enter: %s(,%s,%d,,)", funcname, path, fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: acquiring exclusive file lock on fd %d", funcname, fd);
    if (flock(fd, LOCK_EX) || inject_error(filecache_error_etagflock1)) {
        g_set_error(gerr, system_quark(), errno, "%s: error acquiring exclusive file lock", funcname);
        return;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: acquired exclusive file lock on fd %d", funcname, fd);

    assert(etag);

    if (fstat(fd, &st) || inject_error(filecache_error_etagfstat)) {
        g_set_error(gerr, system_quark(), errno, "%s: fstat failed", funcname);
        goto finish;
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "%s: file size %d", funcname, st.st_size);

    // If we're in saint mode, skip the PUT altogether
    for (int idx = 0;
         idx < num_filesystem_server_nodes && (res != CURLE_OK || response_code >= 500);
         idx++) {
        long elapsed_time = 0;
        CURL *session;
        struct curl_slist *slist = NULL;
        FILE *fp;

        fp = fdopen(dup(fd), "r");
        if (!fp) {
            g_set_error(gerr, system_quark(), errno, "%s: NULL fp from fdopen on fd %d for path %s", funcname, fd, path);
            goto finish;
        }
        if (fseek(fp, 0L, SEEK_SET) == (off_t)-1) {
            g_set_error(gerr, system_quark(), errno, "%s: fseek error on path %s", funcname, path);
            goto finish;
        }

        // REVIEW: We didn't use to check for sesssion == NULL, so now we 
        // also call try_release_request_outstanding. Is this OK?
        session = session_request_init(path, NULL, false);
        if (!session || inject_error(filecache_error_freshsession)) {
            g_set_error(gerr, curl_quark(), E_FC_CURLERR, "%s: Failed session_request_init on GET", funcname);
            // TODO(kibra): Manually cleaning up this lock sucks. We should make sure this happens in a better way.
            try_release_request_outstanding();
            goto finish;
        }

        curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(session, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(session, CURLOPT_INFILESIZE, st.st_size);
        curl_easy_setopt(session, CURLOPT_READDATA, (void *) fp);

        slist = enhanced_logging(slist, LOG_DYNAMIC, SECTION_FILECACHE_COMM, "put_return_tag: %s", path);
        if (slist) curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

        // Set a header capture path.
        etag[0] = '\0';
        curl_easy_setopt(session, CURLOPT_HEADERFUNCTION, capture_etag);
        curl_easy_setopt(session, CURLOPT_WRITEHEADER, etag);

        timed_curl_easy_perform(session, &res, &response_code, &elapsed_time);

        fclose(fp);

        if (slist) curl_slist_free_all(slist);

        process_status(funcname, session, res, response_code, elapsed_time, idx, path, false);
    }

    if ((res != CURLE_OK || response_code >= 500) || inject_error(filecache_error_etagcurl1)) {
        trigger_saint_event(CLUSTER_FAILURE);
        set_dynamic_logging();
        g_set_error(gerr, curl_quark(), E_FC_CURLERR, "%s: retry_curl_easy_perform is not CURLE_OK: %s", 
                funcname, curl_easy_strerror(res));
        goto finish;
    }
    else {
        long elapsed_time;
        struct timespec now;
        unsigned long latency;
        unsigned long count;
        const char *sz;

        trigger_saint_event(CLUSTER_SUCCESS);
        log_print(LOG_INFO, SECTION_FILECACHE_COMM, "%s: curl_easy_perform succeeds (fd=%d)", funcname, fd);

        // Ensure that it's a 2xx response code.

        log_print(LOG_INFO, SECTION_FILECACHE_COMM, "%s: Request got HTTP status code %lu", funcname, response_code);
        if (!(response_code >= 200 && response_code < 300) || inject_error(filecache_error_etagcurl2)) {
            // Opening up into the abyss...adding a separate code for a specific error return. Where will it end?
            int curlerr = E_FC_CURLERR;
            if (response_code == 413) curlerr = E_FC_FILETOOLARGE;
            g_set_error(gerr, curl_quark(), curlerr, "%s: retry_curl_easy_perform error response %ld: ",
                funcname, response_code);
            goto finish;
        }

        /* Get the time into now.
         * Subtract seconds since start_time and multiply by 1000 to get ms.
         * Subtract nanoseconds since start_time and divide by a million to get ms.
         * ns count might be negative (now is 3s and 100 million ns, start was 1 sec and 800 million ns.
         * Seconds is now 2 (*1000);
         * ns is now -700 (800 million ns - 100 million ns divided by a million.
         * 2000 - 700 = 1300 ms, or 1s 300ms, which is correct for 3.1 - 1.8)
         */
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_time = ((now.tv_sec - start_time.tv_sec) * 1000) + ((now.tv_nsec - start_time.tv_nsec) / (1000 * 1000));

        if (st.st_size > XLG) {
            TIMING(filecache_put_xlg_timing, elapsed_time);
            BUMP(filecache_put_xlg_count);
            latency = FETCH(filecache_put_xlg_timing);
            count = FETCH(filecache_put_xlg_count);
            sz = "XLG";
            stats_counter("large-puts", 1);
            stats_timer("large-put-latency", elapsed_time);
        }
        else if (st.st_size > LG) {
            TIMING(filecache_put_lg_timing, elapsed_time);
            BUMP(filecache_put_lg_count);
            latency = FETCH(filecache_put_lg_timing);
            count = FETCH(filecache_put_lg_count);
            sz = "LG";
            stats_counter("large-puts", 1);
            stats_timer("large-put-latency", elapsed_time);
         }
        else if (st.st_size > MED) {
            TIMING(filecache_put_med_timing, elapsed_time);
            BUMP(filecache_put_med_count);
            latency = FETCH(filecache_put_med_timing);
            count = FETCH(filecache_put_med_count);
            sz = "MED";
            stats_counter("large-puts", 1);
            stats_timer("large-put-latency", elapsed_time);
        }
        else if (st.st_size > SM) {
            TIMING(filecache_put_sm_timing, elapsed_time);
            BUMP(filecache_put_sm_count);
            latency = FETCH(filecache_put_sm_timing);
            count = FETCH(filecache_put_sm_count);
            sz = "SM";
            stats_counter("small-puts", 1);
            stats_timer("small-put-latency", elapsed_time);
        }
        else if (st.st_size > XSM) {
            TIMING(filecache_put_xsm_timing, elapsed_time);
            BUMP(filecache_put_xsm_count);
            latency = FETCH(filecache_put_xsm_timing);
            count = FETCH(filecache_put_xsm_count);
            sz = "XSM";
            stats_counter("small-puts", 1);
            stats_timer("small-put-latency", elapsed_time);
        }
        else {
            TIMING(filecache_put_xxsm_timing, elapsed_time);
            BUMP(filecache_put_xxsm_count);
            latency = FETCH(filecache_put_xxsm_timing);
            count = FETCH(filecache_put_xxsm_count);
            sz = "XXSM";
            stats_counter("small-puts", 1);
            stats_timer("small-put-latency", elapsed_time);
        }
        log_print(LOG_DEBUG, SECTION_FILECACHE_OPEN, "%s: PUT on size %s (%lu) for %s -- Current:Average latency %lu :: %lu",
            funcname, sz, st.st_size, path, elapsed_time, (latency / count));

        if (st.st_size >= LG && elapsed_time > large_time_allotment) {
            log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "%s: large (%lu) PUT for %s exceeded time allotment %lu with %lu",
                funcname, st.st_size, path, large_time_allotment, elapsed_time);
            stats_counter("exceeded-time-large-PUT-count", 1);
            stats_timer("exceeded-time-large-PUT-latency", elapsed_time);
        }
        else if (st.st_size < LG && elapsed_time > small_time_allotment) {
            log_print(LOG_WARNING, SECTION_FILECACHE_OPEN, "%s: small (%lu) PUT for %s exceeded time allotment %lu with %lu",
                funcname, st.st_size, path, small_time_allotment, elapsed_time);
            stats_counter("exceeded-time-small-PUT-count", 1);
            stats_timer("exceeded-time-small-PUT-latency", elapsed_time);
        }
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "PUT returns etag: %s", etag);

finish:

    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: releasing exclusive file lock on fd %d", funcname, fd);
    if (flock(fd, LOCK_UN) || inject_error(filecache_error_etagflock2)) {
        g_set_error(gerr, system_quark(), errno, "%s: error releasing exclusive file lock", funcname);
    }
    else {
        log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "%s: released exclusive file lock on fd %d", funcname, fd);
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "exit: %s", funcname);

    return;
}

// top-level sync call
bool filecache_sync(filecache_t *cache, const char *path, struct fuse_file_info *info, bool do_put, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;
    struct filecache_pdata *pdata = NULL;
    GError *tmpgerr = NULL;
    bool wrote_data = false;

    BUMP(filecache_sync);

    // We only do the sync if we have a path
    // If we are accessing a bare file descriptor (open/unlink/read|write),
    // path will be NULL, so just return without doing anything
    if (path == NULL) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(NULL path, returning, fd=%d)", sdata? sdata->fd : -1);
        goto finish;
    }
    else {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(%s, fd=%d)", path, sdata? sdata->fd : -1);
    }

    if (sdata == NULL || inject_error(filecache_error_syncsdata)) {
        log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: error on NULL sdata on %s", path);
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_sync: sdata is NULL");
        goto finish;
    }

    // If we already have an error:
    // If we are about to try a PUT, just stop and return. This will cause dav_release to
    // cleanup, sending file to forensic haven.
    // So no need to go ahead and try to process this.
    // However, if we aren't yet doing the PUT, let the sync continue. Eventually, the file
    // will make it to forensic haven
    if (sdata->error_code && do_put) {
        log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: already have previous error on %s", path);
        g_set_error(gerr, filecache_quark(), sdata->error_code, "filecache_sync: sdata indicates previous error");
        goto finish;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_COMM, "filecache_sync: Checking if file (%s) was writable.", path);
    if (!sdata->writable) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: not writable on %s", path);
        goto finish;
    }

    // Write this data to the persistent cache
    // Update the file cache
    pdata = filecache_pdata_get(cache, path, &tmpgerr);
    if (tmpgerr) {
        log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: error on filecache_pdata_get on %s", path);
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: ");
        goto finish;
    }
    if (pdata == NULL || inject_error(filecache_error_syncpdata)) {
        log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: error on pdata NULL on %s", path);
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_sync: pdata is NULL");
        goto finish;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync(%s, fd=%d): cachefile=%s", path, sdata->fd, pdata->filename);

    if (sdata->modified) {
        if (do_put) {
            log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Seeking fd=%d", sdata->fd);
            // If this lseek fails, file eventually goes to forensic haven.
            if ((lseek(sdata->fd, 0, SEEK_SET) == (off_t)-1) || inject_error(filecache_error_synclseek)) {
                set_error(sdata, errno);
                log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: error on lseek on %s", path);
                g_set_error(gerr, system_quark(), errno, "filecache_sync: failed lseek");
                goto finish;
            }

            log_print(LOG_INFO, SECTION_FILECACHE_COMM, "About to PUT file (%s, fd=%d).", path, sdata->fd);

            put_return_etag(path, sdata->fd, pdata->etag, &tmpgerr);

            // if we fail PUT for any reason, file will eventually go to forensic haven.
            // We err in put_return_etag on:
            // -- failure to get flock
            // -- failure on fstat of fd
            // -- retry_curl_easy_perform not CURL_OK
            // -- curl response code not between 200 and 300
            // -- failure to release flock
            if (tmpgerr) {
                /* Outside of calls to fsync itself, we call filecache_sync and PUT the file twice,
                 * once on dav_flush, then closely after on dav_release. If we call set_error on the
                 * first one, we won't attempt the PUT on the second one. In case of cURL error,
                 * don't set_error, so if it fails on the dav_flush, it might still succeed on the
                 * dav_release.
                 * (We call filecache_sync on writes and other times, but with the arg do_put
                 * set to false, so it doesn't do the PUT anyway.)
                 * This is a separate issue from whether or not the file goes to forensic haven.
                 * set_error really means, "If we see an error on write before we ever even attempt
                 * to do the PUT, don't do the PUT." This is different from, "If we fail PUT on dav_flush,
                 * do/don't try the PUT on dav_release."
                 */
                 // Don't set error on cURL error; if dav_flush fails, we can still try again on dav_release
                if (tmpgerr->code != E_FC_CURLERR) set_error(sdata, tmpgerr->code);
                log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: put_return_etag PUT failed on %s", path);
                g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: put_return_etag PUT failed: ");
                goto finish;
            }

            log_print(LOG_INFO, SECTION_FILECACHE_COMM, "filecache_sync: PUT successful: %s : %s : old-timestamp: %lu: etag = %s", path, pdata->filename, pdata->last_server_update, pdata->etag);

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
        wrote_data = true;


        // @REVIEW: If sdata->modified is false, we didn't change pdata, and if
        // we didn't change pdata, why call filecache_pdata_set? Or am I wrong?
        // Point the persistent cache to the new file content.
        filecache_pdata_set(cache, path, pdata, &tmpgerr);
        if (tmpgerr) {
            set_error(sdata, tmpgerr->code);
            log_print(LOG_NOTICE, SECTION_FILECACHE_COMM, "filecache_sync: filecache_pdata_set failed on %s", path);
            g_propagate_prefixed_error(gerr, tmpgerr, "filecache_sync: ");
            goto finish;
        }
    }
    log_print(LOG_INFO, SECTION_FILECACHE_COMM, "filecache_sync: Updated stat cache %d:%s:%s:%lu", sdata->fd, path, pdata->filename, pdata->last_server_update);

finish:

    free(pdata);

    log_print(LOG_DEBUG, SECTION_FILECACHE_COMM, "filecache_sync: Done syncing file (%s, fd=%d).", path, sdata ? sdata->fd : -1);

    return wrote_data;
}

// top-level truncate call
void filecache_truncate(struct fuse_file_info *info, off_t s, GError **gerr) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(filecache_truncate);

    if (sdata == NULL || inject_error(filecache_error_truncsdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_SDATANULL, "filecache_truncate: sdata is NULL");
        return;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_FILE, "filecache_truncate(%d)", sdata->fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_truncate: acquiring shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_SH) || inject_error(filecache_error_truncflock1)) {
        g_set_error(gerr, system_quark(), errno, "filecache_truncate: error acquiring shared file lock");
        return;
    }
    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_truncate: acquired shared file lock on fd %d", sdata->fd);

    if ((ftruncate(sdata->fd, s) < 0) || inject_error(filecache_error_truncftrunc)) {
        g_set_error(gerr, system_quark(), errno, "filecache_truncate: ftruncate failed");
        // fall through to release lock ...
    }

    log_print(LOG_DEBUG, SECTION_FILECACHE_FLOCK, "filecache_truncate: releasing shared file lock on fd %d", sdata->fd);
    if (flock(sdata->fd, LOCK_UN) || inject_error(filecache_error_truncflock2)) {
        if (!gerr) {
            g_set_error(gerr, system_quark(), errno, "filecache_truncate: error releasing shared file lock");
        }
        else {
            log_print(LOG_CRIT, SECTION_FILECACHE_FILE, "filecache_truncate: error releasing shared file lock :: %s", g_strerror(errno));
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

    BUMP(filecache_get_fd);

    log_print(LOG_DEBUG, SECTION_FILECACHE_FILE, "filecache_fd: %d", sdata->fd);
    return sdata->fd;
}

void filecache_set_error(struct fuse_file_info *info, int error_code) {
    struct filecache_sdata *sdata = (struct filecache_sdata *)info->fh;

    BUMP(filecache_set_error);
    set_error(sdata, error_code);
}

// deletes entry from ldb cache
void filecache_delete(filecache_t *cache, const char *path, bool unlink_cachefile, GError **gerr) {
    struct filecache_pdata *pdata;
    leveldb_writeoptions_t *options;
    GError *tmpgerr = NULL;
    char *key;
    char *ldberr = NULL;

    BUMP(filecache_delete);

    log_print(LOG_INFO, SECTION_FILECACHE_CACHE, "filecache_delete: path (%s).", path);

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
            log_print(LOG_WARNING, SECTION_FILECACHE_CACHE, "filecache_delete: error unlinking %s", pdata->filename);
        }
    }

    if (ldberr != NULL || inject_error(filecache_error_deleteldb)) {
        g_set_error(gerr, leveldb_quark(), E_FC_LDBERR, "filecache_delete: leveldb_delete: %s", ldberr ? ldberr : "error-inject");
        free(ldberr);
    }

    free(pdata);

    return;
}

static int clear_files(const char *filecache_path, time_t stamped_time, GError **gerr) {
    const char *fname = "clear_files";
    struct dirent *diriter;
    DIR *dir;
    char cachefile_path[PATH_MAX + 1]; // path to file in the cache
    int ret = 0;
    int visited = 0;
    int unlinked = 0;

    BUMP(filecache_orphans);

    cachefile_path[PATH_MAX] = '\0';

    dir = opendir(filecache_path);
    if (dir == NULL || inject_error(filecache_error_orphanopendir)) {
        g_set_error(gerr, system_quark(), errno, "%s: Can't open filecache directory %s", fname, filecache_path);
        return -1;
    }

    while ((diriter = readdir(dir)) != NULL) {
        struct stat stbuf;
        snprintf(cachefile_path, PATH_MAX , "%s/%s", filecache_path, diriter->d_name) ;
        if (stat(cachefile_path, &stbuf) == -1)
        {
            log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: Unable to stat file: %s: %d %s", 
                    fname, cachefile_path, errno, strerror(errno));
            --ret;
            continue;
        }

        if ((stbuf.st_mode & S_IFMT ) == S_IFDIR) {
            // We don't expect directories, but skip them
            if ((strcmp(diriter->d_name, ".") == 0) || (strcmp(diriter->d_name, "..") == 0)) {
                log_print(LOG_DEBUG, SECTION_FILECACHE_CLEAN, "%s: found . or .. directory: %s", fname, cachefile_path);
            }
            else {
                log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: unexpected directory in filecache: %s", fname, cachefile_path);
                --ret;
            }
        }
        else if ((stbuf.st_mode & S_IFMT ) != S_IFREG) {
            log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: found and ignoring non-regular file: %s", fname, cachefile_path);
            --ret;
        }
        else {
            ++visited;
            if (stbuf.st_mtime < stamped_time) {
                if (unlink(cachefile_path)) {
                    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: failed to unlink %s: %d %s", 
                            fname, cachefile_path, errno, strerror(errno));
                    --ret;
                }
                log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: unlinked %s", fname, cachefile_path);
                ++unlinked;
            }
            else {
                log_print(LOG_INFO, SECTION_FILECACHE_CLEAN, "%s: didn't unlink %s: %d %d", 
                        fname, cachefile_path, stamped_time, stbuf.st_mtime);
            }
        }
    }
    closedir(dir);
    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "%s: visited %d files, unlinked %d, and had %d issues", 
            fname, visited, unlinked, ret);

    // return the number of files still left
    return visited - unlinked;
}

void filecache_forensic_haven(const char *cache_path, filecache_t *cache, const char *path, off_t fsize, GError **gerr) {
    const char *fname = "filecache_forensic_haven";
    struct filecache_pdata *pdata = NULL;
    char *bpath = NULL;
    char *bname;
    char *newpath = NULL;
    GError *subgerr = NULL;
    int fd = -1;
    int files_left = 8;
    const int files_kept = 8;
    int hours = 64;
    char *buf = NULL;
    ssize_t bytes_written;
    bool failed_rename = false;

    BUMP(filecache_forensic_haven);
    log_print(LOG_DYNAMIC, SECTION_FILECACHE_FILE, "%s: cp %s p %s", fname, cache_path, path);

    // Get info from pdata and write to file in forensic haven
    pdata = filecache_pdata_get(cache, path, &subgerr);
    // If there's no pdata, there's no filecache cache file to move to the forensic haven
    if (subgerr) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: error on filecache_pdata_get %s", fname, path);
        g_propagate_prefixed_error(gerr, subgerr, "%s: ", fname);
        goto finish;
    }
    if (pdata == NULL) {
        log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: pdata is NULL %s", fname, path);
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "%s: pdata is NULL on %s", fname, path);
        goto finish;
    }

    // get name of cache file path
    bpath = strdup(pdata->filename);
    // get the base name of the cache file
    bname = basename(bpath);
    // Make a path name for the cache file but in the directory forensic-haven rather than files
    asprintf(&newpath, "%s/%s/%s", cache_path, forensic_haven_dir, bname);
    // Move the file to forensic-haven
    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: doing rename(%s, %s)", fname, pdata->filename, newpath);
    if (rename(pdata->filename, newpath) == -1) {
        log_print(LOG_WARNING, SECTION_FILECACHE_CACHE, "%s: error on rename(%s, %s)", fname, pdata->filename, newpath);
        // If rename fails, put this in the .txt file
        failed_rename = true;
    }
    // do not pass bname to free; basename() does not return a free'able address
    free(newpath);
    newpath = NULL; // reusing below

    // Create the .txt file with information about the cache file we moved
    // It will have the same name as the cache file, with .txt appended
    asprintf(&newpath, "%s/%s/%s.txt", cache_path, forensic_haven_dir, bname);
    free(bpath);
    fd = creat(newpath, 0600);
    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: creat(%s) fd %d", fname, newpath, fd);
    if (fd < 0) {
        log_print(LOG_WARNING, SECTION_FILECACHE_CACHE, "%s: error on creat(%s) fd %d", fname, newpath, fd);
        // Exit; no point in writing a file we couldn't create
        goto finish;
    }

    // Put info into buf that will go into the .txt file
    // Currently path, cache file name, last server update, filesize, and whether the rename above failed
    asprintf(&buf, "path: %s\ncache filename: %s\nlast_server_update: %lu\nfilesize: %lu\nfailed_rename %d\n",
        path, pdata->filename, pdata->last_server_update, fsize, failed_rename);
    bytes_written = write(fd, buf, strlen(buf));
    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: write (%s) of fd %d returns %d", fname, newpath, fd, bytes_written);
    if (bytes_written < 0) {
        log_print(LOG_NOTICE, SECTION_FILECACHE_CACHE, "%s: error on write (%s) of fd %d returns %d", fname, newpath, fd, bytes_written);
        g_set_error(gerr, filecache_quark(), errno, "%s: Failed on write to %s", fname, newpath);
        goto finish;
    }

finish:
    if (fd >= 0) close(fd);
    free(buf);
    free(newpath);
    newpath = NULL;
    free(pdata);
    // Cleanup older entries in the forensic haven
    asprintf(&newpath, "%s/%s/", cache_path, forensic_haven_dir);
    // Clear out all files older than a day
    while (files_left >= files_kept && hours > 0) {
        files_left = clear_files(newpath, time(NULL) - (hours * 60 * 60), &subgerr);
        if (subgerr) {
            log_print(LOG_ERR, SECTION_FILECACHE_FILE, 
                    "%s: error on clear_files: %s -- %d: %s", 
                    fname, subgerr->message, subgerr->code, g_strerror(subgerr->code));
            break;
        }
        hours /= 4;
        log_print(LOG_NOTICE, SECTION_FILECACHE_FILE, 
                "%s: files_left: %d; files_kept: %d; hours: %d", 
                fname, files_left, files_kept, hours);
    }
    free(newpath);
    newpath = NULL;
    log_print(LOG_DEBUG, SECTION_FILECACHE_CACHE, "%s: exiting for %s", fname, path);
}

void filecache_pdata_move(filecache_t *cache, const char *old_path, const char *new_path, GError **gerr) {
    struct filecache_pdata *pdata = NULL;
    GError *tmpgerr = NULL;

    BUMP(filecache_pdata_move);

    pdata = filecache_pdata_get(cache, old_path, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_pdata_move: ");
        return;
    }

    if (pdata == NULL || inject_error(filecache_error_movepdata)) {
        g_set_error(gerr, filecache_quark(), E_FC_PDATANULL, "filecache_pdata_move: Old path %s does not exist.", old_path);
        return;
    }

    log_print(LOG_INFO, SECTION_FILECACHE_FILE, "filecache_pdata_move: Update last_server_update on %s: timestamp: %lu", pdata->filename, pdata->last_server_update);

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

    BUMP(filecache_key2path);

    prefix = strstr(key, filecache_prefix);
    // Looking for "fc:" (filecache_prefix) at the beginning of the key
    if (prefix == key) {
        return key + strlen(filecache_prefix);
    }
    return NULL;
}

void filecache_cleanup(filecache_t *cache, const char *cache_path, bool first, GError **gerr) {
    leveldb_iterator_t *iter = NULL;
    leveldb_readoptions_t *options;
    GError *tmpgerr = NULL;

    char *newpath = NULL;
    size_t klen;
    char fname[PATH_MAX];
    time_t starttime;
    int ret;
    // Statistics
    int cached_files = 0;
    int unlinked_files = 0;
    int issues = 0;
    int pruned_files = 0;

    BUMP(filecache_cleanup);

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
    // Ignore return value, which is files still left in the directory
    asprintf(&newpath, "%s/files", cache_path);
    clear_files(newpath, (starttime - 1), &tmpgerr);
    free(newpath);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "filecache_cleanup: ");
    }

finish:
    log_print(LOG_NOTICE, SECTION_FILECACHE_CLEAN, "filecache_cleanup: visited %d cache entries; unlinked %d, pruned %d, had %d issues",
        cached_files, unlinked_files, pruned_files, issues);
}

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

#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <sys/file.h>
#include <getopt.h>
#include <sys/types.h>
#include <syscall.h>
#include <sys/prctl.h>

#include <grp.h>
#include <pwd.h>

#include <curl/curl.h>

#include <fuse.h>
#include <jemalloc/jemalloc.h>

#include <yaml.h>

#include "log.h"
#include "statcache.h"
#include "ldb-filecache.h"
#include "session.h"
#include "fusedav.h"
#include "props.h"
#include "util.h"

/*
const ne_propname query_properties[] = {
    { "DAV:", "resourcetype" },
    { "http://apache.org/dav/props/", "executable" },
    { "DAV:", "getcontentlength" },
    { "DAV:", "getlastmodified" },
    { "DAV:", "creationdate" },
    { "DAV:", "event" }, // For optional progressive PROPFIND support.
    { NULL, NULL }
};
*/

mode_t mask = 0;
int debug = 1;
struct fuse* fuse = NULL;

#define CLOCK_SKEW 10 // seconds

// Run cache cleanup once a day.
#define CACHE_CLEANUP_INTERVAL 86400

struct fill_info {
    void *buf;
    fuse_fill_dir_t filler;
    const char *root;
};

struct statistics {
    unsigned chmod;
    unsigned chown;
    unsigned create;
    unsigned fsync;
    unsigned flush;
    unsigned ftruncate;
    unsigned fgetattr;
    unsigned getattr;
    unsigned mkdir;
    unsigned mknod;
    unsigned open;
    unsigned read;
    unsigned readdir;
    unsigned release;
    unsigned rename;
    unsigned rmdir;
    unsigned unlink;
    unsigned utimens;
    unsigned write;
};

static struct statistics stats;

#define BUMP(op) __sync_fetch_and_add(&stats.op, 1)
#define FETCH(c) __sync_fetch_and_or(&stats.c, 0)

// Access with struct fusedav_config *config = fuse_get_context()->private_data;
struct fusedav_config {
    char *uri;
    char *username;
    char *password;
    char *ca_certificate;
    char *client_certificate;
    int  verbosity;
    bool nodaemon;
    bool ignoreutimens;
    char *cache_path;
    stat_cache_t *cache;
    struct stat_cache_supplemental cache_supplemental;
    uid_t uid;
    gid_t gid;
    mode_t dir_mode;
    mode_t file_mode;
    char *run_as_uid_name;
    char *run_as_gid_name;
    bool progressive_propfind;
    bool refresh_dir_for_file_stat;
    bool singlethread;
};

enum {
     KEY_HELP,
     KEY_VERSION,
};

#define FUSEDAV_OPT(t, p, v) { t, offsetof(struct fusedav_config, p), v }

static struct fuse_opt fusedav_opts[] = {
     FUSEDAV_OPT("username=%s",                    username, 0),
     FUSEDAV_OPT("password=%s",                    password, 0),
     FUSEDAV_OPT("ca_certificate=%s",              ca_certificate, 0),
     FUSEDAV_OPT("client_certificate=%s",          client_certificate, 0),
     FUSEDAV_OPT("cache_path=%s",                  cache_path, 0),
     FUSEDAV_OPT("verbosity=%d",                   verbosity, 7),
     FUSEDAV_OPT("nodaemon",                       nodaemon, true),
     FUSEDAV_OPT("ignoreutimens",                  ignoreutimens, true),
     FUSEDAV_OPT("uid=%d",                         uid, 0),
     FUSEDAV_OPT("gid=%d",                         gid, 0),
     FUSEDAV_OPT("dir_mode=%o",                    dir_mode, 0),
     FUSEDAV_OPT("file_mode=%o",                   file_mode, 0),
     FUSEDAV_OPT("run_as_uid=%s",                  run_as_uid_name, 0),
     FUSEDAV_OPT("run_as_gid=%s",                  run_as_gid_name, 0),
     FUSEDAV_OPT("progressive_propfind",           progressive_propfind, true),
     FUSEDAV_OPT("refresh_dir_for_file_stat",      refresh_dir_for_file_stat, true),
     FUSEDAV_OPT("singlethread",                   singlethread, true),

     FUSE_OPT_KEY("-V",             KEY_VERSION),
     FUSE_OPT_KEY("--version",      KEY_VERSION),
     FUSE_OPT_KEY("-h",             KEY_HELP),
     FUSE_OPT_KEY("--help",         KEY_HELP),
     FUSE_OPT_KEY("-?",             KEY_HELP),
     FUSE_OPT_END
};

static int get_stat(const char *path, struct stat *stbuf);

static pthread_once_t path_cvt_once = PTHREAD_ONCE_INIT;
static pthread_key_t path_cvt_tsd_key;

static void sigsegv_handler(int signum) {
    assert(signum == 11);
    log_print(LOG_CRIT, "Segmentation fault.");
    signal(signum, SIG_DFL);
    kill(getpid(), signum);
}

static void malloc_stats_output(__unused void *cbopaque, const char *s) {
    char stripped[256];
    size_t len;

    len = strlen(s);
    if (len >= 256) {
        log_print(LOG_NOTICE, "Skipping line over 256 characters.");
        return;
    }

    // Ignore up to one leading space.
    if (s[0] == '\n')
        strncpy(stripped, s + 1, len);
    else
        strncpy(stripped, s, len);

    // Ignore up to two trailing spaces.
    if (stripped[len - 2] == '\n')
        stripped[len - 2] = '\0';
    if (stripped[len - 1] == '\n')
        stripped[len - 1] = '\0';
    stripped[len] = '\0';

    log_print(LOG_NOTICE, "%s", stripped);
}

static void sigusr2_handler(__unused int signum) {
    mallctl("prof.dump", NULL, NULL, NULL, 0);

    log_print(LOG_NOTICE, "Caught SIGUSR2. Printing status.");
    malloc_stats_print(malloc_stats_output, NULL, "");

    log_print(LOG_NOTICE, "Operations:");
    log_print(LOG_NOTICE, "  chmod:       %u", FETCH(chmod));
    log_print(LOG_NOTICE, "  chown:       %u", FETCH(chown));
    log_print(LOG_NOTICE, "  create:      %u", FETCH(create));
    log_print(LOG_NOTICE, "  fsync:       %u", FETCH(fsync));
    log_print(LOG_NOTICE, "  flush:       %u", FETCH(flush));
    log_print(LOG_NOTICE, "  ftruncate:   %u", FETCH(ftruncate));
    log_print(LOG_NOTICE, "  fgetattr:    %u", FETCH(fgetattr));
    log_print(LOG_NOTICE, "  getattr:     %u", FETCH(getattr));
    log_print(LOG_NOTICE, "  mkdir:       %u", FETCH(mkdir));
    log_print(LOG_NOTICE, "  mknod:       %u", FETCH(mknod));
    log_print(LOG_NOTICE, "  open:        %u", FETCH(open));
    log_print(LOG_NOTICE, "  read:        %u", FETCH(read));
    log_print(LOG_NOTICE, "  readdir:     %u", FETCH(readdir));
    log_print(LOG_NOTICE, "  release:     %u", FETCH(release));
    log_print(LOG_NOTICE, "  rename:      %u", FETCH(rename));
    log_print(LOG_NOTICE, "  rmdir:       %u", FETCH(rmdir));
    log_print(LOG_NOTICE, "  unlink:      %u", FETCH(unlink));
    log_print(LOG_NOTICE, "  utimens:     %u", FETCH(utimens));
    log_print(LOG_NOTICE, "  write:       %u", FETCH(write));

    filecache_print_stats();
    stat_cache_print_stats();
}

static void path_cvt_tsd_key_init(void) {
    pthread_key_create(&path_cvt_tsd_key, free);
}

static const char *path_cvt(const char *path) {
    CURL *session;
    char *r, *t;
    int l;

    log_print(LOG_DEBUG, "path_cvt(%s)", path ? path : "null path");

    // Path might be NULL if file was unlinked but file descriptor remains open.
    if (path == NULL)
        return NULL;

    session = session_get_handle();

    pthread_once(&path_cvt_once, path_cvt_tsd_key_init);

    if ((r = pthread_getspecific(path_cvt_tsd_key)))
        curl_free(r);

    asprintf(&t, "%s%s", get_base_url(), path);
    assert(t);
    l = strlen(t);

    if (l > 1 && t[l-1] == '/')
        t[l-1] = 0;

    r = curl_easy_escape(session, t, strlen(t));
    free(t);

    pthread_setspecific(path_cvt_tsd_key, r);

    log_print(LOG_DEBUG, "%s=path_cvt(%s)", r, path);

    return r;
}

static int simple_propfind_with_redirect(
        const char *path,
        int depth,
        props_result_callback result_callback,
        void *userdata) {

    int ret;

    log_print(LOG_DEBUG, "Performing PROPFIND of depth %d on path %s.", depth, path);

    ret = simple_propfind(path, depth, result_callback, userdata);

    log_print(LOG_DEBUG, "Done with PROPFIND.");

    return ret;
}

char *strip_trailing_slash(char *fn, int *is_dir) {
    size_t l = strlen(fn);
    assert(fn);
    assert(is_dir);
    assert(l > 0);

    if ((*is_dir = (fn[l-1] == '/')))
        fn[l-1] = 0;

    return fn;
}

static void getdir_propfind_callback(__unused void *userdata, const char *path, struct stat st, bool exists) {
    char *local_path = NULL;
    //int is_dir = 0;
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;

    local_path = strdup(path);

    // Avoid valgrind warnings
    memset(&value, 0, sizeof(struct stat_cache_value));
    value.st = st;

    //log_print(LOG_DEBUG, "getdir_propfind_callback: %s", path);

    // @TODO: Consider whether the is_dir check here is worth keeping
    // now that we check whether it's a collection.
    //strip_trailing_slash(local_path, &is_dir);

    if (exists) {
        stat_cache_value_set(config->cache, path, &value);
    }
    else {
        log_print(LOG_DEBUG, "Removing path: %s", path);
        stat_cache_delete(config->cache, local_path);
    }

    free(local_path);
}

static void getdir_cache_callback(const char *root, const char *fn, void *user) {
    CURL *session = session_get_handle();
    struct fill_info *f = user;
    char path[PATH_MAX];
    char *h;

    assert(f);

    snprintf(path, sizeof(path), "%s/%s", !strcmp(root, "/") ? "" : root, fn);

    h = curl_easy_unescape(session, fn, strlen(fn), NULL);

    //log_print(LOG_DEBUG, "getdir_cache_callback fn: %s", h);

    f->filler(f->buf, h, NULL, 0);
    curl_free(h);
}

static int update_directory(const char *path, bool attempt_progessive_update) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    bool needs_update = true;
    time_t last_updated;
    time_t timestamp;
    char *update_path = NULL;
    int propfind_result;

    // Attempt to freshen the cache.
    if (attempt_progessive_update && config->progressive_propfind) {
        timestamp = time(NULL);
        last_updated = stat_cache_read_updated_children(config->cache, path);
        asprintf(&update_path, "%s?changes_since=%lu", path, last_updated - CLOCK_SKEW);

        log_print(LOG_DEBUG, "Freshening directory data: %s", update_path);

        propfind_result = simple_propfind_with_redirect(update_path, PROPFIND_DEPTH_ONE, getdir_propfind_callback, NULL);
        if (propfind_result < 0) {
            log_print(LOG_DEBUG, "Freshen PROPFIND success");
            needs_update = false;
        }

        free(update_path);
    }

    // If we had *no data* or freshening failed, rebuild the cache
    // with a full PROPFIND.
    if (needs_update) {
        unsigned int min_generation;

        log_print(LOG_DEBUG, "Replacing directory data: %s", path);
        timestamp = time(NULL);
        min_generation = stat_cache_get_local_generation();
        propfind_result = simple_propfind_with_redirect(path, PROPFIND_DEPTH_ONE, getdir_propfind_callback, NULL);
        if (propfind_result < 0) {
            log_print(LOG_WARNING, "Complete PROPFIND failed on %s", path);
            /* Here's the scenario:
             * mkdir a/b/c/d/e/f/g
             * rmdir a/b/c/d  (with the pre-fixed rmdir, orphans e f g)
             * mkdir a/b/c/d/e/f/g
             * ls a/b/c/d/e/f/g -> Operation not permitted
             *
             * /a/b/c/d gets made, because it didn't exist
             * /a/b/c/d/e doesn't get made, because it's in the cache
             * /a/b/c/d/e/f fails when it tries to update parent by accessing server, and server
             * returns a 404.
             *
             * Calling stat_cache_prune will fix this situation if the stat cache is in an
             * inconsistent internal state (as in the above example). But if it is just a mismatch
             * between cache and server, delete_parent should correct, and put the stat cache in a state
             * where stat_cache_prune can reestablish consistency.
             *
             * We think we have made the fixes necessary to prevent this situation from happening.
             * For now, don't bother making these calls. Leave this in for future reconsideration
             * if we continue to see 404 on PROPFIND.
             *
             * stat_cache_delete_parent(config->cache, path);
             * stat_cache_prune(config->cache);
             */
            return -ENOENT;
        }
        stat_cache_delete_older(config->cache, path, min_generation);
    }

    // Mark the directory contents as updated.
    log_print(LOG_DEBUG, "Marking directory %s as updated at timestamp %lu.", path, timestamp);
    stat_cache_updated_children(config->cache, path, timestamp);
    return 0;
}

static int dav_readdir(
        const char *path,
        void *buf,
        fuse_fill_dir_t filler,
        __unused off_t offset,
        __unused struct fuse_file_info *fi) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    struct fill_info f;
    int ret;

    BUMP(readdir);

    // We might get a null path if we are accessing a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // Since it's a directory name, this is unexpected. While we can imagine
    // a scenario, we won't go out of our way to handle it. Exit with an error.
    if (path == NULL) {
        log_print(LOG_INFO, "CALLBACK: dav_readdir(NULL path)");
        return -1;
    }

    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_readdir(%s)", path);

    f.buf = buf;
    f.filler = filler;
    f.root = path;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // First, attempt to hit the cache.
    ret = stat_cache_enumerate(config->cache, path, getdir_cache_callback, &f, false);
    if (ret < 0) {
        if (debug) {
            if (ret == -STAT_CACHE_OLD_DATA) log_print(LOG_DEBUG, "DIR-CACHE-TOO-OLD: %s", path);
            else log_print(LOG_DEBUG, "DIR-CACHE-MISS: %s", path);
        }

        log_print(LOG_DEBUG, "Updating directory: %s", path);
        if (update_directory(path, (ret == -STAT_CACHE_OLD_DATA)) != 0) {
            log_print(LOG_ERR, "Failed to update directory: %s", path);
            return -1;
        }

        // Output the new data, skipping any cache freshness checks
        // (which should pass, anyway).
        stat_cache_enumerate(config->cache, path, getdir_cache_callback, &f, true);
    }

    return 0;
}

static void getattr_propfind_callback(__unused void *userdata, const char *path, struct stat st, bool exists) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;

    // Avoid valgrind warnings
    memset(&value, 0, sizeof(struct stat_cache_value));
    value.st = st;

    if (exists)
        stat_cache_value_set(config->cache, path, &value);
    // @TODO: Delete if non-existent.
}

static int get_stat(const char *path, struct stat *stbuf) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value *response;
    char *parent_path;
    const char *base_directory;
    char *nepp;
    int is_dir = 0;
    time_t parent_children_update_ts;
    bool is_base_directory;
    int ret = -ENOENT;

    memset(stbuf, 0, sizeof(struct stat));

    log_print(LOG_DEBUG, "get_stat(%s, stbuf)", path);

    base_directory = get_base_url();

    log_print(LOG_DEBUG, "Checking if path %s matches base directory: %s", path, base_directory);
    is_base_directory = (strcmp(path, base_directory) == 0);

    // If it's the root directory and all attributes are specified,
    // construct a response.
    if (is_base_directory && config->dir_mode && config->uid && config->gid) {
        memset(stbuf, 0, sizeof(struct stat));
        stbuf->st_mode = S_IFDIR | config->dir_mode;
        stbuf->st_nlink = 3;
        stbuf->st_uid = config->uid;
        stbuf->st_gid = config->gid;
        stbuf->st_size = 0;
        stbuf->st_blksize = 0;
        stbuf->st_blocks = 0;
        stbuf->st_atime = time(NULL);
        stbuf->st_mtime = stbuf->st_atime;
        stbuf->st_ctime = stbuf->st_mtime;
        log_print(LOG_DEBUG, "Used constructed stat data for base directory.");
        return 0;
    }

    // Check if we can directly hit this entry in the stat cache.
    response = stat_cache_value_get(config->cache, path, false);
    if (response != NULL) {
        *stbuf = response->st;
        free(response);
        //print_stat(stbuf, "get_stat from cache");
        if (stbuf->st_mode == 0) log_print(LOG_DEBUG, "get_stat(%s): 1. returns ENOENT", path);
        else log_print(LOG_DEBUG, "get_stat(%s): 1. returns 0", path);
        return stbuf->st_mode == 0 ? -ENOENT : 0;
    }

    log_print(LOG_DEBUG, "STAT-CACHE-MISS");

    // If it's the root directory, just do a single PROPFIND.
    if (!config->refresh_dir_for_file_stat || strcmp(path, base_directory) == 0) {
        log_print(LOG_DEBUG, "Performing zero-depth PROPFIND on base directory: %s", base_directory);
        // @TODO: Armor this better if the server returns unexpected data.
        if (simple_propfind_with_redirect(path, PROPFIND_DEPTH_ZERO, getattr_propfind_callback, NULL) < 0) {
            stat_cache_delete(config->cache, path);
            log_print(LOG_NOTICE, "PROPFIND failed");
            memset(stbuf, 0, sizeof(struct stat));
            log_print(LOG_DEBUG, "get_stat(%s): 1. returns ENOENT", path);
            return -ENOENT;
        }
        log_print(LOG_DEBUG, "Zero-depth PROPFIND succeeded: %s", base_directory);
        return 0;
    }

    // If we're here, refresh_dir_for_file_stat is set, so we're updating
    // directory stat data to, in turn, update the desired file stat data.

    // If it's not found, check the freshness of its directory.
    nepp = path_parent(path);
    parent_path = strip_trailing_slash(nepp, &is_dir);

    log_print(LOG_DEBUG, "Getting parent path entry: %s", parent_path);
    parent_children_update_ts = stat_cache_read_updated_children(config->cache, parent_path);
    log_print(LOG_DEBUG, "Parent was updated: %s %lu", parent_path, parent_children_update_ts);

    // If the parent directory is out of date, update it.
    if (parent_children_update_ts < (time(NULL) - STAT_CACHE_NEGATIVE_TTL)) {
         ret = update_directory(parent_path, (parent_children_update_ts > 0));

         // If the parent is not on the server, treat the child as not available,
         // regardless of what might be in stat_cache. This likely will prevent
         // the 404's we see when trying to open a file
         if (ret == -ENOENT) {
            log_print(LOG_NOTICE, "parent returns ENOENT: %s", parent_path);

            /* REVIEW: We might also want to ensure the parent and child is not in stat_cache? */
            stat_cache_delete(config->cache, path);
            stat_cache_delete_parent(config->cache, path);
            stat_cache_prune(config->cache);

            // Need some cleanup before returning ...
            free(nepp);
            memset(stbuf, 0, sizeof(struct stat));

            return ret;
        }
        // REVIEW: If ret < 0 but not -ENOENT, what should we do?
    }

    free(nepp);

    // Try again to hit the file in the stat cache.
    if ((response = stat_cache_value_get(config->cache, path, true))) {
        log_print(LOG_DEBUG, "Hit updated cache: %s", path);
        *stbuf = response->st;
        free(response);
        if (stbuf->st_mode == 0) log_print(LOG_DEBUG, "get_stat(%s): 2. returns ENOENT", path);
        else log_print(LOG_DEBUG, "get_stat(%s): 2. returns 0", path);
        return stbuf->st_mode == 0 ? -ENOENT : 0;
    }

    log_print(LOG_DEBUG, "Missed updated cache: %s", path);

    // If it's still not found, return that it doesn't exist.
    memset(stbuf, 0, sizeof(struct stat));
    log_print(LOG_DEBUG, "get_stat(%s): 3. returns ENOENT", path);
    return -ENOENT;
}

static int common_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret;

    assert(info != NULL || path != NULL);

    if (path != NULL) {
        ret = get_stat(path, stbuf);
        if (ret != 0) {
            log_print(LOG_DEBUG, "dav_fgetattr(%s) failed on get_stat; %d %s", path, -ret, strerror(-ret));
            return ret;
        }
        if (S_ISDIR(stbuf->st_mode) && config->dir_mode)
            stbuf->st_mode = S_IFDIR | config->dir_mode;
    }
    else {
        // Fill in generic values
        int fd;
        fd = ldb_filecache_fd(info);
        stbuf->st_mode = 0666 | S_IFREG;
        stbuf->st_nlink = 1;
        stbuf->st_size = lseek(fd, 0, SEEK_END);
        stbuf->st_atime = time(NULL);
        stbuf->st_mtime = stbuf->st_atime;
        stbuf->st_ctime = stbuf->st_atime;
        stbuf->st_blksize = 0;
        stbuf->st_blocks = 8;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        ret = 0;
    }

    // Zero-out unused nanosecond fields.
    stbuf->st_atim.tv_nsec = 0;
    stbuf->st_mtim.tv_nsec = 0;
    stbuf->st_ctim.tv_nsec = 0;

    if (config->uid)
        stbuf->st_uid = config->uid;
    if (config->gid)
        stbuf->st_gid = config->gid;
    if (S_ISREG(stbuf->st_mode) && config->file_mode)
        stbuf->st_mode = S_IFREG | config->file_mode;

    return ret;
}

static int dav_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info) {
    int ret;

    BUMP(fgetattr);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_fgetattr(%s)", path?path:"null path");
    ret = common_getattr(path, stbuf, info);
    log_print(LOG_DEBUG, "Done: dav_fgetattr(%s)", path?path:"null path");

    return ret;
}

static int dav_getattr(const char *path, struct stat *stbuf) {
    int ret;

    BUMP(getattr);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_getattr(%s)", path);
    ret = common_getattr(path, stbuf, NULL);
    log_print(LOG_DEBUG, "Done: dav_getattr(%s)", path);

    return ret;
}

static int dav_unlink(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int r;
    struct stat st;
    CURL *session;
    CURLcode res;

    BUMP(unlink);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_unlink(%s)", path);

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISREG(st.st_mode))
        return -EISDIR;

    if (!(session = session_request_init(path))) {
        log_print(LOG_ERR, "dav_unlink(%s): failed to get request session", path);
        return -EIO;
    }

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "DELETE");

    log_print(LOG_DEBUG, "dav_unlink: calling DELETE on %s", path);
    res = curl_easy_perform(session);
    if(res != CURLE_OK) {
        log_print(LOG_DEBUG, "DELETE failed: %s\n", curl_easy_strerror(res));
        return -EIO;
    }

    log_print(LOG_DEBUG, "dav_unlink: calling ldb_filecache_delete on %s", path);
    if (ldb_filecache_delete(config->cache, path, true)) {
        log_print(LOG_WARNING, "dav_unlink: ldb_filecache_delete failed");
    }

    log_print(LOG_DEBUG, "dav_unlink: calling stat_cache_delete on %s", path);
    stat_cache_delete(config->cache, path);

    return 0;
}

static int dav_rmdir(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char fn[PATH_MAX];
    int ret;
    bool has_child;
    struct stat st;
    CURL *session;
    CURLcode res;

    BUMP(rmdir);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_rmdir(%s)", path);

    ret = get_stat(path, &st);
    if (ret < 0) {
        log_print(LOG_WARNING, "dav_rmdir(%s): failed on get_stat: %d %s", path, ret, strerror(-ret));
        return ret;
    }

    if (!S_ISDIR(st.st_mode)) {
        log_print(LOG_INFO, "dav_rmdir: failed to remove `%s\': Not a directory", path);
        return -ENOTDIR;
    }

    // The slash should force it to find entries in the directory after the slash, and
    // not the directory itself
    snprintf(fn, sizeof(fn), "%s/", path);

    // Check to see if it is empty ...
    // get_stat already called update_directory, which called stat_cache_updated_children
    // so the stat cache should be up to date.
    has_child = stat_cache_dir_has_child(config->cache, path);
    if (has_child) {
        log_print(LOG_INFO, "dav_rmdir: failed to remove `%s\': Directory not empty ", path);
        return -ENOTEMPTY;
    }

    if (!(session = session_request_init(path))) {
        log_print(LOG_WARNING, "dav_rmdir(%s): failed to get session", path);
        return -EIO;
    }

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "DELETE");

    res = curl_easy_perform(session);
    if (res != CURLE_OK) {
        log_print(LOG_ERR, "dav_rmdir(%s): DELETE failed: %s", path, curl_easy_strerror(res));
        return -ENOENT;
    }

    log_print(LOG_DEBUG, "dav_rmdir: removed(%s)", path);

    stat_cache_delete(config->cache, path);

    // Delete Updated_children entry for path
    stat_cache_updated_children(config->cache, path, 0);

    return 0;
}

static int dav_mkdir(const char *path, mode_t mode) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    char fn[PATH_MAX];
    CURL *session;
    CURLcode res;

    BUMP(mkdir);

    path = path_cvt(path);

    // Avoid valgrind warnings
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_INFO, "CALLBACK: dav_mkdir(%s, %04o)", path, mode);

    snprintf(fn, sizeof(fn), "%s/", path);

    if (!(session = session_request_init(fn))) {
        log_print(LOG_ERR, "dav_mkdir(%s): failed to get session", path);
        return -EIO;
    }

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "MKCOL");

    res = curl_easy_perform(session);
    if (res != CURLE_OK) {
        log_print(LOG_ERR, "dav_mkdir(%s): MKCOL failed: %s", path, curl_easy_strerror(res));
        return -ENOENT;
    }

    // Prepopulate stat cache.
    value.st.st_mode = mode | S_IFDIR;
    value.st.st_nlink = 3;
    value.st.st_size = 0;
    value.st.st_atime = time(NULL);
    value.st.st_mtime = value.st.st_atime;
    value.st.st_ctime = value.st.st_mtime;
    value.st.st_blksize = 0;
    value.st.st_blocks = 8;
    value.st.st_uid = getuid();
    value.st.st_gid = getgid();
    value.prepopulated = true;
    stat_cache_value_set(config->cache, path, &value);

    //stat_cache_delete(config->cache, path);
    //stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int dav_rename(const char *from, const char *to) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char *header = NULL;
    CURL *session;
    struct curl_slist *slist = NULL;
    CURLcode res;
    int server_ret = -EIO;
    int local_ret = -EIO;
    int ret;
    int fd = -1;
    struct stat st;
    char fn[PATH_MAX], *_from;
    struct stat_cache_value *entry = NULL;

    BUMP(rename);

    from = _from = strdup(path_cvt(from));
    assert(from);
    to = path_cvt(to);

    log_print(LOG_INFO, "CALLBACK: dav_rename(%s, %s)", from, to);

    if ((ret = get_stat(from, &st)) < 0) {
        log_print(LOG_ERR, "dav_rename: failed get_stat for %d:%s", fd, from);
        server_ret = ret;
        goto finish;
    }

    if (S_ISDIR(st.st_mode)) {
        snprintf(fn, sizeof(fn), "%s/", from);
        from = fn;
    }

    if (!(session = session_request_init(from))) {
        log_print(LOG_ERR, "dav_rename: failed to get session for %d:%s", fd, from);
        goto finish;
    }

    // Add the destination header.
    // @TODO: Check that this is a URL.
    asprintf(&header, "Destination: %s", to);
    slist = curl_slist_append(slist, header);
    free(header);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

    /* ne_move:
     * succeeds: mv 'from' to 'to', delete 'from'
     * fails with 404: may be doing the move on an open file, so this may be ok
     *                 mv 'from' to 'to', delete 'from'
     * fails, not 404: error, exit
     */
    // Do the server side move

    res = curl_easy_perform(session);
    if(res != CURLE_OK) {
        unsigned long response_code;
        curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 404 || response_code == 500) {
            // We allow silent failures because we might have done a rename before the
            // file ever made it to the server
            log_print(LOG_INFO, "dav_rename: MOVE failed with 404, recoverable: %s", curl_easy_strerror(res));
            // Allow the error code -EIO to percolate down, we need to pass the local move
        }
        else {
            log_print(LOG_ERR, "dav_rename: MOVE failed: %s", curl_easy_strerror(res));
            goto finish;
        }
    }
    else {
        server_ret = 0;
    }

    /* If the server_side failed, then both the stat_cache and filecache moves need to succeed */
    entry = stat_cache_value_get(config->cache, from, true);
    log_print(LOG_DEBUG, "dav_rename: stat cache moving source entry to destination %d:%s", fd, to);
    if (entry != NULL && stat_cache_value_set(config->cache, to, entry) < 0) {
        log_print(LOG_NOTICE, "dav_rename: failed stat cache moving source entry to destination %d:%s", fd, to);
        // If the local stat_cache move fails, leave the filecache alone so we don't get mixed state
        goto finish;
    }

    stat_cache_delete(config->cache, from);

    if (ldb_filecache_pdata_move(config->cache, from, to) < 0) {
        log_print(LOG_NOTICE, "dav_rename: No local file cache data to move (or move failed).");
        ldb_filecache_delete(config->cache, to, true);
        goto finish;
    }
    local_ret = 0;

finish:

    log_print(LOG_DEBUG, "Exiting: dav_rename(%s, %s); %d %d", from, to, server_ret, local_ret);

    free(entry);
    free(slist);
    free(_from);

    // if either the server move or the local move succeed, we return
    if (server_ret == 0 || local_ret == 0)
        return 0;
    return server_ret; // error from either get_stat or curl_easy_getinfo
}

static int dav_release(const char *path, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(release);

    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_release: release(%s)", path ? path : "null path");

    // path might be NULL if we are accessing a bare file descriptor. Since
    // pulling the file descriptor is the job of ldb_filecache, we'll have
    // to detect there.
    ret = ldb_filecache_release(config->cache, path, info);
    if (ret < 0) {
        log_print(LOG_ERR, "dav_release: error on ldb_filecache_release: %d::%s", ret, (path ? path : "null path"));
    }

    log_print(LOG_DEBUG, "END: dav_release: release(%s)", (path ? path : "null path"));

    return ret;
}

static int dav_fsync(const char *path, __unused int isdatasync, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(fsync);

    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_fsync(%s)", path ? path : "null path");

    // If path is NULL because we are accessing a bare file descriptor,
    // let ldb_filecache_sync handle it since we need to get the file
    // descriptor there
    ret = ldb_filecache_sync(config->cache, path, info, true);
    if (ret < 0) {
        log_print(LOG_ERR, "dav_fsync: error on ldb_filecache_sync: %d::%s", ret, path ? path : "null path");
    }

    return ret;
}

static int dav_flush(const char *path, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(flush);

    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_flush(%s)", path ? path : "null path");

    // If path is NULL because we are accessing a bare file descriptor,
    // let ldb_filecache_sync handle it since we need to get the file
    // descriptor there
    ret = ldb_filecache_sync(config->cache, path, info, true);
    if (ret < 0) {
        log_print(LOG_ERR, "dav_flush: error on ldb_filecache_sync: %d::%s", ret, path ? path : "null path");
    }

    return ret;
}

static int dav_mknod(const char *path, mode_t mode, __unused dev_t rdev) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;

    BUMP(mknod);

    path = path_cvt(path);

    // Avoid valgrind warnings
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_INFO, "CALLBACK: dav_mknod(%s)", path);

    /*
    if (!(session = session_get(1)))
        return -EIO;

    if (!S_ISREG(mode))
        return -ENOTSUP;

    snprintf(tempfile, sizeof(tempfile), "%s/fusedav-empty-XXXXXX", "/tmp");
    if ((fd = mkstemp(tempfile)) < 0)
        return -errno;

    unlink(tempfile);

    if (ne_put(session, path, fd)) {
        log_print(LOG_ERR, "mknod:PUT failed: %s", ne_get_error(session));
        close(fd);
        return -EACCES;
    }

    log_print(LOG_ERR, "mknod(%s):PUT complete", path); // change back to DEBUG

    close(fd);
    */

    // Prepopulate stat cache.

    value.st.st_mode = mode | S_IFREG;
    value.st.st_nlink = 1;
    value.st.st_size = 0;
    value.st.st_atime = time(NULL);
    value.st.st_mtime = value.st.st_atime;
    value.st.st_ctime = value.st.st_mtime;
    value.st.st_blksize = 0;
    value.st.st_blocks = 8;
    value.st.st_uid = getuid();
    value.st.st_gid = getgid();
    value.prepopulated = true;
    stat_cache_value_set(config->cache, path, &value);

    //stat_cache_delete(config->cache, path);
    //stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int do_open(const char *path, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    assert(info);

    if ((ret = ldb_filecache_open(config->cache_path, config->cache, path, info)) < 0) {
        log_print(LOG_ERR, "do_open: Failed ldb_filecache_open");
        return ret;
    }

    log_print(LOG_DEBUG, "do_open: after ldb_filecache_open");

    return ret;
}


static int dav_open(const char *path, struct fuse_file_info *info) {
    BUMP(open);

    path = path_cvt(path);

    // There are circumstances where we read a write-only file, so if write-only
    // is specified, change to read-write. Otherwise, a read on that file will
    // return an EBADF.
    if (info->flags & O_WRONLY) {
        info->flags &= ~O_WRONLY;
        info->flags |= O_RDWR;
    }

    log_print(LOG_INFO, "CALLBACK: dav_open: open(%s, %x, trunc=%x)", path, info->flags, info->flags & O_TRUNC);
    return do_open(path, info);
}

static int dav_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
    ssize_t bytes_read;

    BUMP(read);

    // We might get a null path if we are reading from a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // In this case we continue to do the read.
    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_read(%s, %lu+%lu)", path ? path : "null path", (unsigned long) offset, (unsigned long) size);

    bytes_read = ldb_filecache_read(info, buf, size, offset);
    if (bytes_read < 0) {
        log_print(LOG_ERR, "dav_read: ldb_filecache_read returns error");
    }

    return bytes_read;
}

static int dav_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ssize_t bytes_written;

    BUMP(write);

    // We might get a null path if we are writing to a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // In this case we continue to do the write, but we skip the sync below
    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_write(%s, %lu+%lu)", path ? path : "null path", (unsigned long) offset, (unsigned long) size);

    bytes_written = ldb_filecache_write(info, buf, size, offset);
    if (bytes_written < 0) {
        log_print(LOG_ERR, "dav_write: ldb_filecache_write returns error");
        goto finish;
    }

    // Let sync handle potential null path
    if (ldb_filecache_sync(config->cache, path, info, false) < 0) {
        log_print(LOG_ERR, "dav_write: ldb_filecache_sync returns error");
        return -EIO;
    }

finish:

   return bytes_written;
}

static int dav_ftruncate(const char *path, off_t size, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(ftruncate);

    path = path_cvt(path);
    log_print(LOG_INFO, "CALLBACK: dav_ftruncate(%s, %lu)", path ? path : "null path", (unsigned long) size);

    if (ldb_filecache_truncate(info, size) < 0) {
        ret = -errno;
        log_print(LOG_ERR, "dav_ftruncate: ldb_filecache_truncate returns error; %d %s", ret, strerror(ret));
        goto finish;
    }

    // Let sync handle a NULL path
    if (ldb_filecache_sync(config->cache, path, info, false) < 0) {
        log_print(LOG_ERR, "dav_ftruncate: ldb_filecache_sync returns error");
        ret = -EIO;
        goto finish;
    }

finish:

    log_print(LOG_DEBUG, "dav_ftruncate: ret=%d", ret);
    return ret;
}

static int dav_utimens(__unused const char *path, __unused const struct timespec tv[2]) {
    BUMP(utimens);
    log_print(LOG_INFO, "CALLBACK: dav_utimens(%s)", path);
    return 0;
}

static int dav_chmod(__unused const char *path, __unused mode_t mode) {
    BUMP(chmod);
    log_print(LOG_INFO, "CALLBACK: dav_chmod(%s, %04o)", path, mode);
    return 0;
}

static int dav_create(const char *path, mode_t mode, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(create);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_create(%s, %04o)", path, mode);

    info->flags |= O_CREAT | O_TRUNC;
    ret = do_open(path, info);

    if (ret < 0)
        return ret;

    // @TODO: Perform a chmod here based on mode.

    if (ldb_filecache_sync(config->cache, path, info, false) < 0) {
        log_print(LOG_ERR, "dav_create: ldb_filecache_sync returns error");
        return -EIO;
    }

    log_print(LOG_DEBUG, "Done: create()");

    return ret;
}

static int dav_chown(__unused const char *path, uid_t u, gid_t g) {
    struct fusedav_config *config = fuse_get_context()->private_data;

    BUMP(chown);

    // If the uid and gid are fixed, there is nothing to chown.
    if (config->uid && config->gid)
        return 0;

    log_print(LOG_ERR, "NOT IMPLEMENTED: chown(%s, %d:%d)", path, u, g);
    return -EPROTONOSUPPORT;
}

/* We need to accommodate the pattern
 * open
 * unlink
 * read/write
 * close
 *
 * We set hard_remove and flag_nullpath_ok, which will refrain from
 * creating fuse_hidden files, but will return NULL for path to dav functions,
 * e.g. read and write. We need to handle this.
 * The list of operations which need to handle NULL paths is:
 *   * read, write, flush, release, fsync, readdir, releasedir,
     * fsyncdir, ftruncate, fgetattr and lock
 * We don't implement releasedir, fsyncdir, and lock.
 */

static struct fuse_operations dav_oper = {
    .fgetattr     = dav_fgetattr,
    .getattr     = dav_getattr,
    .readdir     = dav_readdir,
    .mknod       = dav_mknod,
    .create      = dav_create,
    .mkdir       = dav_mkdir,
    .unlink      = dav_unlink,
    .rmdir       = dav_rmdir,
    .rename      = dav_rename,
    .chmod       = dav_chmod,
    .chown       = dav_chown,
    .ftruncate    = dav_ftruncate,
    .utimens     = dav_utimens,
    .open        = dav_open,
    .read        = dav_read,
    .write       = dav_write,
    .release     = dav_release,
    .fsync       = dav_fsync,
    .flush       = dav_flush,
    .flag_nullpath_ok = 1,
};

static void exit_handler(__unused int sig) {
    static const char m[] = "*** Caught signal ***\n";
    if(fuse != NULL)
        fuse_exit(fuse);
    write(2, m, strlen(m));
}

static void empty_handler(__unused int sig) {}

static int setup_signal_handlers(void) {
    struct sigaction sa;
    sigset_t m;

    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(SIGHUP, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {

        log_print(LOG_CRIT, "Cannot set exit signal handlers: %s", strerror(errno));
        return -1;
    }

    sa.sa_handler = SIG_IGN;

    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        log_print(LOG_CRIT, "Cannot set ignored signals: %s", strerror(errno));
        return -1;
    }

    /* Used to shut down the locking thread */
    sa.sa_handler = empty_handler;

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        log_print(LOG_CRIT, "Cannot set user signals: %s", strerror(errno));
        return -1;
    }

    sigemptyset(&m);
    pthread_sigmask(SIG_BLOCK, &m, &m);
    sigdelset(&m, SIGHUP);
    sigdelset(&m, SIGINT);
    sigdelset(&m, SIGTERM);
    sigaddset(&m, SIGPIPE);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_SETMASK, &m, NULL);

    return 0;
}

static int fusedav_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs) {
    struct fusedav_config *config = data;

    switch (key) {
    case FUSE_OPT_KEY_NONOPT:
        if (!config->uri) {
            config->uri = strdup(arg);
            return 0;
        }
        break;

    case KEY_HELP:
        fprintf(stderr,
                "usage: %s uri mountpoint [options]\n"
                "\n"
                "general options:\n"
                "    -o opt,[opt...]  mount options\n"
                "    -h   --help      print help\n"
                "    -V   --version   print version\n"
                "\n"
                "fusedav mount options:\n"
                "    Authenticating with the server:\n"
                "        -o username=STRING\n"
                "        -o password=STRING\n"
                "        -o ca_certificate=PATH\n"
                "        -o client_certificate=PATH\n"
                "        -o client_certificate_password=STRING\n"
                "    Locking:\n"
                "        -o lock_timeout=NUM\n"
                "        -o lock_on_mount\n"
                "    File and directory attributes:\n"
                "        -o uid=STRING (masks file owner)\n"
                "        -o gid=STRING (masks file group)\n"
                "        -o file_mode=OCTAL (masks file permissions)\n"
                "        -o dir_mode=OCTAL (masks directory permissions)\n"
                "        -o ignoreutimens\n"
                "    Protocol and performance options:\n"
                "        -o progressive_propfind\n"
                "        -o refresh_dir_for_file_stat\n"
                "        -o singlethread\n"
                "    Daemon, logging, and process privilege:\n"
                "        -o verbosity=NUM (use 7 for debug)\n"
                "        -o nodaemon\n"
                "        -o run_as_uid=STRING\n"
                "        -o run_as_gid=STRING (defaults to primary group for run_as_uid)\n"
                "        -o cache_path=STRING\n"
                "\n"
                , outargs->argv[0]);
        fuse_opt_add_arg(outargs, "-ho");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(1);

    case KEY_VERSION:
        fprintf(stderr, "fusedav version %s\n", PACKAGE_VERSION);
        fprintf(stderr, "LevelDB version %d.%d\n", leveldb_major_version(), leveldb_minor_version());
        fprintf(stderr, "%s\n", curl_version());
        //malloc_stats_print(NULL, NULL, "g");
        fuse_opt_add_arg(outargs, "--version");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(0);
    }
    return 1;
}

static int config_privileges(struct fusedav_config *config) {
    if (config->run_as_gid_name != 0) {
        struct group *g = getgrnam(config->run_as_gid_name);
        if (setegid(g->gr_gid) < 0) {
            log_print(LOG_ERR, "Can't drop gid to %d.", g->gr_gid);
            return -1;
        }
        log_print(LOG_DEBUG, "Set egid to %d.", g->gr_gid);
    }

    if (config->run_as_uid_name != 0) {
        struct passwd *u = getpwnam(config->run_as_uid_name);

        // If there's no explict group set, use the user's primary gid.
        if (config->run_as_gid_name == 0) {
            if (setegid(u->pw_gid) < 0) {
                log_print(LOG_ERR, "Can't drop git to %d (which is uid %d's primary gid).", u->pw_gid, u->pw_uid);
                return -1;
            }
            log_print(LOG_DEBUG, "Set egid to %d (which is uid %d's primary gid).", u->pw_gid, u->pw_uid);
        }

        if (seteuid(u->pw_uid) < 0) {
            log_print(LOG_ERR, "Can't drop uid to %d.", u->pw_uid);
            return -1;
        }
        log_print(LOG_DEBUG, "Set euid to %d.", u->pw_uid);
    }

    // Ensure the core is still dumpable.
    prctl(PR_SET_DUMPABLE, 1);

    return 0;
}

static void *cache_cleanup(void *ptr) {
    struct fusedav_config *config = (struct fusedav_config *)ptr;
    bool first = true;

    log_print(LOG_DEBUG, "enter cache_cleanup");

    while (true) {
        // We would like to do cleanup on startup, to resolve issues
        // from errant stat and file caches
        ldb_filecache_cleanup(config->cache, config->cache_path, first);
        first = false;
        stat_cache_prune(config->cache);
        if ((sleep(CACHE_CLEANUP_INTERVAL)) != 0) {
            log_print(LOG_WARNING, "cache_cleanup: sleep interrupted; exiting ...");
            return NULL;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fusedav_config config;
    struct fuse_chan *ch = NULL;
    char *mountpoint = NULL;
    int ret = 1;
    pthread_t filecache_cleanup_thread;
    int fail = 0;

    // Initialize the statistics and configuration.
    memset(&stats, 0, sizeof(struct statistics));
    memset(&config, 0, sizeof(config));

    signal(SIGSEGV, sigsegv_handler);
    signal(SIGUSR2, sigusr2_handler);

    mask = umask(0);
    umask(mask);

    if (setup_signal_handlers() < 0)
        goto finish;

    // default verbosity: LOG_NOTICE
    config.verbosity = 5;

    // Parse options.
    if (fuse_opt_parse(&args, &config, fusedav_opts, fusedav_opt_proc) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse options.");
        goto finish;
    }

    if (session_config_init(config.uri, config.ca_certificate, config.client_certificate) < 0) {
        log_print(LOG_CRIT, "Failed to initialize sessions.");
        goto finish;
    }

    if (fail) {
        goto finish;
    }

    // Apply debug mode.
    log_set_maximum_verbosity(config.verbosity);
    debug = (config.verbosity >= 7);
    log_print(LOG_DEBUG, "Log verbosity: %d.", config.verbosity);
    log_print(LOG_DEBUG, "Parsed options.");

    if (config.ignoreutimens)
        log_print(LOG_DEBUG, "Ignoring utimens requests.");

    if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse the command line.");
        goto finish;
    }

    // fuse_opt_add_arg(&args, "-o atomic_o_trunc");

    log_print(LOG_DEBUG, "Parsed command line.");

    if (!config.uri) {
        log_print(LOG_CRIT, "Missing the required URI argument.");
        goto finish;
    }

    if (!(ch = fuse_mount(mountpoint, &args))) {
        log_print(LOG_CRIT, "Failed to mount FUSE file system.");
        goto finish;
    }
    log_print(LOG_DEBUG, "Mounted the FUSE file system.");

    if (!(fuse = fuse_new(ch, &args, &dav_oper, sizeof(dav_oper), &config))) {
        log_print(LOG_CRIT, "Failed to create FUSE object.");
        goto finish;
    }
    log_print(LOG_DEBUG, "Created the FUSE object.");

    if (config.nodaemon) {
        log_print(LOG_DEBUG, "Running in foreground (skipping daemonization).");
    }
    else {
        log_print(LOG_DEBUG, "Attempting to daemonize.");
        if (fuse_daemonize(/* run in foreground */ 0) < 0) {
            log_print(LOG_CRIT, "Failed to daemonize.");
            goto finish;
        }
    }

    log_print(LOG_DEBUG, "Attempting to configure privileges.");
    if (config_privileges(&config) < 0) {
        log_print(LOG_CRIT, "Failed to configure privileges.");
        goto finish;
    }

    // Ensure directory exists for file content cache.
    if (ldb_filecache_init(config.cache_path) < 0) {
        log_print(LOG_CRIT, "Could not initialize file content cache directory.");
        goto finish;
    }
    log_print(LOG_DEBUG, "Opened ldb file cache.");

    // Open the stat cache.
    if (stat_cache_open(&config.cache, &config.cache_supplemental, config.cache_path) < 0) {
        log_print(LOG_CRIT, "Failed to open the stat cache.");
        config.cache = NULL;
        goto finish;
    }
    log_print(LOG_DEBUG, "Opened stat cache.");

    if (pthread_create(&filecache_cleanup_thread, NULL, cache_cleanup, &config)) {
        log_print(LOG_CRIT, "Failed to create cache cleanup thread.");
        goto finish;
    }

    log_print(LOG_NOTICE, "Startup complete. Entering main FUSE loop.");

    if (config.singlethread) {
        log_print(LOG_DEBUG, "...singlethreaded");
        if (fuse_loop(fuse) < 0) {
            log_print(LOG_CRIT, "Error occurred while trying to enter single-threaded FUSE loop.");
            goto finish;
        }
    }
    else {
        log_print(LOG_DEBUG, "...multi-threaded");
        if (fuse_loop_mt(fuse) < 0) {
            log_print(LOG_CRIT, "Error occurred while trying to enter multi-threaded FUSE loop.");
            goto finish;
        }
    }

    log_print(LOG_NOTICE, "Left main FUSE loop. Shutting down.");

    ret = 0;

finish:
    if (ch != NULL) {
        log_print(LOG_DEBUG, "Unmounting: %s", mountpoint);
        fuse_unmount(mountpoint, ch);
    }
    if (mountpoint != NULL)
        free(mountpoint);

    log_print(LOG_NOTICE, "Unmounted.");

    if (fuse)
        fuse_destroy(fuse);
    log_print(LOG_DEBUG, "Destroyed FUSE object.");

    fuse_opt_free_args(&args);
    log_print(LOG_DEBUG, "Freed arguments.");

    session_config_free();
    log_print(LOG_DEBUG, "Cleaned up session system.");

    if (config.cache != NULL && stat_cache_close(config.cache, config.cache_supplemental) < 0)
        log_print(LOG_ERR, "Failed to close the stat cache.");

    log_print(LOG_NOTICE, "Shutdown was successful. Exiting.");

    return ret;
}

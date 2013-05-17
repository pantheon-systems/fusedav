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
#include "filecache.h"
#include "session.h"
#include "fusedav.h"
#include "props.h"
#include "util.h"

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

#define SAINT_MODE_DURATION 10

pthread_mutex_t last_failure_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_failure = 0;

static bool use_saint_mode(void) {
    struct timespec now;
    bool use_saint;
    clock_gettime(CLOCK_MONOTONIC, &now);
    pthread_mutex_lock(&last_failure_mutex);
    use_saint = (last_failure + SAINT_MODE_DURATION >= now.tv_sec);
    pthread_mutex_unlock(&last_failure_mutex);
    return use_saint;
}

static void set_saint_mode(void) {
    struct timespec now;
    log_print(LOG_WARNING, "Using saint mode for %lu seconds.", SAINT_MODE_DURATION);
    clock_gettime(CLOCK_MONOTONIC, &now);
    pthread_mutex_lock(&last_failure_mutex);
    last_failure = now.tv_sec;
    pthread_mutex_unlock(&last_failure_mutex);
}

// Access with struct fusedav_config *config = fuse_get_context()->private_data;
struct fusedav_config {
    char *uri;
    char *username;
    char *password;
    char *ca_certificate;
    char *client_certificate;
    char *client_certificate_password;
    char *cache_uri;
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
    bool ignorexattr;
    bool singlethread;
    bool grace;
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
     FUSEDAV_OPT("cache_uri=%s",                   cache_uri, 0),
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

     // These options have no effect.
     FUSEDAV_OPT("ignorexattr",                    ignorexattr, true),
     FUSEDAV_OPT("client_certificate_password=%s", client_certificate_password, 0),

     FUSE_OPT_KEY("-V",             KEY_VERSION),
     FUSE_OPT_KEY("--version",      KEY_VERSION),
     FUSE_OPT_KEY("-h",             KEY_HELP),
     FUSE_OPT_KEY("--help",         KEY_HELP),
     FUSE_OPT_KEY("-?",             KEY_HELP),
     FUSE_OPT_END
};

// GError mechanisms
G_DEFINE_QUARK(FUSEDAV, fusedav)

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

static int processed_gerror(const char *prefix, const char *path, GError *gerr) {
    int ret;
    log_print(LOG_ERR, "%s on %s: %s -- %d: %s", prefix, path ? path : "null path", gerr->message, gerr->code, g_strerror(gerr->code));
    ret = -gerr->code;
    g_clear_error(&gerr);
    return ret;
}

static int simple_propfind_with_redirect(
        const char *path,
        int depth,
        time_t last_updated,
        props_result_callback result_callback,
        void *userdata) {

    int ret;

    log_print(LOG_DEBUG, "Performing PROPFIND of depth %d on path %s.", depth, path);

    ret = simple_propfind(path, depth, last_updated, result_callback, userdata);

    log_print(LOG_DEBUG, "Done with PROPFIND.");

    return ret;
}

static void fill_stat_generic(struct stat *st, mode_t mode, bool is_dir, int fd) {
    struct fusedav_config *config = fuse_get_context()->private_data;

    // initialize to 0
    memset(st, 0, sizeof(struct stat));

    log_print(LOG_DEBUG, "fill_stat_generic: Enter");

    if (is_dir) {
        // Our default mode for directories is 0770, for files 0660; use them here if not specified
        if (mode != 0) st->st_mode = mode;
        else if (config->dir_mode) st->st_mode = config->dir_mode;
        else st->st_mode = 0770; // Our "default" dir mode
        st->st_mode |= S_IFDIR;
        // In a POSIX systems, directories with subdirs have nlink = 3; otherwise 2. Just use 3
        st->st_nlink = 3;
        // on local systems, directories seem to have size 4096 when they have few files.
        st->st_size = 4096;
    }
    else {
        if (mode != 0) st->st_mode = mode;
        else if (config->file_mode) st->st_mode = config->file_mode;
        else st->st_mode = 0660; // Our "default" file mode
        st->st_mode |= S_IFREG;
        st->st_nlink = 1;
        // If we are creating a file, size will start at 0.
        st->st_size = 0;
    }
    st->st_atime = time(NULL);
    st->st_mtime = st->st_atime;
    st->st_ctime = st->st_mtime;
    st->st_blksize = 4096;
    st->st_uid = config->uid ? config->uid : getuid();
    st->st_gid = config->gid ? config->gid : getgid();

    if (fd >= 0) {
        st->st_size = lseek(fd, 0, SEEK_END);
        log_print(LOG_DEBUG, "fill_stat_generic: seek: fd = %d : size = %d : %d %s", fd, st->st_size, errno, strerror(errno));
        // Silently overlook error
        if (st->st_size < 0) st->st_size = 0;
    }

    st->st_blocks = (st->st_size+511)/512;

    log_print(LOG_DEBUG, "fill_stat_generic: fd = %d : size = %d", fd, st->st_size);
    log_print(LOG_DEBUG, "Done with fill_stat_generic.");
}

char *strip_trailing_slash(char *fn, int *is_dir) {
    size_t l = strlen(fn);
    assert(fn);
    assert(is_dir);
    assert(l > 0);

    // If the string is length one, it's just a slash. Don't trim it.
    if (l == 1)
        return fn;

    if ((*is_dir = (fn[l-1] == '/')))
        fn[l-1] = 0;

    return fn;
}

static void getdir_propfind_callback(__unused void *userdata, const char *path, struct stat st, unsigned long status_code) {
    //int is_dir = 0;
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    GError *gerr = NULL ;

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));
    value.st = st;

    log_print(LOG_INFO, "getdir_propfind_callback: %s (%lu)", path, status_code);

    if (status_code == 410) {
        log_print(LOG_DEBUG, "Removing path: %s", path);
        stat_cache_delete(config->cache, path, &gerr);
        // @TODO call processed_gerror here because gerr begins here, and is not passed back.
        // But this is not really the right place to call processed_gerror
        if (gerr) {
            processed_gerror("getdir_propfind_callback: ", path, gerr);
            return;
        }
        //stat_cache_prune(config->cache);
    }
    else {
        stat_cache_value_set(config->cache, path, &value, &gerr);
        if (gerr) {
            processed_gerror("getdir_propfind_callback: ", path, gerr);
            return;
        }
    }
}

static void getdir_cache_callback(__unused const char *path_prefix, const char *filename, void *user) {
    struct fill_info *f = user;

    assert(f);

    if (strlen(filename) > 0) {
        log_print(LOG_DEBUG, "getdir_cache_callback path: %s", filename);
        f->filler(f->buf, filename, NULL, 0);
    }
}

static void update_directory(const char *path, bool attempt_progessive_update, GError **gerr) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *tmpgerr = NULL;
    bool needs_update = true;
    time_t last_updated;
    time_t timestamp;
    int propfind_result;

    // Attempt to freshen the cache.
    if (attempt_progessive_update && config->progressive_propfind) {
        timestamp = time(NULL);
        last_updated = stat_cache_read_updated_children(config->cache, path, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "update_directory: ");
            return;
        }
        log_print(LOG_DEBUG, "Freshening directory data: %s", path);

        propfind_result = simple_propfind_with_redirect(path, PROPFIND_DEPTH_ONE, last_updated - CLOCK_SKEW, getdir_propfind_callback, NULL);
        // On true error, we set an error and return, avoiding the complete PROPFIND.
        // On sucess we avoid the complete PROPFIND
        // On ESTALE, we do a complete PROPFIND
        if (propfind_result == 0 && !fusedav_inject_error(0)) {
            log_print(LOG_DEBUG, "Freshen PROPFIND success");
            needs_update = false;
        }
        else if (propfind_result == -ESTALE && !fusedav_inject_error(0)) {
            log_print(LOG_DEBUG, "Freshen PROPFIND failed because of staleness.");
        }
        else {
            g_set_error(gerr, fusedav_quark(), EIO, "update_directory: propfind failed: ");
            return;
        }
    }

    // If we had *no data* or freshening failed, rebuild the cache with a full PROPFIND.
    if (needs_update) {
        unsigned int min_generation;

        // Up log level to NOTICE temporarily to get reports in the logs
        log_print(LOG_NOTICE, "update_directory: Doing complete PROPFIND (attempt_progessive_update=%d): %s", attempt_progessive_update, path);
        timestamp = time(NULL);
        min_generation = stat_cache_get_local_generation();
        propfind_result = simple_propfind_with_redirect(path, PROPFIND_DEPTH_ONE, 0, getdir_propfind_callback, NULL);
        if (propfind_result < 0 || fusedav_inject_error(1)) {
            g_set_error(gerr, fusedav_quark(), EIO, "update_directory: Complete PROPFIND failed on %s", path);
            return;
        }

        stat_cache_delete_older(config->cache, path, min_generation, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "update_directory: ");
            return;
        }
    }

    // Mark the directory contents as updated.
    log_print(LOG_DEBUG, "Marking directory %s as updated at timestamp %lu.", path, timestamp);
    stat_cache_updated_children(config->cache, path, timestamp, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "update_directory: ");
        return;
    }
    return;
}

static int dav_readdir(
        const char *path,
        void *buf,
        fuse_fill_dir_t filler,
        __unused off_t offset,
        __unused struct fuse_file_info *fi) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    struct fill_info f;
    GError *gerr = NULL;
    int ret;
    bool ignore_freshness = false;

    BUMP(readdir);

    // We might get a null path if we are accessing a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // Since it's a directory name, this is unexpected. While we can imagine
    // a scenario, we won't go out of our way to handle it. Exit with an error.
    if (path == NULL) {
        log_print(LOG_INFO, "CALLBACK: dav_readdir(NULL path)");
        return -ENOENT;
    }

    log_print(LOG_INFO, "CALLBACK: dav_readdir(%s)", path);

    f.buf = buf;
    f.filler = filler;
    f.root = path;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // If we are in grace mode, we don't do the freshness check. In this case,
    // stat_cache_enumerate can only return either success, or no data available, which is not really an error
    if (config->grace && use_saint_mode())
        ignore_freshness = true;

    // First, attempt to hit the cache.
    ret = stat_cache_enumerate(config->cache, path, getdir_cache_callback, &f, ignore_freshness);
    if (ret < 0) {
        if (debug) {
            if (ret == -STAT_CACHE_OLD_DATA) log_print(LOG_DEBUG, "DIR-CACHE-TOO-OLD: %s", path);
            else if (ret == -STAT_CACHE_NO_DATA) log_print(LOG_DEBUG, "DIR_CACHE-NO-DATA available: %s", path);
            else log_print(LOG_DEBUG, "DIR-CACHE-MISS: %s", path);
        }

        log_print(LOG_DEBUG, "Updating directory: %s", path);
        update_directory(path, (ret == -STAT_CACHE_OLD_DATA), &gerr);
        if (gerr) {
            if (!config->grace) {
                return processed_gerror("dav_readdir: failed to update directory: ", path, gerr);
            }
            log_print(LOG_WARNING, "Failed to update directory: %s : using grace : %d %s", path, gerr->code, strerror(gerr->code));
            set_saint_mode();
        }

        // Output the new data, skipping any cache freshness checks
        // (which should pass, anyway, unless it's grace mode).
        // At this point, we can only get a zero return, or an empty directory. Let both fall through and return 0
        stat_cache_enumerate(config->cache, path, getdir_cache_callback, &f, true);
    }

    log_print(LOG_DEBUG, "Successful readdir for path: %s", path);
    return 0;
}

static void getattr_propfind_callback(__unused void *userdata, const char *path, struct stat st,
        unsigned long status_code) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    GError *tmpgerr = NULL;

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));
    value.st = st;

    if (status_code == 410) {
        log_print(LOG_DEBUG, "getattr_propfind_callback: Deleting from stat cache: %s", path);
        stat_cache_delete(config->cache, path, &tmpgerr);
        if (tmpgerr) {
            log_print(LOG_WARNING, "getattr_propfind_callback: %s: %s", path, tmpgerr->message);
            return;
        }
    }
    else {
        log_print(LOG_DEBUG, "getattr_propfind_callback: Adding to stat cache: %s", path);
        stat_cache_value_set(config->cache, path, &value, &tmpgerr);
        if (tmpgerr) {
            log_print(LOG_WARNING, "getattr_propfind_callback: %s: %s", path, tmpgerr->message);
            return;
        }
    }
}

static int get_stat_from_cache(const char *path, struct stat *stbuf, bool ignore_freshness, GError **gerr) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value *response;
    GError *tmpgerr = NULL;

    response = stat_cache_value_get(config->cache, path, ignore_freshness, &tmpgerr);

    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "get_stat_from_cache: ");
        memset(stbuf, 0, sizeof(struct stat));
        return -1;
    }

    // REVIEW: @TODO: Grace mode setting ignore_freshness should not result in
    // -ENOENT for cache misses.
    if (response == NULL) {
        log_print(LOG_DEBUG, "NULL response from stat_cache_value_get for path %s.", path);

        if (ignore_freshness) {
            log_print(LOG_DEBUG, "Ignoring freshness and sending -ENOENT for path %s.", path);
            memset(stbuf, 0, sizeof(struct stat));
            g_set_error(gerr, fusedav_quark(), ENOENT, "get_stat_from_cache: ");
            return -1;
        }

        log_print(LOG_DEBUG, "Treating key as absent of expired for path %s.", path);
        return -EKEYEXPIRED;
    }

    log_print(LOG_DEBUG, "Got response from stat_cache_value_get for path %s.", path);
    *stbuf = response->st;
    print_stat(stbuf, "stat_cache_value_get response");
    free(response);
    log_print(LOG_DEBUG, "get_stat_from_cache(%s, stbuf, %d): returns %s", path, ignore_freshness, stbuf->st_mode ? "0" : "ENOENT");
    if (stbuf->st_mode == 0) {
        g_set_error(gerr, fusedav_quark(), ENOENT, "get_stat_from_cache: stbuf mode is 0: ");
        return -1;
    }
    return 0;

}

static void get_stat(const char *path, struct stat *stbuf, GError **gerr) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char *parent_path;
    char *nepp = NULL;
    GError *tmpgerr = NULL;
    int is_dir = 0;
    time_t parent_children_update_ts;
    bool is_base_directory;
    int ret = -ENOENT;
    bool skip_freshness_check = false;

    memset(stbuf, 0, sizeof(struct stat));

    log_print(LOG_DEBUG, "get_stat(%s, stbuf)", path);

    log_print(LOG_DEBUG, "Checking if path %s matches base directory.", path);
    is_base_directory = (strcmp(path, "/") == 0);

    // If it's the root directory and all attributes are specified, construct a response.
    if (is_base_directory && config->dir_mode && config->uid && config->gid) {

        // mode = 0 (unspecified), is_dir = true; fd = -1, irrelevant for dir
        fill_stat_generic(stbuf, 0, true, -1);

        log_print(LOG_DEBUG, "Used constructed stat data for base directory.");
        return;
    }

    if (config->grace && use_saint_mode())
        skip_freshness_check = true;

    // Check if we can directly hit this entry in the stat cache.
    ret = get_stat_from_cache(path, stbuf, skip_freshness_check, &tmpgerr);

    // Propagate the error but let the rest of the logic determine return value
    // Unless we change the logic in get_stat_from_cache, it will return ENONENT
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "get _stat: ");
        return;
    }
    else if (ret == 0) {
        return;
    }
    // else fall through, this would be for EKEYEXPIRED, indicating statcache miss

    log_print(LOG_DEBUG, "STAT-CACHE-MISS");

    // If it's the root directory or refresh_dir_for_file_stat is false,
    // just do a single, zero-depth PROPFIND.
    if (!config->refresh_dir_for_file_stat || is_base_directory) {
        // Not sure that tmpgerr above, if triggered, will exit, so get a new gerr variable
        GError *subgerr = NULL;
        log_print(LOG_DEBUG, "Performing zero-depth PROPFIND on path: %s", path);
        // @TODO: Armor this better if the server returns unexpected data.
        if (simple_propfind_with_redirect(path, PROPFIND_DEPTH_ZERO, 0, getattr_propfind_callback, NULL) < 0) {
            stat_cache_delete(config->cache, path, &subgerr);
            if (subgerr) {
                g_propagate_prefixed_error(gerr, tmpgerr, "get_stat: ");
                goto fail;
            }
            g_set_error(gerr, fusedav_quark(), EIO, "get_stat: PROPFIND failed");
            goto fail;
        }
        log_print(LOG_DEBUG, "Zero-depth PROPFIND succeeded: %s", path);

        get_stat_from_cache(path, stbuf, true, &subgerr);
        if (subgerr) {
            g_propagate_prefixed_error(gerr, subgerr, "get_stat: ");
            goto fail;
        }
        // success (we could just return, but it looks more consistent to goto finish after the goto fails above
        goto finish;
    }

    // If we're here, refresh_dir_for_file_stat is set, so we're updating
    // directory stat data to, in turn, update the desired file stat data.

    nepp = path_parent(path);
    parent_path = strip_trailing_slash(nepp, &is_dir);

    log_print(LOG_DEBUG, "Getting parent path entry: %s", parent_path);
    parent_children_update_ts = stat_cache_read_updated_children(config->cache, parent_path, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "get_stat: ");
        goto fail;
    }
    log_print(LOG_DEBUG, "Parent was updated: %s %lu", parent_path, parent_children_update_ts);

    // If the parent directory is out of date, update it.
    if (parent_children_update_ts < (time(NULL) - STAT_CACHE_NEGATIVE_TTL)) {
        GError *subgerr = NULL;
        // If parent_children_update_ts is 0, there are no entries for updated_children in statcache
        // In that case, skip the progressive propfind and go straight to complete propfind
        update_directory(parent_path, (parent_children_update_ts > 0), &subgerr);
        if (subgerr) {
            // If the error is non-EIO or grace is off, fail.
            if (subgerr->code != EIO || !config->grace) {
                g_propagate_prefixed_error(gerr, subgerr, "get_stat: ");
                goto fail;
            }
            log_print(LOG_WARNING, "get_stat: Attempting recovery with grace from error %s on path %s.", subgerr->message, path);
            g_clear_error(&subgerr);
            set_saint_mode();
        }
    }

    // Try again to hit the file in the stat cache.
    ret = get_stat_from_cache(path, stbuf, true, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "get_stat: ");
        goto fail;
    }
    if (ret == 0) goto finish;

fail:
    memset(stbuf, 0, sizeof(struct stat));

finish:
    free(nepp);
    return;
}

static void common_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *info, GError **gerr) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *tmpgerr = NULL;

    assert(info != NULL || path != NULL);

    if (path != NULL) {
        get_stat(path, stbuf, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "common_getattr: ");
            return;
        }
        // These are taken care of by fill_stat_generic below if path is NULL
        if (S_ISDIR(stbuf->st_mode) && config->dir_mode)
            stbuf->st_mode = S_IFDIR | config->dir_mode;
        if (S_ISREG(stbuf->st_mode) && config->file_mode)
            stbuf->st_mode = S_IFREG | config->file_mode;
        if (config->uid)
            stbuf->st_uid = config->uid;
        if (config->gid)
            stbuf->st_gid = config->gid;
    }
    else {
        int fd = filecache_fd(info);
        log_print(LOG_INFO, "common_getattr(NULL path)");
        // Fill in generic values
        // We can't be a directory if we have a null path
        // mode = 0 (unspecified), is_dir = false; fd to get size
        fill_stat_generic(stbuf, 0, false, fd);
    }

    // Zero-out unused nanosecond fields.
    stbuf->st_atim.tv_nsec = 0;
    stbuf->st_mtim.tv_nsec = 0;
    stbuf->st_ctim.tv_nsec = 0;

    //assert(stbuf->st_mode);

    return;
}

static int dav_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *info) {
    GError *gerr = NULL;

    BUMP(fgetattr);

    log_print(LOG_INFO, "CALLBACK: dav_fgetattr(%s)", path?path:"null path");
    common_getattr(path, stbuf, info, &gerr);
    if (gerr) {
        // Don't print error on ENOENT; that's what get_attr is for
        if (gerr->code == ENOENT) return -gerr->code;
        return processed_gerror("dav_fgetattr: ", path, gerr);
    }
    log_print(LOG_DEBUG, "Done: dav_fgetattr(%s)", path?path:"null path");

    return 0;
}

static int dav_getattr(const char *path, struct stat *stbuf) {
    GError *gerr = NULL;

    BUMP(getattr);

    log_print(LOG_INFO, "CALLBACK: dav_getattr(%s)", path);
    common_getattr(path, stbuf, NULL, &gerr);
    if (gerr) {
        // Don't print error on ENOENT; that's what get_attr is for
        if (gerr->code == ENOENT) return -gerr->code;
        return processed_gerror("dav_getattr: ", path, gerr);
    }
    print_stat(stbuf, "dav_getattr");
    log_print(LOG_DEBUG, "Done: dav_getattr(%s)", path);

    return 0;
}

static int dav_unlink(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat st;
    GError *gerr = NULL;
    CURL *session;
    CURLcode res;

    BUMP(unlink);

    log_print(LOG_INFO, "CALLBACK: dav_unlink(%s)", path);

    get_stat(path, &st, &gerr);
    if (gerr) {
        return processed_gerror("dav_unlink: ", path, gerr);
    }

    if (!S_ISREG(st.st_mode))
        return -EISDIR;

    if (!(session = session_request_init(path, NULL))) {
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

    log_print(LOG_DEBUG, "dav_unlink: calling filecache_delete on %s", path);
    filecache_delete(config->cache, path, true, &gerr);
    if (gerr) {
        return processed_gerror("dav_unlink: ", path, gerr);
    }

    log_print(LOG_DEBUG, "dav_unlink: calling stat_cache_delete on %s", path);
    stat_cache_delete(config->cache, path, &gerr);
    if (gerr) {
        return processed_gerror("dav_unlink: ", path, gerr);
    }

    return 0;
}

static int dav_rmdir(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *gerr = NULL;
    char fn[PATH_MAX];
    bool has_child;
    struct stat st;
    CURL *session;
    CURLcode res;

    BUMP(rmdir);

    log_print(LOG_INFO, "CALLBACK: dav_rmdir(%s)", path);

    get_stat(path, &st, &gerr);
    if (gerr) {
        return processed_gerror("dav_rmdir: ", path, gerr);
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

    if (!(session = session_request_init(fn, NULL))) {
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

    stat_cache_delete(config->cache, path, &gerr);
    if (gerr) {
        return processed_gerror("dav_rmdir: ", path, gerr);
    }

    // Delete Updated_children entry for path
    stat_cache_updated_children(config->cache, path, 0, &gerr);
    if (gerr) {
        return processed_gerror("dav_rmdir: ", path, gerr);
    }

    return 0;
}

static int dav_mkdir(const char *path, mode_t mode) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    char fn[PATH_MAX];
    CURL *session;
    CURLcode res;
    GError *gerr = NULL;

    BUMP(mkdir);

    log_print(LOG_INFO, "CALLBACK: dav_mkdir(%s, %04o)", path, mode);

    snprintf(fn, sizeof(fn), "%s/", path);

    if (!(session = session_request_init(fn, NULL))) {
        log_print(LOG_ERR, "dav_mkdir(%s): failed to get session", path);
        return -EIO;
    }

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "MKCOL");

    res = curl_easy_perform(session);
    if (res != CURLE_OK) {
        log_print(LOG_ERR, "dav_mkdir(%s): MKCOL failed: %s", path, curl_easy_strerror(res));
        return -ENOENT;
    }

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    // Populate stat cache.
    // is_dir = true; fd = -1 (not a regular file)
    fill_stat_generic(&(value.st), mode, true, -1);
    stat_cache_value_set(config->cache, path, &value, &gerr);
    if (gerr) {
        return processed_gerror("dav_mkdir: ", path, gerr);
    }

    return 0;
}

static int dav_rename(const char *from, const char *to) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char *header = NULL;
    CURL *session;
    struct curl_slist *slist = NULL;
    CURLcode res;
    GError *gerr = NULL;
    int server_ret = -EIO;
    int local_ret = -EIO;
    int fd = -1;
    struct stat st;
    char fn[PATH_MAX];
    char *escaped_to;
    struct stat_cache_value *entry = NULL;

    BUMP(rename);

    assert(from);
    assert(to);

    log_print(LOG_INFO, "CALLBACK: dav_rename(%s, %s)", from, to);

    get_stat(from, &st, &gerr);
    if (gerr) {
        server_ret = processed_gerror("dav_rmdir: ", from, gerr);
        goto finish;
    }

    if (S_ISDIR(st.st_mode)) {
        snprintf(fn, sizeof(fn), "%s/", from);
        from = fn;
    }

    if (!(session = session_request_init(from, NULL))) {
        log_print(LOG_ERR, "dav_rename: failed to get session for %d:%s", fd, from);
        goto finish;
    }

    curl_easy_setopt(session, CURLOPT_CUSTOMREQUEST, "MOVE");

    // Add the destination header.
    // @TODO: Better error handling on failure.
    escaped_to = escape_except_slashes(session, to);
    asprintf(&header, "Destination: %s%s", get_base_url(), escaped_to);
    curl_free(escaped_to);
    slist = curl_slist_append(slist, header);
    free(header);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, slist);

    /* move:
     * succeeds: mv 'from' to 'to', delete 'from'
     * fails with 404: may be doing the move on an open file, so this may be ok
     *                 mv 'from' to 'to', delete 'from'
     * fails, not 404: error, exit
     */
    // Do the server side move

    res = curl_easy_perform(session);
    if(res != CURLE_OK) {
        long response_code;
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
    entry = stat_cache_value_get(config->cache, from, true, &gerr);
    if (gerr) {
        local_ret = processed_gerror("dav_rename: ", from, gerr);
        goto finish;
    }

    // No entry means that the "from" file doesn't really exist, at least it has no cache presence
    if (entry == NULL) {
        local_ret = -ENOENT;
        goto finish;
    }

    log_print(LOG_DEBUG, "dav_rename: stat cache moving source entry to destination %d:%s", fd, to);
    stat_cache_value_set(config->cache, to, entry, &gerr);
    if (gerr) {
        local_ret = processed_gerror("dav_rename: ", to, gerr);
        log_print(LOG_NOTICE, "dav_rename: failed stat cache moving source entry to destination %d:%s", fd, to);
        // If the local stat_cache move fails, leave the filecache alone so we don't get mixed state
        goto finish;
    }

    stat_cache_delete(config->cache, from, &gerr);
    if (gerr) {
        local_ret = processed_gerror("dav_rename: ", from, gerr);
        goto finish;
    }

    filecache_pdata_move(config->cache, from, to, &gerr);
    if (gerr) {
        GError *tmpgerr = NULL;
        filecache_delete(config->cache, to, true, &tmpgerr);
        if (tmpgerr) {
            // Don't propagate but do log
            log_print(LOG_NOTICE, "dav_rename: filecache_delete failed %d:%s -- %s", fd, to, tmpgerr->message);
        }
        local_ret = processed_gerror("dav_rename: ", to, gerr);
        goto finish;
    }
    local_ret = 0;

finish:

    log_print(LOG_DEBUG, "Exiting: dav_rename(%s, %s); %d %d", from, to, server_ret, local_ret);

    free(entry);
    free(slist);

    // if either the server move or the local move succeed, we return
    if (server_ret == 0 || local_ret == 0)
        return 0;
    return server_ret; // error from either get_stat or curl_easy_getinfo
}

static int dav_release(const char *path, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *gerr = NULL;
    GError *gerr2 = NULL;

    BUMP(release);

    log_print(LOG_INFO, "CALLBACK: dav_release: release(%s)", path ? path : "null path");

    // path might be NULL if we are accessing a bare file descriptor.
    if (path != NULL) {
        filecache_sync(config->cache, path, info, true, &gerr);
        if (!gerr) {
            struct stat_cache_value value;
            int fd = filecache_fd(info);
            // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
            memset(&value, 0, sizeof(struct stat_cache_value));
            // mode = 0 (unspecified), is_dir = false; fd to get size
            fill_stat_generic(&(value.st), 0, false, fd);
            stat_cache_value_set(config->cache, path, &value, &gerr);
        }
    }

    filecache_close(info, &gerr2);
    if (!gerr && gerr2) {
        g_propagate_error(&gerr, gerr2);
    }

    if (gerr) {
        return processed_gerror("dav_release: ", path, gerr);
    }

    log_print(LOG_DEBUG, "END: dav_release: release(%s)", (path ? path : "null path"));

    return 0;
}

static int dav_fsync(const char *path, __unused int isdatasync, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    GError *gerr = NULL;
    int fd;

    BUMP(fsync);

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_INFO, "CALLBACK: dav_fsync(%s)", path ? path : "null path");

    // If path is NULL because we are accessing a bare file descriptor,
    // let filecache_sync handle it since we need to get the file
    // descriptor there
    filecache_sync(config->cache, path, info, true, &gerr);
    if (gerr) {
        return processed_gerror("dav_fsync: ", path, gerr);
    }

    fd = filecache_fd(info);
    // mode = 0 (unspecified), is_dir = false; fd to get size
    fill_stat_generic(&(value.st), 0, false, fd);
    stat_cache_value_set(config->cache, path, &value, &gerr);
    if (gerr) {
        return processed_gerror("dav_fsync: ", path, gerr);
    }

    return 0;
}

static int dav_flush(const char *path, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *gerr = NULL;

    BUMP(flush);

    log_print(LOG_INFO, "CALLBACK: dav_flush(%s)", path ? path : "null path");

    // path might be NULL because we are accessing a bare file descriptor,
    if (path != NULL) {
        int fd;
        // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
        struct stat_cache_value value;
        memset(&value, 0, sizeof(struct stat_cache_value));

        filecache_sync(config->cache, path, info, true, &gerr);
        if (gerr) {
            return processed_gerror("dav_flush: ", path, gerr);
        }

        fd = filecache_fd(info);
        // mode = 0 (unspecified), is_dir = false; fd to get size
        fill_stat_generic(&(value.st), 0, false, fd);
        stat_cache_value_set(config->cache, path, &value, &gerr);
        if (gerr) {
            return processed_gerror("dav_flush: ", path, gerr);
        }
    }

    return 0;
}

static int dav_mknod(const char *path, mode_t mode, __unused dev_t rdev) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    GError *gerr = NULL;

    BUMP(mknod);

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_INFO, "CALLBACK: dav_mknod(%s)", path);

    // Prepopulate stat cache.
    // is_dir = false, fd = -1, can't set size
    fill_stat_generic(&(value.st), mode, false, -1);
    stat_cache_value_set(config->cache, path, &value, &gerr);
    if (gerr) {
        return processed_gerror("dav_mknod: ", path, gerr);
    }

    return 0;
}

static void do_open(const char *path, struct fuse_file_info *info, GError **gerr) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value *value;
    GError *tmpgerr = NULL;
    bool used_grace;
    unsigned grace_level = 0;

    assert(info);

    if (config->grace) {
        if (use_saint_mode())
            grace_level = 2;
        else
            grace_level = 1;
    }
    filecache_open(config->cache_path, config->cache, path, info, grace_level, &used_grace, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "do_open: ");
        return;
    }

    if (used_grace)
        set_saint_mode();

    /* If we create a new file, fill in a stat and put it in the stat cache.
     * If we aren't creating a new file, perhaps we should be updating some
     * values, but since we haven't been doing it up to now, I leave that
     * as a question for the future.
     */
    // @TODO: Before public release: Lock for concurrency.
    value = stat_cache_value_get(config->cache, path, false, &tmpgerr);
    if (tmpgerr) {
        g_propagate_prefixed_error(gerr, tmpgerr, "do_open: ");
        return;
    }

    if (value == NULL) {
        // Use a stack variable since that's how we do it everywhere else
        struct stat_cache_value nvalue;
        memset(&nvalue, 0, sizeof(struct stat_cache_value));
        // mode = 0 (unspecified), is_dir = false; fd = -1, no need to get size on new file
        fill_stat_generic(&(nvalue.st), 0, false, -1);
        stat_cache_value_set(config->cache, path, &nvalue, &tmpgerr);
        if (tmpgerr) {
            g_propagate_prefixed_error(gerr, tmpgerr, "do_open: ");
            return;
        }
    } else {
        free(value);
    }

    log_print(LOG_DEBUG, "do_open: after filecache_open");

    return;
}


static int dav_open(const char *path, struct fuse_file_info *info) {
    GError *gerr = NULL;
    BUMP(open);

    // There are circumstances where we read a write-only file, so if write-only
    // is specified, change to read-write. Otherwise, a read on that file will
    // return an EBADF.
    if (info->flags & O_WRONLY) {
        info->flags &= ~O_WRONLY;
        info->flags |= O_RDWR;
    }

    log_print(LOG_INFO, "CALLBACK: dav_open: open(%s, %x, trunc=%x)", path, info->flags, info->flags & O_TRUNC);
    do_open(path, info, &gerr);
    if (gerr) {
        int ret = processed_gerror("dav_open: ", path, gerr);
        log_print(LOG_DEBUG, "CALLBACK: dav_open: returns %d", ret);
        return ret;
    }
    return 0;
}

static int dav_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
    ssize_t bytes_read;
    GError *gerr = NULL;

    BUMP(read);

    // We might get a null path if we are reading from a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // In this case we continue to do the read.
    log_print(LOG_INFO, "CALLBACK: dav_read(%s, %lu+%lu)", path ? path : "null path", (unsigned long) offset, (unsigned long) size);

    bytes_read = filecache_read(info, buf, size, offset, &gerr);
    if (gerr) {
        return processed_gerror("dav_read: ", path, gerr);
    }

    if (bytes_read < 0) {
        log_print(LOG_ERR, "dav_read: filecache_read returns error");
    }

    return bytes_read;
}

static int dav_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    GError *gerr = NULL;
    ssize_t bytes_written;
    struct stat_cache_value value;

    BUMP(write);

    // We might get a null path if we are writing to a bare file descriptor
    // (we have unlinked the path but kept the file descriptor open)
    // In this case we continue to do the write, but we skip the sync below

    log_print(LOG_INFO, "CALLBACK: dav_write(%s, %lu+%lu)", path ? path : "null path", (unsigned long) offset, (unsigned long) size);

    bytes_written = filecache_write(info, buf, size, offset, &gerr);
    if (gerr) {
        return processed_gerror("dav_write: ", path, gerr);
    }

    if (bytes_written < 0) {
        log_print(LOG_ERR, "dav_write: filecache_write returns error");
        return bytes_written;
    }

    if (path != NULL) {
        int fd;
        filecache_sync(config->cache, path, info, false, &gerr);
        if (gerr) {
            return processed_gerror("dav_write: ", path, gerr);
        }

        // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
        memset(&value, 0, sizeof(struct stat_cache_value));

        fd = filecache_fd(info);
        // mode = 0 (unspecified), is_dir = false; fd to get size
        fill_stat_generic(&(value.st), 0, false, fd);
        stat_cache_value_set(config->cache, path, &value, &gerr);
        if (gerr) {
            return processed_gerror("dav_write: ", path, gerr);
        }
    }

   return bytes_written;
}

static int dav_ftruncate(const char *path, off_t size, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    GError *gerr = NULL;
    int fd;

    BUMP(ftruncate);

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    log_print(LOG_INFO, "CALLBACK: dav_ftruncate(%s, %lu)", path ? path : "null path", (unsigned long) size);

    filecache_truncate(info, size, &gerr);
    if (gerr) {
        return processed_gerror("dav_ftruncate: ", path, gerr);
    }

    // Let sync handle a NULL path
    filecache_sync(config->cache, path, info, false, &gerr);
    if (gerr) {
        return processed_gerror("dav_ftruncate: ", path, gerr);
    }

    fd = filecache_fd(info);
    // mode = 0 (unspecified), is_dir = false; fd to get size
    fill_stat_generic(&(value.st), 0, false, fd);
    stat_cache_value_set(config->cache, path, &value, &gerr);
    if (gerr) {
        return processed_gerror("dav_ftruncate: ", path, gerr);
    }

    log_print(LOG_DEBUG, "dav_ftruncate: returning");
    return 0;
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
    struct stat_cache_value value;
    GError *gerr = NULL;
    int fd;

    BUMP(create);

    log_print(LOG_INFO, "CALLBACK: dav_create(%s, %04o)", path, mode);

    info->flags |= O_CREAT | O_TRUNC;
    do_open(path, info, &gerr);

    if (gerr) {
        return processed_gerror("dav_create: ", path, gerr);
    }

    // @TODO: Perform a chmod here based on mode.

    filecache_sync(config->cache, path, info, false, &gerr);
    if (gerr) {
        return processed_gerror("dav_create: ", path, gerr);
    }

    // Zero-out structure; some fields we don't populate but want to be 0, e.g. st_atim.tv_nsec
    memset(&value, 0, sizeof(struct stat_cache_value));

    fd = filecache_fd(info);
    // mode = 0 (unspecified), is_dir = false; fd to get size
    fill_stat_generic(&(value.st), 0, false, fd);
    stat_cache_value_set(config->cache, path, &value, &gerr);
    if (gerr) {
        return processed_gerror("dav_create: ", path, gerr);
    }

    log_print(LOG_DEBUG, "Done: create()");

    return 0;
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
                "        -o cache_uri=STRING\n"
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


// error injection routines
// This routine is here because it is easier to update if one adds a new call to <>_inject_error() than if it were in util.c
int fusedav_errors(void) {
    int const inject_errors = 2; // Number of places we call fusedav_inject_error(). Update when changed.
    return inject_errors;
}

static void *cache_cleanup(void *ptr) {
    struct fusedav_config *config = (struct fusedav_config *)ptr;
    GError *gerr = NULL;
    bool first = true;

    log_print(LOG_DEBUG, "enter cache_cleanup");

    while (true) {
        // We would like to do cleanup on startup, to resolve issues
        // from errant stat and file caches
        filecache_cleanup(config->cache, config->cache_path, first, &gerr);
        if (gerr) {
            processed_gerror("cache_cleanup: ", config->cache_path, gerr);
        }
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
    GError *gerr = NULL;
    int ret = 1;
    pthread_t cache_cleanup_thread;
    pthread_t error_injection_thread;

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

    // @TODO: Make configurable.
    config.grace = true;

    if (session_config_init(config.uri, config.ca_certificate, config.client_certificate) < 0) {
        log_print(LOG_CRIT, "Failed to initialize session system.");
        goto finish;
    }

    // Apply debug mode.
    log_init(config.verbosity, get_base_url());
    debug = (config.verbosity >= 7);
    log_print(LOG_DEBUG, "Log verbosity: %d.", config.verbosity);

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

    if (config.cache_uri)
        log_print(LOG_INFO, "Using cache URI: %s", config.cache_uri);

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

    // Error injection mechanism. Should only be run during development.
    if (injecting_errors) {
        if (pthread_create(&error_injection_thread, NULL, inject_error_mechanism, NULL)) {
            log_print(LOG_INFO, "Failed to create error injection thread.");
            goto finish;
        }
    }

    // Ensure directory exists for file content cache.
    filecache_init(config.cache_path, &gerr);
    if (gerr) {
        log_print(LOG_CRIT, "main: %s.", gerr->message);
        goto finish;
    }
    log_print(LOG_DEBUG, "Opened ldb file cache.");

    // Open the stat cache.
    stat_cache_open(&config.cache, &config.cache_supplemental, config.cache_path, &gerr);
    if (gerr) {
        processed_gerror("main: ", config.cache_path, gerr);
        config.cache = NULL;
        goto finish;
    }
    log_print(LOG_DEBUG, "Opened stat cache.");

    if (pthread_create(&cache_cleanup_thread, NULL, cache_cleanup, &config)) {
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

    // We don't capture any errors from stat_cache_close
    stat_cache_close(config.cache, config.cache_supplemental);

    log_print(LOG_NOTICE, "Shutdown was successful. Exiting.");

    return ret;
}

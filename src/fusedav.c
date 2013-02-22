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
#include <attr/xattr.h>
#include <sys/types.h>
#include <syscall.h>
#include <sys/prctl.h>

#include <grp.h>
#include <pwd.h>

#include <ne_request.h>
#include <ne_basic.h>
#include <ne_props.h>
#include <ne_utils.h>
#include <ne_socket.h>
#include <ne_auth.h>
#include <ne_dates.h>
#include <ne_redirect.h>
#include <ne_uri.h>

#include <fuse.h>
#include <jemalloc/jemalloc.h>

#include <yaml.h>

#include "log.h"
#include "statcache.h"
#include "ldb-filecache.h"
#include "session.h"
#include "fusedav.h"

const ne_propname query_properties[] = {
    { "DAV:", "resourcetype" },
    { "http://apache.org/dav/props/", "executable" },
    { "DAV:", "getcontentlength" },
    { "DAV:", "getlastmodified" },
    { "DAV:", "creationdate" },
    { "DAV:", "event" }, // For optional progressive PROPFIND support.
    { NULL, NULL }
};

mode_t mask = 0;
int debug = 1;
struct fuse* fuse = NULL;
ne_lock_store *lock_store = NULL;
struct ne_lock *lock = NULL;
int lock_thread_exit = 0;

#define MIME_XATTR "user.mime_type"

#define MAX_REDIRECTS 10

#define CLOCK_SKEW 10 // seconds

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
    unsigned ftruncate;
    unsigned getattr;
    unsigned getxattr;
    unsigned listxattr;
    unsigned mkdir;
    unsigned mknod;
    unsigned open;
    unsigned read;
    unsigned readdir;
    unsigned release;
    unsigned removexattr;
    unsigned rename;
    unsigned rmdir;
    unsigned setxattr;
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
    char *client_certificate_password;
    int  lock_timeout;
    bool lock_on_mount;
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
     FUSEDAV_OPT("client_certificate_password=%s", client_certificate_password, 0),
     FUSEDAV_OPT("lock_on_mount",                  lock_on_mount, true),
     FUSEDAV_OPT("lock_timeout=%i",                lock_timeout, 60),
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
     FUSEDAV_OPT("ignorexattr",                    ignorexattr, true),
     FUSEDAV_OPT("singlethread",                   singlethread, true),

     FUSE_OPT_KEY("-V",             KEY_VERSION),
     FUSE_OPT_KEY("--version",      KEY_VERSION),
     FUSE_OPT_KEY("-h",             KEY_HELP),
     FUSE_OPT_KEY("--help",         KEY_HELP),
     FUSE_OPT_KEY("-?",             KEY_HELP),
     FUSE_OPT_END
};

static int get_stat(const char *path, struct stat *stbuf);
int file_exists_or_set_null(char **path);

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
    log_print(LOG_NOTICE, "Caught SIGUSR2. Printing status.");
    malloc_stats_print(malloc_stats_output, NULL, "");

    log_print(LOG_NOTICE, "Operations:");
    log_print(LOG_NOTICE, "  chmod:       %u", FETCH(chmod));
    log_print(LOG_NOTICE, "  chown:       %u", FETCH(chown));
    log_print(LOG_NOTICE, "  create:      %u", FETCH(create));
    log_print(LOG_NOTICE, "  fsync:       %u", FETCH(fsync));
    log_print(LOG_NOTICE, "  ftruncate:   %u", FETCH(ftruncate));
    log_print(LOG_NOTICE, "  getattr:     %u", FETCH(getattr));
    log_print(LOG_NOTICE, "  getxattr:    %u", FETCH(getxattr));
    log_print(LOG_NOTICE, "  listxattr:   %u", FETCH(listxattr));
    log_print(LOG_NOTICE, "  mkdir:       %u", FETCH(mkdir));
    log_print(LOG_NOTICE, "  mknod:       %u", FETCH(mknod));
    log_print(LOG_NOTICE, "  open:        %u", FETCH(open));
    log_print(LOG_NOTICE, "  read:        %u", FETCH(read));
    log_print(LOG_NOTICE, "  readdir:     %u", FETCH(readdir));
    log_print(LOG_NOTICE, "  release:     %u", FETCH(release));
    log_print(LOG_NOTICE, "  removexattr: %u", FETCH(removexattr));
    log_print(LOG_NOTICE, "  rename:      %u", FETCH(rename));
    log_print(LOG_NOTICE, "  rmdir:       %u", FETCH(rmdir));
    log_print(LOG_NOTICE, "  setxattr:    %u", FETCH(setxattr));
    log_print(LOG_NOTICE, "  unlink:      %u", FETCH(unlink));
    log_print(LOG_NOTICE, "  utimens:     %u", FETCH(utimens));
    log_print(LOG_NOTICE, "  write:       %u", FETCH(write));
}

static void path_cvt_tsd_key_init(void) {
    pthread_key_create(&path_cvt_tsd_key, free);
}

static const char *path_cvt(const char *path) {
    char *r, *t;
    int l;

    log_print(LOG_DEBUG, "path_cvt(%s)", path);

    pthread_once(&path_cvt_once, path_cvt_tsd_key_init);

    if ((r = pthread_getspecific(path_cvt_tsd_key)))
        free(r);

    t = malloc((l = strlen(base_directory) + strlen(path)) + 1);
    assert(t);
    sprintf(t, "%s%s", base_directory, path);

    if (l > 1 && t[l-1] == '/')
        t[l-1] = 0;

    r = ne_path_escape(t);
    free(t);

    pthread_setspecific(path_cvt_tsd_key, r);

    log_print(LOG_DEBUG, "%s=path_cvt(%s)", r, path);

    return r;
}

static int simple_propfind_with_redirect(
        ne_session *session,
        const char *path,
        int depth,
        const ne_propname *props,
        ne_props_result results,
        void *userdata) {

    int i, ret;

    log_print(LOG_DEBUG, "Performing PROPFIND of depth %d on path %s.", depth, path);

    for (i = 0; i < MAX_REDIRECTS; i++) {
        const ne_uri *u;

        if ((ret = ne_simple_propfind(session, path, depth, props, results, userdata)) != NE_REDIRECT)
            return ret;

        if (!(u = ne_redirect_location(session)))
            break;

        if (!session_is_local(u))
            break;

        log_print(LOG_DEBUG, "REDIRECT FROM '%s' to '%s'", path, u->path);

        path = u->path;
    }

    log_print(LOG_DEBUG, "Done with PROPFIND.");

    return ret;
}

static int proppatch_with_redirect(
        ne_session *session,
        const char *path,
        const ne_proppatch_operation *ops) {

    int i, ret;

    for (i = 0; i < MAX_REDIRECTS; i++) {
        const ne_uri *u;

        if ((ret = ne_proppatch(session, path, ops)) != NE_REDIRECT)
            return ret;

        if (!(u = ne_redirect_location(session)))
            break;

        if (!session_is_local(u))
            break;

        log_print(LOG_DEBUG, "REDIRECT FROM '%s' to '%s'", path, u->path);

        path = u->path;
    }

    return ret;
}


static void fill_stat(struct stat *st, const ne_prop_result_set *results, bool *is_deleted, int is_dir) {
    const char *rt, *e, *gcl, *glm, *cd, *ev;
    const ne_propname resourcetype = { "DAV:", "resourcetype" };
    const ne_propname executable = { "http://apache.org/dav/props/", "executable" };
    const ne_propname getcontentlength = { "DAV:", "getcontentlength" };
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    const ne_propname creationdate = { "DAV:", "creationdate" };
    const ne_propname event = { "DAV:", "event" };

    assert(st && results);

    rt = ne_propset_value(results, &resourcetype);
    e = ne_propset_value(results, &executable);
    gcl = ne_propset_value(results, &getcontentlength);
    glm = ne_propset_value(results, &getlastmodified);
    cd = ne_propset_value(results, &creationdate);

    // If it's a collection, force the type to directory.
    log_print(LOG_DEBUG, "fill_stat: resourcetype=%s", rt);
    if (rt && strstr(rt, "collection")) {
        is_dir = 1;
    }

    if (is_deleted != NULL) {
        ev = ne_propset_value(results, &event);
        if (ev == NULL) {
            *is_deleted = false;
        }
        else {
            log_print(LOG_DEBUG, "DAV:event=%s", ev);
            *is_deleted = (strcmp(ev, "DESTROYED") == 0);
        }
    }

    memset(st, 0, sizeof(struct stat));

    if (is_dir) {
        st->st_mode = S_IFDIR | 0777;
        st->st_nlink = 3;            /* find will ignore this directory if nlin <= and st_size == 0 */
        st->st_size = 4096;
    } else {
        st->st_mode = S_IFREG | (e && (*e == 'T' || *e == 't') ? 0777 : 0666);
        st->st_nlink = 1;
        st->st_size = gcl ? atoll(gcl) : 0;
    }

    st->st_atime = time(NULL);
    st->st_mtime = glm ? ne_rfc1123_parse(glm) : 0;
    st->st_ctime = cd ? ne_iso8601_parse(cd) : 0;

    st->st_blocks = (st->st_size+511)/512;
    /*log_print(LOG_DEBUG, "a: %u; m: %u; c: %u", st->st_atime, st->st_mtime, st->st_ctime);*/

    st->st_mode &= ~mask;

    st->st_uid = getuid();
    st->st_gid = getgid();
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

static void getdir_propfind_callback(__unused void *userdata, const ne_uri *u, const ne_prop_result_set *results) {
    char *path = NULL;
    int is_dir = 0;
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    bool is_deleted;

    path = strdup(u->path);

    //log_print(LOG_DEBUG, "getdir_propfind_callback: %s", path);

    // @TODO: Consider whether the is_dir check here is worth keeping
    // now that we check whether it's a collection.
    strip_trailing_slash(path, &is_dir);

    fill_stat(&value.st, results, &is_deleted, is_dir);
    value.prepopulated = false;

    if (is_deleted) {
        log_print(LOG_DEBUG, "Removing path: %s", path);
        stat_cache_delete(config->cache, path);
    }
    else {
        stat_cache_value_set(config->cache, path, &value);
    }

    free(path);
}

static void getdir_cache_callback(
        const char *root,
        const char *fn,
        void *user) {

    struct fill_info *f = user;
    char path[PATH_MAX];
    char *h;

    assert(f);

    snprintf(path, sizeof(path), "%s/%s", !strcmp(root, "/") ? "" : root, fn);

    h = ne_path_unescape(fn);

    //log_print(LOG_DEBUG, "getdir_cache_callback fn: %s", h);

    f->filler(f->buf, h, NULL, 0);
    free(h);
}

static int update_directory(const char *path, bool attempt_progessive_update) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    bool needs_update = true;
    ne_session *session;
    unsigned int min_generation;
    time_t last_updated;
    time_t timestamp;
    char *update_path = NULL;
    int ne_result;

    if (!(session = session_get(1)))
        return -EIO;

    // Attempt to freshen the cache.
    if (attempt_progessive_update && config->progressive_propfind) {
        timestamp = time(NULL);
        last_updated = stat_cache_read_updated_children(config->cache, path);
        asprintf(&update_path, "%s?changes_since=%lu", path, last_updated - CLOCK_SKEW);

        log_print(LOG_DEBUG, "Freshening directory data: %s", update_path);

        ne_result = simple_propfind_with_redirect(session, update_path, NE_DEPTH_ONE, query_properties, getdir_propfind_callback, NULL);
        if (ne_result == NE_OK) {
            log_print(LOG_DEBUG, "Freshen PROPFIND success");
            needs_update = false;
        }
        else {
            log_print(LOG_DEBUG, "Freshen PROPFIND failed: %s", ne_get_error(session));
        }

        free(update_path);
    }

    // If we had *no data* or freshening failed, rebuild the cache
    // with a full PROPFIND.
    if (needs_update) {
        log_print(LOG_DEBUG, "Replacing directory data: %s", path);
        timestamp = time(NULL);
        min_generation = stat_cache_get_local_generation();
        ne_result = simple_propfind_with_redirect(session, path, NE_DEPTH_ONE, query_properties, getdir_propfind_callback, NULL);
        if (ne_result != NE_OK) {
            log_print(LOG_WARNING, "Complete PROPFIND failed: %s", ne_get_error(session));
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
        __unused ne_off_t offset,
        __unused struct fuse_file_info *fi) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    struct fill_info f;
    int ret;

    BUMP(readdir);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_readdir(%s)", path);

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

static void getattr_propfind_callback(void *userdata, const ne_uri *u, const ne_prop_result_set *results) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat *st = (struct stat*) userdata;
    struct stat_cache_value value;
    char *path;
    int is_dir;

    assert(st);

    path = strdup(u->path);

    strip_trailing_slash(path, &is_dir);

    fill_stat(st, results, NULL, is_dir);

    value.st = *st;
    value.prepopulated = false;
    stat_cache_value_set(config->cache, path, &value);

    free(path);
}

static int get_stat(const char *path, struct stat *stbuf) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    struct stat_cache_value *response;
    char *parent_path;
    char *nepp;
    int is_dir = 0;
    time_t parent_children_update_ts;
    bool is_base_directory;

    memset(stbuf, 0, sizeof(struct stat));

    log_print(LOG_DEBUG, "get_stat(%s, stbuf)", path);

    if (!(session = session_get(1))) {
        memset(stbuf, 0, sizeof(struct stat));
        log_print(LOG_DEBUG, "get_stat(%s): returns EIO", path);
        return -EIO;
    }

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
        if (simple_propfind_with_redirect(session, path, NE_DEPTH_ZERO, query_properties, getattr_propfind_callback, stbuf) != NE_OK) {
            stat_cache_delete(config->cache, path);
            log_print(LOG_NOTICE, "PROPFIND failed: %s", ne_get_error(session));
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
    nepp = ne_path_parent(path);
    parent_path = strip_trailing_slash(nepp, &is_dir);

    log_print(LOG_DEBUG, "Getting parent path entry: %s", parent_path);
    parent_children_update_ts = stat_cache_read_updated_children(config->cache, parent_path);
    log_print(LOG_DEBUG, "Parent was updated: %lu", parent_children_update_ts);

    // If the parent directory is out of date, update it.
    if (parent_children_update_ts < (time(NULL) - STAT_CACHE_NEGATIVE_TTL)) {
        log_print(LOG_DEBUG, "Updating directory: %s", parent_path);
        update_directory(parent_path, (parent_children_update_ts > 0));
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

static int dav_getattr(const char *path, struct stat *stbuf) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int r;

    BUMP(getattr);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: getattr(%s)", path);
    r = get_stat(path, stbuf);

    // Zero-out unused nanosecond fields.
    stbuf->st_atim.tv_nsec = 0;
    stbuf->st_mtim.tv_nsec = 0;
    stbuf->st_ctim.tv_nsec = 0;

    if (config->uid)
        stbuf->st_uid = config->uid;
    if (config->gid)
        stbuf->st_gid = config->gid;
    if (S_ISDIR(stbuf->st_mode) && config->dir_mode)
        stbuf->st_mode = S_IFDIR | config->dir_mode;
    if (S_ISREG(stbuf->st_mode) && config->file_mode)
        stbuf->st_mode = S_IFREG | config->file_mode;

    log_print(LOG_DEBUG, "Done: getattr(%s)", path);

    return r;
}

static int dav_unlink(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int r;
    struct stat st;
    ne_session *session;

    BUMP(unlink);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_unlink(%s)", path);

    if (!(session = session_get(1)))
        return -EIO;

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISREG(st.st_mode))
        return -EISDIR;

    log_print(LOG_DEBUG, "dav_unlink: calling ne_delete on %s", path);
    if (ne_delete(session, path)) {
        log_print(LOG_ERR, "DELETE failed: %s", ne_get_error(session));
        return -ENOENT;
    }

    log_print(LOG_DEBUG, "dav_unlink: calling ldb_filecache_delete on %s", path);
    if (ldb_filecache_delete(config->cache, path)) {
        log_print(LOG_WARNING, "dav_unlink: ldb_filecache_delete failed");
    }

    log_print(LOG_DEBUG, "dav_unlink: calling stat_cache_delete on %s", path);
    stat_cache_delete(config->cache, path);

    return 0;
}

static int dav_rmdir(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char fn[PATH_MAX];
    int r;
    struct stat st;
    ne_session *session;

    BUMP(rmdir);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_rmdir(%s)", path);

    if (!(session = session_get(1)))
        return -EIO;

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISDIR(st.st_mode))
        return -ENOTDIR;

    snprintf(fn, sizeof(fn), "%s/", path);

    if (ne_delete(session, fn)) {
        log_print(LOG_ERR, "DELETE failed: %s", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_delete(config->cache, path);
    stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int dav_mkdir(const char *path, mode_t mode) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    char fn[PATH_MAX];
    ne_session *session;

    BUMP(mkdir);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_mkdir(%s, %04o)", path, mode);

    if (!(session = session_get(1)))
        return -EIO;

    snprintf(fn, sizeof(fn), "%s/", path);

    if (ne_mkcol(session, fn)) {
        log_print(LOG_ERR, "MKCOL failed: %s", ne_get_error(session));
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
    ne_session *session;
    int r = 0;
    int fd;
    struct stat st;
    char fn[PATH_MAX], *_from;
    struct stat_cache_value *entry = NULL;

    BUMP(rename);

    from = _from = strdup(path_cvt(from));
    assert(from);
    to = path_cvt(to);

    log_print(LOG_INFO, "CALLBACK: dav_rename(%s, %s)", from, to);

    fd = ldb_filecache_fd(config->cache, from);
    if (fd < 0) {
        log_print(LOG_DEBUG, "dav_rename: no current cache file for \"%s\": errno: %d, %s", from, errno, strerror(errno));
    }
    else {
        log_print(LOG_DEBUG, "dav_rename: acquiring exclusive file lock on fd %d:%s", fd, from);
        if (flock(fd, LOCK_EX)) {
            log_print(LOG_WARNING, "dav_rename: error acquiring shared file lock on fd %d:%s", fd, from);
        }
        log_print(LOG_DEBUG, "dav_rename: acquired shared file lock on fd %d", fd);
    }

    if (!(session = session_get(1))) {
        r = -EIO;
        log_print(LOG_WARNING, "dav_rename: failed to get session for %d:%s", fd, from);
        goto finish;
    }

    if ((r = get_stat(from, &st)) < 0)
        goto finish;

    if (S_ISDIR(st.st_mode)) {
        snprintf(fn, sizeof(fn), "%s/", from);
        from = fn;
    }

    if (ne_move(session, 1, from, to)) {
        log_print(LOG_WARNING, "dav_rename: MOVE failed: %s", ne_get_error(session));
        r = -ENOENT;
        goto finish;
    }

    entry = stat_cache_value_get(config->cache, from, true);
    log_print(LOG_DEBUG, "dav_rename: stat cache moving source entry to destination %d:%s", fd, to);
    if (entry != NULL && stat_cache_value_set(config->cache, to, entry) < 0) {
        r = -EIO;
        goto finish;
    }
    stat_cache_delete(config->cache, from);

    if (fd < 0 || ldb_filecache_pdata_move(config->cache, from, to) < 0) {
        log_print(LOG_DEBUG, "dav_rename: No local file cache data to move (or move failed).");
        ldb_filecache_delete(config->cache, to);
    }

finish:

    if (entry != NULL)
        free(entry);

    // Also releases lock.
    if (fd > 0) close(fd);

    free(_from);

    return r;
}

static int dav_release(const char *path, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(release);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_release: release(%s)", path);

    if ((ret = ldb_filecache_release(config->cache, path, info)) < 0) {
        log_print(LOG_ERR, "dav_release: error on ldb_filecache_release: %d::%s", ret, path);
    }

    return ret;
}

static int dav_fsync(const char *path, __unused int isdatasync, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(fsync);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_fsync(%s)", path);

    if ((ret = ldb_filecache_sync(config->cache, path, info, true)) < 0) {
        log_print(LOG_ERR, "dav_fsync: error on ldb_filecache_sync: %d::%s", ret, path);
        goto finish;
    }

finish:

    return ret;
}

static int dav_mknod(const char *path, mode_t mode, __unused dev_t rdev) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;

    BUMP(mknod);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_mknod(%s)", path);

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

static int dav_read(const char *path, char *buf, size_t size, ne_off_t offset, struct fuse_file_info *info) {
    ssize_t bytes_read;

    BUMP(read);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_read(%s, %lu+%lu)", path, (unsigned long) offset, (unsigned long) size);

    if ((bytes_read = ldb_filecache_read(info, buf, size, offset)) < 0) {
        log_print(LOG_ERR, "dav_read: ldb_filecache_read returns error");
        goto finish;
    }

finish:

    return bytes_read;
}

static int dav_write(const char *path, const char *buf, size_t size, ne_off_t offset, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ssize_t bytes_written;

    BUMP(write);

    path = path_cvt(path);

    log_print(LOG_INFO, "CALLBACK: dav_write(%s, %lu+%lu)", path, (unsigned long) offset, (unsigned long) size);

    if ((bytes_written = ldb_filecache_write(info, buf, size, offset)) < 0) {
        log_print(LOG_ERR, "dav_write: ldb_filecache_write returns error");
        goto finish;
    }

    if (ldb_filecache_sync(config->cache, path, info, false) < 0) {
        log_print(LOG_ERR, "dav_write: ldb_filecache_sync returns error");
        return -EIO;
    }

finish:

   return bytes_written;
}

static int dav_ftruncate(const char *path, ne_off_t size, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;
    ne_session *session;

    BUMP(ftruncate);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_truncate(%s, %lu)", path, (unsigned long) size);

    if (!(session = session_get(1)))
        ret = -EIO;
        goto finish;

    if (ldb_filecache_truncate(info, size) < 0) {
        ret = -errno;
        goto finish;
    }

    if (ldb_filecache_sync(config->cache, path, info, false) < 0) {
        log_print(LOG_ERR, "dav_ftruncate: ldb_filecache_sync returns error");
        ret = -EIO;
        goto finish;
    }

finish:

    return ret;
}

static int dav_utimens(const char *path, const struct timespec tv[2]) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    ne_proppatch_operation ops[2];
    int r = 0;
    char *date;

    BUMP(utimens);

    if (config->ignoreutimens) {
        //log_print(LOG_DEBUG, "Skipping utimens attribute setting.");
        return r;
    }

    assert(path);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_utimens(%s, %lu, %lu)", path, tv[0].tv_sec, tv[1].tv_sec);

    ops[0].name = &getlastmodified;
    ops[0].type = ne_propset;
    ops[0].value = date = ne_rfc1123_date(tv[1].tv_sec);
    ops[1].name = NULL;

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (proppatch_with_redirect(session, path, ops)) {
        log_print(LOG_ERR, "PROPPATCH failed: %s", ne_get_error(session));
        r = -ENOTSUP;
        goto finish;
    }

    // @TODO: Before public release: Update the stat cache instead.
    stat_cache_delete(config->cache, path);

finish:
    free(date);

    return r;
}

static const char *fix_xattr(const char *name) {
    assert(name);

    if (!strcmp(name, MIME_XATTR))
        return "user.webdav(DAV:;getcontenttype)";

    return name;
}

struct listxattr_info {
    char *list;
    size_t space, size;
};

static int listxattr_iterator(
        void *userdata,
        const ne_propname *pname,
        const char *value,
        __unused const ne_status *status) {

    struct listxattr_info *l = userdata;
    int n;

    assert(l);

    if (!value || !pname)
        return -1;

    if (l->list) {
        n = snprintf(l->list, l->space, "user.webdav(%s;%s)", pname->nspace, pname->name) + 1;

        if (n >= (int) l->space) {
            l->size += l->space;
            l->space = 0;
            return 1;

        } else {
            l->size += n;
            l->space -= n;

            if (l->list)
                l->list += n;

            return 0;
        }
    } else {
        /* Calculate space */

        l->size += strlen(pname->nspace) + strlen(pname->name) + 15;
        return 0;
    }
}

static void listxattr_propfind_callback(void *userdata, __unused const ne_uri *u, const ne_prop_result_set *results) {
    struct listxattr_info *l = userdata;
    ne_propset_iterate(results, listxattr_iterator, l);
}

static int dav_listxattr(
        const char *path,
        char *list,
        size_t size) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    struct listxattr_info l;

    BUMP(listxattr);

    if (config->ignorexattr)
        return 0;

    assert(path);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "listxattr(%s, .., %lu)", path, (unsigned long) size);

    if (list) {
        l.list = list;
        l.space = size-1;
        l.size = 0;

        if (l.space >= sizeof(MIME_XATTR)) {
            memcpy(l.list, MIME_XATTR, sizeof(MIME_XATTR));
            l.list += sizeof(MIME_XATTR);
            l.space -= sizeof(MIME_XATTR);
            l.size += sizeof(MIME_XATTR);
        }

    } else {
        l.list = NULL;
        l.space = 0;
        l.size = sizeof(MIME_XATTR);
    }

    if (!(session = session_get(1)))
        return -EIO;

    if (simple_propfind_with_redirect(session, path, NE_DEPTH_ZERO, NULL, listxattr_propfind_callback, &l) != NE_OK) {
        log_print(LOG_ERR, "PROPFIND failed: %s", ne_get_error(session));
        return -EIO;
    }

    if (l.list) {
        assert(l.space > 0);
        *l.list = 0;
    }

    return l.size+1;
}

struct getxattr_info {
    ne_propname propname;
    char *value;
    size_t space, size;
};

static int getxattr_iterator(
        void *userdata,
        const ne_propname *pname,
        const char *value,
        __unused const ne_status *status) {

    struct getxattr_info *g = userdata;

    assert(g);

    if (!value || !pname)
        return -1;

    if (strcmp(pname->nspace, g->propname.nspace) ||
        strcmp(pname->name, g->propname.name))
        return 0;

    if (g->value) {
        size_t l;

        l = strlen(value);

        if (l > g->space)
            l = g->space;

        memcpy(g->value, value, l);
        g->size = l;
    } else {
        /* Calculate space */

        g->size = strlen(value);
        return 0;
    }

    return 0;
}

static void getxattr_propfind_callback(void *userdata, __unused const ne_uri *u, const ne_prop_result_set *results) {
    struct getxattr_info *g = userdata;
    ne_propset_iterate(results, getxattr_iterator, g);
}

static int parse_xattr(const char *name, char *dnspace, size_t dnspace_length, char *dname, size_t dname_length) {
    char *e;
    size_t k;

    assert(name);
    assert(dnspace);
    assert(dnspace_length);
    assert(dname);
    assert(dname_length);

    if (strncmp(name, "user.webdav(", 12) ||
        name[strlen(name)-1] != ')' ||
        !(e = strchr(name+12, ';')))
        return -1;

    if ((k = strcspn(name+12, ";")) > dnspace_length-1)
        return -1;

    memcpy(dnspace, name+12, k);
    dnspace[k] = 0;

    e++;

    if ((k = strlen(e)) > dname_length-1)
        return -1;

    assert(k > 0);
    k--;

    memcpy(dname, e, k);
    dname[k] = 0;

    return 0;
}

static int dav_getxattr(
        const char *path,
        const char *name,
        char *value,
        size_t size) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    struct getxattr_info g;
    ne_propname props[2];
    char dnspace[128], dname[128];

    BUMP(getxattr);

    if (config->ignorexattr)
        return -ENOATTR;

    assert(path);

    path = path_cvt(path);
    name = fix_xattr(name);

    log_print(LOG_DEBUG, "getxattr(%s, %s, .., %lu)", path, name, (unsigned long) size);

    if (parse_xattr(name, dnspace, sizeof(dnspace), dname, sizeof(dname)) < 0)
        return -ENOATTR;

    props[0].nspace = dnspace;
    props[0].name = dname;
    props[1].nspace = NULL;
    props[1].name = NULL;

    if (value) {
        g.value = value;
        g.space = size;
        g.size = (size_t) -1;
    } else {
        g.value = NULL;
        g.space = 0;
        g.size = (size_t) -1;
    }

    g.propname = props[0];

    if (!(session = session_get(1)))
        return -EIO;

    if (simple_propfind_with_redirect(session, path, NE_DEPTH_ZERO, props, getxattr_propfind_callback, &g) != NE_OK) {
        log_print(LOG_ERR, "PROPFIND failed: %s", ne_get_error(session));
        return -EIO;
    }

    if (g.size == (size_t) -1)
        return -ENOATTR;

    return g.size;
}

static int dav_setxattr(
        const char *path,
        const char *name,
        const char *value,
        size_t size,
        int flags) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    ne_propname propname;
    ne_proppatch_operation ops[2];
    int r = 0;
    char dnspace[128], dname[128];
    char *value_fixed = NULL;

    BUMP(setxattr);

    if (config->ignorexattr)
        return 0;

    assert(path);
    assert(name);
    assert(value);

    path = path_cvt(path);
    name = fix_xattr(name);

    log_print(LOG_DEBUG, "setxattr(%s, %s)", path, name);

    if (flags) {
        r = ENOTSUP;
        goto finish;
    }

    if (parse_xattr(name, dnspace, sizeof(dnspace), dname, sizeof(dname)) < 0) {
        r = -ENOATTR;
        goto finish;
    }

    propname.nspace = dnspace;
    propname.name = dname;

    /* Add trailing NUL byte if required */
    if (!memchr(value, 0, size)) {
        value_fixed = malloc(size+1);
        assert(value_fixed);

        memcpy(value_fixed, value, size);
        value_fixed[size] = 0;

        value = value_fixed;
    }

    ops[0].name = &propname;
    ops[0].type = ne_propset;
    ops[0].value = value;

    ops[1].name = NULL;

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (proppatch_with_redirect(session, path, ops)) {
        log_print(LOG_ERR, "PROPPATCH failed: %s", ne_get_error(session));
        r = -ENOTSUP;
        goto finish;
    }

    stat_cache_delete(config->cache, path);

finish:
    free(value_fixed);

    return r;
}

static int dav_removexattr(const char *path, const char *name) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    ne_propname propname;
    ne_proppatch_operation ops[2];
    int r = 0;
    char dnspace[128], dname[128];

    BUMP(removexattr);

    if (config->ignorexattr)
        return 0;

    assert(path);
    assert(name);

    path = path_cvt(path);
    name = fix_xattr(name);

    log_print(LOG_DEBUG, "removexattr(%s, %s)", path, name);

    if (parse_xattr(name, dnspace, sizeof(dnspace), dname, sizeof(dname)) < 0) {
        r = -ENOATTR;
        goto finish;
    }

    propname.nspace = dnspace;
    propname.name = dname;

    ops[0].name = &propname;
    ops[0].type = ne_propremove;
    ops[0].value = NULL;

    ops[1].name = NULL;

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (proppatch_with_redirect(session, path, ops)) {
        log_print(LOG_ERR, "PROPPATCH failed: %s", ne_get_error(session));
        r = -ENOTSUP;
        goto finish;
    }

    stat_cache_delete(config->cache, path);

finish:

    return r;
}

static int dav_chmod(const char *path, mode_t mode) {
    ne_session *session;
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value *value;
    const ne_propname executable = { "http://apache.org/dav/props/", "executable" };
    ne_proppatch_operation ops[2];
    int r = 0;

    BUMP(chmod);

    // If both file and dir modes are fixed, there is nothing to set.
    if (config->file_mode && config->dir_mode)
        return 0;

    assert(path);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "chmod(%s, %04o)", path, mode);

    ops[0].name = &executable;
    ops[0].type = ne_propset;
    ops[0].value = mode & 0111 ? "T" : "F";
    ops[1].name = NULL;

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (proppatch_with_redirect(session, path, ops)) {
        log_print(LOG_ERR, "PROPPATCH failed: %s", ne_get_error(session));
        r = -ENOTSUP;
        goto finish;
    }

    // @TODO: Before public release: Lock for concurrency.
    value = stat_cache_value_get(config->cache, path, true);
    if (value != NULL) {
        value->st.st_mode = mode;
        stat_cache_value_set(config->cache, path, value);
        free(value);
    }

finish:

    return r;
}

static int dav_create(const char *path, mode_t mode, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int ret = 0;

    BUMP(create);

    path = path_cvt(path);

    log_print(LOG_DEBUG, "CALLBACK: dav_create(%s, %04o)", path, mode);

    info->flags |= O_CREAT | O_TRUNC;
    ret = do_open(path, info);

    if (ret < 0)
        return ret;

    ret = dav_chmod(path, mode);

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

static struct fuse_operations dav_oper = {
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
    //.truncate    = dav_truncate,
    .utimens     = dav_utimens,
    .open        = dav_open,
    .read        = dav_read,
    .write       = dav_write,
    .release     = dav_release,
    .fsync       = dav_fsync,
    .setxattr    = dav_setxattr,
    .getxattr    = dav_getxattr,
    .listxattr   = dav_listxattr,
    .removexattr = dav_removexattr,
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

static int create_lock(int lock_timeout) {
    ne_session *session;
    char _owner[64], *owner;
    int i;
    int ret;

    lock = ne_lock_create();
    assert(lock);

    if (!(session = session_get(0)))
        return -1;

    if (!(owner = username))
        if (!(owner = getenv("USER")))
            if (!(owner = getenv("LOGNAME"))) {
                snprintf(_owner, sizeof(_owner), "%lu", (unsigned long) getuid());
                owner = owner;
            }

    ne_fill_server_uri(session, &lock->uri);

    lock->uri.path = strdup(base_directory);
    lock->depth = NE_DEPTH_INFINITE;
    lock->timeout = lock_timeout;
    lock->owner = strdup(owner);

    log_print(LOG_DEBUG, "Acquiring lock...");

    for (i = 0; i < MAX_REDIRECTS; i++) {
        const ne_uri *u;

        if ((ret = ne_lock(session, lock)) != NE_REDIRECT)
            break;

        if (!(u = ne_redirect_location(session)))
            break;

        if (!session_is_local(u))
            break;

        log_print(LOG_DEBUG, "REDIRECT FROM '%s' to '%s'", lock->uri.path, u->path);

        free(lock->uri.path);
        lock->uri.path = strdup(u->path);
    }

    if (ret) {
        log_print(LOG_ERR, "LOCK failed: %s", ne_get_error(session));
        ne_lock_destroy(lock);
        lock = NULL;
        return -1;
    }

    lock_store = ne_lockstore_create();
    assert(lock_store);

    ne_lockstore_add(lock_store, lock);

    return 0;
}

static int remove_lock(void) {
    ne_session *session;

    assert(lock);

    if (!(session = session_get(0)))
        return -1;

    log_print(LOG_DEBUG, "Removing lock...");

    if (ne_unlock(session, lock)) {
        log_print(LOG_ERR, "UNLOCK failed: %s", ne_get_error(session));
        return -1;
    }

    return 0;
}

static void *lock_thread_func(void *p) {
    struct fusedav_config *conf = p;
    ne_session *session;
    sigset_t block;

    log_print(LOG_DEBUG, "lock_thread entering");

    if (!(session = session_get(1)))
        return NULL;

    sigemptyset(&block);
    sigaddset(&block, SIGUSR1);

    assert(lock);

    while (!lock_thread_exit) {
        int r, t;

        lock->timeout = conf->lock_timeout;

        pthread_sigmask(SIG_BLOCK, &block, NULL);
        r = ne_lock_refresh(session, lock);
        pthread_sigmask(SIG_UNBLOCK, &block, NULL);

        if (r) {
            log_print(LOG_ERR, "LOCK refresh failed: %s", ne_get_error(session));
            break;
        }

        if (lock_thread_exit)
            break;

        t = conf->lock_timeout/2;
        if (t <= 0)
            t = 1;
        sleep(t);
    }

    log_print(LOG_DEBUG, "lock_thread exiting");

    return NULL;
}

int file_exists_or_set_null(char **path) {
    FILE *file;

    if ((file = fopen(*path, "r"))) {
        fclose(file);
        log_print(LOG_DEBUG, "file_exists_or_set_null(%s): found", *path);
        return 0;
    }
    free(*path);
    *path = NULL;
    log_print(LOG_DEBUG, "file_exists_or_set_null(%s): not found", *path);
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
                "        -o ignorexattr\n"
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

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fusedav_config config;
    struct fuse_chan *ch = NULL;
    char *mountpoint = NULL;
    int ret = 1;
    pthread_t lock_thread;
    int lock_thread_running = 0;
    int fail = 0;

    // Initialize the statistics.
    memset(&stats, 0, sizeof(struct statistics));

    signal(SIGSEGV, sigsegv_handler);
    signal(SIGUSR2, sigusr2_handler);

    if (ne_sock_init()) {
        log_print(LOG_CRIT, "Failed to set libneon thread-safety locks.");
        ++fail;
    }

    if (!ne_has_support(NE_FEATURE_SSL)) {
        log_print(LOG_CRIT, "fusedav requires libneon built with SSL.");
        ++fail;
    }

    if (!ne_has_support(NE_FEATURE_TS_SSL)) {
        log_print(LOG_CRIT, "fusedav requires libneon built with TS_SSL.");
        ++fail;
    }

    mask = umask(0);
    umask(mask);

    if (setup_signal_handlers() < 0)
        goto finish;

    memset(&config, 0, sizeof(config));
    // default verbosity: LOG_NOTICE
    config.verbosity = 5;

    // Parse options.
    if (!fuse_opt_parse(&args, &config, fusedav_opts, fusedav_opt_proc) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse options.");
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

    if (config.ignorexattr)
        log_print(LOG_DEBUG, "Ignoring extended attributes.");

    if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse the command line.");
        goto finish;
    }

    //fuse_opt_add_arg(&args, "-o atomic_o_trunc");

    log_print(LOG_DEBUG, "Parsed command line.");

    if (!config.uri) {
        log_print(LOG_CRIT, "Missing the required URI argument.");
        goto finish;
    }

    if (session_set_uri(config.uri, config.username, config.password, config.client_certificate, config.ca_certificate) < 0) {
        log_print(LOG_CRIT, "Failed to initialize the session URI.");
        goto finish;
    }
    log_print(LOG_DEBUG, "Set session URI and configuration.");

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

    if (config.lock_on_mount && create_lock(config.lock_timeout) >= 0) {
        int r;
        if ((r = pthread_create(&lock_thread, NULL, lock_thread_func, &config)) < 0) {
            log_print(LOG_CRIT, "pthread_create(): %s", strerror(r));
            goto finish;
        }

        lock_thread_running = 1;
        log_print(LOG_DEBUG, "Acquired lock.");
    }

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
        log_print(LOG_WARNING, "Failed to open the stat cache.");
        config.cache = NULL;
        goto finish;
    }
    log_print(LOG_DEBUG, "Opened stat cache.");

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
    if (lock_thread_running) {
        lock_thread_exit = 1;
        pthread_kill(lock_thread, SIGUSR1);
        pthread_join(lock_thread, NULL);
        remove_lock();
        ne_lockstore_destroy(lock_store);

        log_print(LOG_DEBUG, "Freed lock.");
    }

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

    session_free();
    log_print(LOG_DEBUG, "Freed session.");

    ne_sock_exit();
    log_print(LOG_DEBUG, "Unset libneon thread-safety locks.");

    if (stat_cache_close(config.cache, config.cache_supplemental) < 0)
        log_print(LOG_ERR, "Failed to close the stat cache.");

    log_print(LOG_NOTICE, "Shutdown was successful. Exiting.");

    return ret;
}

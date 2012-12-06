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
#include <getopt.h>
#include <attr/xattr.h>

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

#include <yaml.h>
#include <systemd/sd-journal.h>

#include "log.h"
#include "statcache.h"
#include "filecache.h"
#include "session.h"
#include "fusedav.h"

const ne_propname query_properties[] = {
    { "DAV:", "resourcetype" },
    { "http://apache.org/dav/props/", "executable" },
    { "DAV:", "getcontentlength" },
    { "DAV:", "getlastmodified" },
    { "DAV:", "creationdate" },
    { "DAV:", "event" }, // @TODO: Progressive PROPFIND support.
    { NULL, NULL }
};

mode_t mask = 0;
int debug = 0;
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
    bool noattributes;
    char *cache_path;
    stat_cache_t *cache;
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
     FUSEDAV_OPT("verbosity=%d",                   verbosity, 5),
     FUSEDAV_OPT("nodaemon",                       nodaemon, true),
     FUSEDAV_OPT("noattributes",                   noattributes, true),

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

static void path_cvt_tsd_key_init(void) {
    pthread_key_create(&path_cvt_tsd_key, free);
}

static const char *path_cvt(const char *path) {
    char *r, *t;
    int l;

    pthread_once(&path_cvt_once, path_cvt_tsd_key_init);

    if ((r = pthread_getspecific(path_cvt_tsd_key)))
        free(r);

    t = malloc((l = strlen(base_directory)+strlen(path))+1);
    assert(t);
    sprintf(t, "%s%s", base_directory, path);

    if (l > 1 && t[l-1] == '/')
        t[l-1] = 0;

    r = ne_path_escape(t);
    free(t);

    pthread_setspecific(path_cvt_tsd_key, r);

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

    for (i = 0; i < MAX_REDIRECTS; i++) {
        const ne_uri *u;

        if ((ret = ne_simple_propfind(session, path, depth, props, results, userdata)) != NE_REDIRECT)
            return ret;

        if (!(u = ne_redirect_location(session)))
            break;

        if (!session_is_local(u))
            break;

        if (debug)
            log_print(LOG_DEBUG, "REDIRECT FROM '%s' to '%s'", path, u->path);

        path = u->path;
    }

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

        if (debug)
            log_print(LOG_DEBUG, "REDIRECT FROM '%s' to '%s'", path, u->path);

        path = u->path;
    }

    return ret;
}


static void fill_stat(struct stat *st, const ne_prop_result_set *results, bool *is_deleted, int is_dir) {
    const char *e, *gcl, *glm, *cd, *ev;
    //const char *rt;
    //const ne_propname resourcetype = { "DAV:", "resourcetype" };
    const ne_propname executable = { "http://apache.org/dav/props/", "executable" };
    const ne_propname getcontentlength = { "DAV:", "getcontentlength" };
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    const ne_propname creationdate = { "DAV:", "creationdate" };
    const ne_propname event = { "DAV:", "event" };

    assert(st && results);

    //rt = ne_propset_value(results, &resourcetype);
    e = ne_propset_value(results, &executable);
    gcl = ne_propset_value(results, &getcontentlength);
    glm = ne_propset_value(results, &getlastmodified);
    cd = ne_propset_value(results, &creationdate);

    if (is_deleted != NULL) {
        ev = ne_propset_value(results, &event);
        if (ev != NULL) {
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

static char *strip_trailing_slash(char *fn, int *is_dir) {
    size_t l = strlen(fn);
    assert(fn);
    assert(is_dir);
    assert(l > 0);

    if ((*is_dir = (fn[l-1] == '/')))
        fn[l-1] = 0;

    return fn;
}

static void getdir_propfind_callback(void *userdata, const ne_uri *u, const ne_prop_result_set *results) {
    struct fill_info *f = userdata;
    char fn[PATH_MAX], *t;
    int is_dir = 0;
    struct fusedav_config *config = fuse_get_context()->private_data;
    struct stat_cache_value value;
    char *cache_path = NULL;
    bool is_deleted;

    assert(f);

    strncpy(fn, u->path, sizeof(fn));
    fn[sizeof(fn)-1] = 0;
    strip_trailing_slash(fn, &is_dir);

    fill_stat(&value.st, results, &is_deleted, is_dir);

    if (strcmp(fn, f->root) && fn[0]) {
        //char *h;
        //log_print(LOG_DEBUG, "getdir_propfind_callback fn: %s", fn);

        if ((t = strrchr(fn, '/')))
            t++;
        else
            t = fn;

        asprintf(&cache_path, "%s/%s", f->root, t);
        //log_print(LOG_DEBUG, "getdir_propfind_callback cache_path: %s", cache_path);
        if (is_deleted)
            stat_cache_delete(config->cache, cache_path);
        else
            stat_cache_value_set(config->cache, cache_path, &value);
        free(cache_path);

        // Send the data to FUSE.
        //h = ne_path_unescape(t);
        //f->filler(f->buf, h, NULL, 0);
        //free(h);
    }
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

static int dav_readdir(
        const char *path,
        void *buf,
        fuse_fill_dir_t filler,
        __unused ne_off_t offset,
        __unused struct fuse_file_info *fi) {

    struct fusedav_config *config = fuse_get_context()->private_data;
    struct fill_info f;
    ne_session *session;
    unsigned int min_generation;
    time_t timestamp;
    time_t last_updated;
    char *update_path = NULL;
    bool needs_update;
    int ret;

    path = path_cvt(path);

    //if (debug)
    //    log_print(LOG_DEBUG, "getdir(%s)", path);

    f.buf = buf;
    f.filler = filler;
    f.root = path;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    // First, attempt to hit the cache.
    ret = stat_cache_enumerate(config->cache, path, getdir_cache_callback, &f, false);
    if (ret < 0) {
        needs_update = true;
        timestamp = time(NULL);

        if (debug) {
            if (ret == -STAT_CACHE_OLD_DATA) log_print(LOG_DEBUG, "DIR-CACHE-TOO-OLD: %s", path);
            else log_print(LOG_DEBUG, "DIR-CACHE-MISS: %s", path);
        }

        if (!(session = session_get(1)))
            return -EIO;

        // If we have *old* data in some form, attempt to freshen the cache.
        // @TODO: Only use with supporting servers.
        if (ret == -STAT_CACHE_OLD_DATA) {
            last_updated = stat_cache_read_updated_children(config->cache, path);
            asprintf(&update_path, "%s?changes_since=%lu", path, last_updated - CLOCK_SKEW);

            if (simple_propfind_with_redirect(session, update_path, NE_DEPTH_ONE, query_properties, getdir_propfind_callback, &f) == NE_OK) {
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
            min_generation = stat_cache_get_local_generation();
            if (simple_propfind_with_redirect(session, path, NE_DEPTH_ONE, query_properties, getdir_propfind_callback, &f) != NE_OK) {
                log_print(LOG_WARNING, "Complete PROPFIND failed: %s", ne_get_error(session));
                return -ENOENT;
            }
            stat_cache_delete_older(config->cache, path, min_generation);
        }

        // Mark the directory contents as updated.
        stat_cache_updated_children(config->cache, path, timestamp);

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
    char fn[PATH_MAX];
    int is_dir;

    assert(st);

    strncpy(fn, u->path, sizeof(fn));
    fn[sizeof(fn) - 1] = 0;

    if (debug)
        log_print(LOG_DEBUG, "getattr_propfind_callback: %s", fn);

    strip_trailing_slash(fn, &is_dir);

    if (debug)
        log_print(LOG_DEBUG, "stripped: %s (isdir: %d)", fn, is_dir);

    fill_stat(st, results, NULL, is_dir);

    value.st = *st;
    stat_cache_value_set(config->cache, fn, &value);
}

static int get_stat(const char *path, struct stat *stbuf) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    struct stat_cache_value *response;

    //if (debug)
    //    log_print(LOG_DEBUG, "get_stat(%s, stbuf)", path);

    if (!(session = session_get(1)))
        return -EIO;

    if ((response = stat_cache_value_get(config->cache, path))) {
        *stbuf = response->st;
        free(response);
        //print_stat(stbuf, "get_stat from cache");
        return stbuf->st_mode == 0 ? -ENOENT : 0;
    }

    if (debug)
        log_print(LOG_DEBUG, "STAT-CACHE-MISS");

    if (simple_propfind_with_redirect(session, path, NE_DEPTH_ZERO, query_properties, getattr_propfind_callback, stbuf) != NE_OK) {
        stat_cache_delete(config->cache, path);
        log_print(LOG_NOTICE, "PROPFIND failed: %s", ne_get_error(session));
        return -ENOENT;
    }

    if (debug)
        log_print(LOG_DEBUG, "STAT-CACHE-PUT");
    //print_stat(stbuf, "get_stat from simple_propfind_with_redirect");

    return 0;
}

static int dav_getattr(const char *path, struct stat *stbuf) {
    path = path_cvt(path);
    //if (debug)
    //    log_print(LOG_DEBUG, "getattr(%s)", path);
    return get_stat(path, stbuf);
}

static int dav_unlink(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    int r;
    struct stat st;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "unlink(%s)", path);

    if (!(session = session_get(1)))
        return -EIO;

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISREG(st.st_mode))
        return -EISDIR;

    if (ne_delete(session, path)) {
        log_print(LOG_ERR, "DELETE failed: %s", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_delete(config->cache, path);
    stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int dav_rmdir(const char *path) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char fn[PATH_MAX];
    int r;
    struct stat st;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "rmdir(%s)", path);

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

static int dav_mkdir(const char *path, __unused mode_t mode) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    char fn[PATH_MAX];
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "mkdir(%s)", path);

    if (!(session = session_get(1)))
        return -EIO;

    snprintf(fn, sizeof(fn), "%s/", path);

    if (ne_mkcol(session, fn)) {
        log_print(LOG_ERR, "MKCOL failed: %s", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_delete(config->cache, path);
    stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int dav_rename(const char *from, const char *to) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    int r = 0;
    struct stat st;
    char fn[PATH_MAX], *_from;

    from = _from = strdup(path_cvt(from));
    assert(from);
    to = path_cvt(to);

    if (debug)
        log_print(LOG_DEBUG, "rename(%s, %s)", from, to);

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if ((r = get_stat(from, &st)) < 0)
        goto finish;

    if (S_ISDIR(st.st_mode)) {
        snprintf(fn, sizeof(fn), "%s/", from);
        from = fn;
    }

    if (ne_move(session, 1, from, to)) {
        log_print(LOG_ERR, "MOVE failed: %s", ne_get_error(session));
        r = -ENOENT;
        goto finish;
    }

    stat_cache_delete(config->cache, from);
    stat_cache_delete_parent(config->cache, from);
    stat_cache_delete(config->cache, to);
    stat_cache_delete_parent(config->cache, to);

finish:

    free(_from);

    return r;
}

static int dav_release(const char *path, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f = NULL;
    int r = 0;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "release(%s)", path);

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (!(f = file_cache_get(path))) {
        log_print(LOG_DEBUG, "release() called for closed file");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_close(f) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(config->cache, f);

    return r;
}

static int dav_fsync(const char *path, __unused int isdatasync, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f = NULL;
    int r = 0;
    ne_session *session;

    path = path_cvt(path);
    if (debug)
        log_print(LOG_DEBUG, "fsync(%s)", path);

    if (!(session = session_get(1))) {
        r = -EIO;
        goto finish;
    }

    if (!(f = file_cache_get(path))) {
        log_print(LOG_DEBUG, "fsync() called for closed file");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_sync(config->cache, f) < 0) {
        r = -errno;
        goto finish;
    }

finish:

    if (f)
        file_cache_unref(config->cache, f);

    return r;
}

static int dav_mknod(const char *path, mode_t mode, __unused dev_t rdev) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    //struct stat_cache_value value;
    char tempfile[PATH_MAX];
    int fd;
    ne_session *session;
    //struct stat st;

    path = path_cvt(path);
    if (debug)
        log_print(LOG_DEBUG, "mknod(%s)", path);

    if (!(session = session_get(1)))
        return -EIO;

    if (!S_ISREG(mode))
        return -ENOTSUP;

    snprintf(tempfile, sizeof(tempfile), "%s/fusedav-empty-XXXXXX", "/tmp");
    if ((fd = mkstemp(tempfile)) < 0)
        return -errno;

    // @TODO: Prepopulate file cache.
    unlink(tempfile);

    if (ne_put(session, path, fd)) {
        log_print(LOG_ERR, "mknod:PUT failed: %s", ne_get_error(session));
        close(fd);
        return -EACCES;
    }

    if (debug)
        log_print(LOG_DEBUG, "mknod(%s):PUT complete", path);

    close(fd);

    // Prepopulate stat cache.

    /*
    st.st_mode = 040775;  // @TODO: Use the right mode data.
    st.st_nlink = 3;
    st.st_size = 0;
    st.st_atime = time(NULL);
    st.st_mtime = st.st_atime;
    st.st_ctime = st.st_mtime;
    st.st_blksize = 0;
    st.st_blocks = 8;
    st.st_uid = getuid();
    st.st_gid = getgid();

    value.st = st;

    stat_cache_value_set(config->cache, path, &value);
    */

    stat_cache_delete(config->cache, path);
    stat_cache_delete_parent(config->cache, path);

    return 0;
}

static int dav_open(const char *path, struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f;

    if (debug)
        log_print(LOG_DEBUG, "open(%s)", path);

    path = path_cvt(path);

    if (!(f = file_cache_open(path, info->flags)))
        return -errno;

    file_cache_unref(config->cache, f);

    return 0;
}

static int dav_read(const char *path, char *buf, size_t size, ne_off_t offset, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f = NULL;
    ssize_t r;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "read(%s, %lu+%lu)", path, (unsigned long) offset, (unsigned long) size);

    if (!(f = file_cache_get(path))) {
        log_print(LOG_WARNING, "read() called for closed file");
        r = -EFAULT;
        goto finish;
    }

    if ((r = file_cache_read(f, buf, size, offset)) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(config->cache, f);

    return r;
}

static int dav_write(const char *path, const char *buf, size_t size, ne_off_t offset, __unused struct fuse_file_info *info) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f = NULL;
    ssize_t r;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "write(%s, %lu+%lu)", path, (unsigned long) offset, (unsigned long) size);

    if (!(f = file_cache_get(path))) {
        log_print(LOG_WARNING, "write() called for closed file");
        r = -EFAULT;
        goto finish;
    }

    if ((r = file_cache_write(f, buf, size, offset)) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(config->cache, f);

    return r;
}


static int dav_truncate(const char *path, ne_off_t size) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    void *f = NULL;
    int r = 0;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "truncate(%s, %lu)", path, (unsigned long) size);

    if (!(session = session_get(1)))
        r = -EIO;
        goto finish;

    if (!(f = file_cache_get(path))) {
        log_print(LOG_WARNING, "truncate() called for closed file");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_truncate(f, size) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(config->cache, f);

    return r;
}

static int dav_utimens(const char *path, const struct timespec tv[2]) {
    struct fusedav_config *config = fuse_get_context()->private_data;
    ne_session *session;
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    ne_proppatch_operation ops[2];
    int r = 0;
    char *date;

    if (config->noattributes) {
        if (debug)
            log_print(LOG_DEBUG, "Skipping attribute setting.");
        return r;
    }

    assert(path);

    path = path_cvt(path);

    if (debug)
        log_print(LOG_DEBUG, "utimens(%s, %lu, %lu)", path, tv[0].tv_sec, tv[1].tv_sec);

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

    stat_cache_delete(config->cache, path);  // @TODO: Update the stat cache instead.

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

    ne_session *session;
    struct listxattr_info l;


    assert(path);

    path = path_cvt(path);

    if (debug)
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

    ne_session *session;
    struct getxattr_info g;
    ne_propname props[2];
    char dnspace[128], dname[128];

    assert(path);

    path = path_cvt(path);
    name = fix_xattr(name);

    //if (debug)
    //    log_print(LOG_DEBUG, "getxattr(%s, %s, .., %lu)", path, name, (unsigned long) size);

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

    assert(path);
    assert(name);
    assert(value);

    path = path_cvt(path);
    name = fix_xattr(name);

    if (debug)
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

    assert(path);
    assert(name);

    path = path_cvt(path);
    name = fix_xattr(name);

    if (debug)
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

    if (config->noattributes)
        return 0;

    assert(path);

    path = path_cvt(path);

    if (debug)
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

    // @TODO: Lock for concurrency.
    value = stat_cache_value_get(config->cache, path);
    if (value != NULL) {
        value->st.st_mode = mode;
        stat_cache_value_set(config->cache, path, value);
        free(value);
    }

finish:

    return r;
}

static int dav_chown(__unused const char *path, __unused uid_t u, __unused gid_t g) {
    struct fusedav_config *config = fuse_get_context()->private_data;

    if (config->noattributes)
        return 0;

    // @TODO: Implement.
    return 0;
}

static struct fuse_operations dav_oper = {
    .getattr     = dav_getattr,
    .readdir     = dav_readdir,
    .mknod       = dav_mknod,
    .mkdir       = dav_mkdir,
    .unlink      = dav_unlink,
    .rmdir       = dav_rmdir,
    .rename      = dav_rename,
    .chmod       = dav_chmod,
    .chown       = dav_chown,
    .truncate    = dav_truncate,
    .utimens     = dav_utimens,
    .open        = dav_open,
    .read        = dav_read,
    .write       = dav_write,
    .release     = dav_release,
    .fsync       = dav_fsync,
// @TODO: Make optional.
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

    if (debug)
        log_print(LOG_DEBUG, "Acquiring lock...");

    for (i = 0; i < MAX_REDIRECTS; i++) {
        const ne_uri *u;

        if ((ret = ne_lock(session, lock)) != NE_REDIRECT)
            break;

        if (!(u = ne_redirect_location(session)))
            break;

        if (!session_is_local(u))
            break;

        if (debug)
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

    if (debug)
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

    if (debug)
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

    if (debug)
        log_print(LOG_DEBUG, "lock_thread exiting");

    return NULL;
}

int file_exists_or_set_null(char **path) {
    FILE *file;

    if ((file = fopen(*path, "r"))) {
        fclose(file);
        if (debug)
            log_print(LOG_DEBUG, "file_exists_or_set_null(%s): found", *path);
        return 0;
    }
    free(*path);
    *path = NULL;
    if (debug)
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
                "    -o username=STRING\n"
                "    -o password=STRING\n"
                "    -o ca_certificate=PATH\n"
                "    -o client_certificate=PATH\n"
                "    -o client_certificate_password=STRING\n"
                "    -o lock_timeout=NUM\n"
                "    -o lock_on_mount\n"
                "    -o debug\n"
                "    -o nodaemon\n"
                "    -o noattributes\n"
                "\n"
                , outargs->argv[0]);
        fuse_opt_add_arg(outargs, "-ho");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(1);

    case KEY_VERSION:
        fprintf(stderr, "fusedav version %s\n", PACKAGE_VERSION);
#ifdef HAVE_LIBLEVELDB
        fprintf(stderr, "LevelDB version %d.%d\n", leveldb_major_version(), leveldb_minor_version());
#endif
        fuse_opt_add_arg(outargs, "--version");
        fuse_main(outargs->argc, outargs->argv, &dav_oper, &config);
        exit(0);
    }
    return 1;
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fusedav_config config;
    struct fuse_chan *ch;
    char *mountpoint;
    int ret = 1;
    pthread_t lock_thread;
    int lock_thread_running = 0;
    int fail = 0;

    if (ne_sock_init()) {
        log_print(LOG_CRIT, "Failed to initialize libneon.");
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

    if (fail) {
        goto finish;
    }

    mask = umask(0);
    umask(mask);

    if (setup_signal_handlers() < 0)
        goto finish;

    memset(&config, 0, sizeof(config));

    // Parse options.
    if (!fuse_opt_parse(&args, &config, fusedav_opts, fusedav_opt_proc) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse options.");
        goto finish;
    }

    //config.verbosity = 3;

    // Apply debug mode.
    debug = (config.verbosity >= 7);
    log_print(LOG_DEBUG, "Log verbosity: %d.", config.verbosity);

    if (debug)
        log_print(LOG_DEBUG, "Parsed options.");

    if (stat_cache_open(&config.cache, config.cache_path) < 0) {
        log_print(LOG_WARNING, "Failed to open the stat cache.");
        config.cache = NULL;
    }

    if (debug)
        log_print(LOG_DEBUG, "Opened stat cache.");

    if (fuse_parse_cmdline(&args, &mountpoint, NULL, NULL) < 0) {
        log_print(LOG_CRIT, "FUSE could not parse the command line.");
        goto finish;
    }
    if (debug)
        log_print(LOG_DEBUG, "Parsed command line.");

    if (!config.uri) {
        log_print(LOG_CRIT, "Missing the required URI argument.");
        goto finish;
    }

    if (session_set_uri(config.uri, config.username, config.password, config.client_certificate, config.ca_certificate) < 0) {
        log_print(LOG_CRIT, "Failed to initialize the session URI.");
        goto finish;
    }
    if (debug)
        log_print(LOG_DEBUG, "Set session URI and configuration.");

    if (!(ch = fuse_mount(mountpoint, &args))) {
        log_print(LOG_CRIT, "Failed to mount FUSE file system.");
        goto finish;
    }
    if (debug)
        log_print(LOG_DEBUG, "Mounted the FUSE file system.");

    if (!(fuse = fuse_new(ch, &args, &dav_oper, sizeof(dav_oper), &config))) {
        log_print(LOG_CRIT, "Failed to create FUSE object.");
        goto finish;
    }
    if (debug)
        log_print(LOG_DEBUG, "Created the FUSE object.");

    if (config.lock_on_mount && create_lock(config.lock_timeout) >= 0) {
        int r;
        if ((r = pthread_create(&lock_thread, NULL, lock_thread_func, &config)) < 0) {
            log_print(LOG_CRIT, "pthread_create(): %s", strerror(r));
            goto finish;
        }

        lock_thread_running = 1;
        if (debug)
            log_print(LOG_DEBUG, "Acquired lock.");
    }

    if (config.nodaemon) {
        if (debug)
            log_print(LOG_DEBUG, "Running in foreground (skipping daemonization).");
    }
    else {
        if (debug)
            log_print(LOG_DEBUG, "Attempting to daemonize.");
        if (fuse_daemonize(/* run in foreground */ 0) < 0) {
            log_print(LOG_CRIT, "Failed to daemonize.");
            goto finish;
        }
    }

    if (debug)
        log_print(LOG_DEBUG, "Entering main FUSE loop.");
    if (fuse_loop_mt(fuse) < 0) {
        log_print(LOG_CRIT, "Error occurred while trying to enter main FUSE loop.");
        goto finish;
    }

    if (debug)
        log_print(LOG_DEBUG, "Exiting cleanly.");

    ret = 0;

finish:
    if (lock_thread_running) {
        lock_thread_exit = 1;
        pthread_kill(lock_thread, SIGUSR1);
        pthread_join(lock_thread, NULL);
        remove_lock();
        ne_lockstore_destroy(lock_store);

        if (debug)
            log_print(LOG_DEBUG, "Freed lock.");
    }

    if (ch != NULL) {
        if (debug)
            log_print(LOG_DEBUG, "Unmounting: %s", mountpoint);
        fuse_unmount(mountpoint, ch);
    }
    if (debug)
        log_print(LOG_DEBUG, "Unmounted.");

    if (fuse)
        fuse_destroy(fuse);
    if (debug)
        log_print(LOG_DEBUG, "Destroyed FUSE object.");

    fuse_opt_free_args(&args);
    if (debug)
        log_print(LOG_DEBUG, "Freed arguments.");

    file_cache_close_all(config.cache);
    if (debug)
        log_print(LOG_DEBUG, "Closed file cache.");

    session_free();
    if (debug)
        log_print(LOG_DEBUG, "Freed session.");

    if (stat_cache_close(config.cache) < 0)
        log_print(LOG_ERR, "Failed to close the stat cache.");

    return ret;
}

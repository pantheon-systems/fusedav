/* $Id$ */

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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statfs.h>
#include <getopt.h>

#include <ne_request.h>
#include <ne_basic.h>
#include <ne_props.h>
#include <ne_utils.h>
#include <ne_socket.h>
#include <ne_auth.h>
#include <ne_dates.h>

#include <fuse.h>

#include "statcache.h"
#include "filecache.h"
#include "session.h"
#include "openssl-thread.h"

const ne_propname query_properties[] = {
    { "DAV:", "resourcetype" },
    { "http://apache.org/dav/props/", "executable" },
    { "DAV:", "getcontentlength" },
    { "DAV:", "getlastmodified" },
    { "DAV:", "creationdate" },
    { NULL, NULL }
};

mode_t mask = 0;
int debug = 0;
struct fuse* fuse = NULL;

struct fill_info {
    fuse_dirh_t h;
    fuse_dirfil_t filler;
    const char *root;
};

static int get_stat(const char *path, struct stat *stbuf);

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

static void fill_stat(struct stat* st, const ne_prop_result_set *results, int is_dir) {
    const char *rt, *e, *gcl, *glm, *cd;
    const ne_propname resourcetype = { "DAV:", "resourcetype" };
    const ne_propname executable = { "http://apache.org/dav/props/", "executable" };
    const ne_propname getcontentlength = { "DAV:", "getcontentlength" };
    const ne_propname getlastmodified = { "DAV:", "getlastmodified" };
    const ne_propname creationdate = { "DAV:", "creationdate" };
        
    assert(st && results);

    rt = ne_propset_value(results, &resourcetype);
    e = ne_propset_value(results, &executable);
    gcl = ne_propset_value(results, &getcontentlength);
    glm = ne_propset_value(results, &getlastmodified);
    cd = ne_propset_value(results, &creationdate);

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
    /*fprintf(stderr, "a: %u; m: %u; c: %u\n", st->st_atime, st->st_mtime, st->st_ctime);*/

    st->st_mode &= ~mask;
    
    st->st_uid = getuid();
    st->st_gid = getgid();
}

static char *strip_trailing_slash(char *fn, int *is_dir) {
    size_t l = strlen(fn);
    assert(fn && is_dir);
    
    if ((*is_dir = (fn[l-1] == '/')))
        fn[l-1] = 0;

    return fn;
}

static void getdir_propfind_callback(void *userdata, const char *href, const ne_prop_result_set *results) {
    struct fill_info *f = userdata;
    struct stat st;
    char fn[PATH_MAX], *t;
    int is_dir = 0;

    assert(f);

    strncpy(fn, href, sizeof(fn));
    fn[sizeof(fn)-1] = 0;
    strip_trailing_slash(fn, &is_dir);

    if (strcmp(fn, f->root) && fn[0]) {
        char *h;
        
        if ((t = strrchr(fn, '/')))
            t++;
        else
            t = fn;

        dir_cache_add(f->root, t, is_dir);
        f->filler(f->h, h = ne_path_unescape(t), is_dir ? DT_DIR : DT_REG);
        free(h);
    }

    fill_stat(&st, results, is_dir);
    stat_cache_set(fn, &st);
}

static void getdir_cache_callback(const char *root, const char *fn, int is_dir, void *user) {
    struct fill_info *f = user;
    assert(f);
    char path[PATH_MAX];
    struct stat st;
    char *h;

    snprintf(path, sizeof(path), "%s/%s", !strcmp(root, "/") ? "" : root, fn);
    
    if (get_stat(path, &st) < 0)
        return;
    
    f->filler(f->h, h = ne_path_unescape(fn), is_dir ? DT_DIR : DT_REG);
    free(h);
}

static int dav_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler) {
    struct fill_info f;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        fprintf(stderr, "getdir(%s)\n", path);

    f.h = h;
    f.filler = filler;
    f.root = path;

    if (dir_cache_enumerate(path, getdir_cache_callback, &f) < 0) {

        if (debug)
            fprintf(stderr, "DIR-CACHE-MISS\n");
        
        if (!(session = session_get())) 
            return -EIO;

        dir_cache_begin(path);
        
        if (ne_simple_propfind(session, path, NE_DEPTH_ONE, query_properties, getdir_propfind_callback, &f) != NE_OK) {
            dir_cache_finish(path, 2);
            fprintf(stderr, "PROPFIND failed: %s\n", ne_get_error(session));
            return -ENOENT;
        }

        dir_cache_finish(path, 1);
    }

    filler(h, ".", DT_DIR);
    filler(h, "..", DT_DIR);

    return 0;
}

static void getattr_propfind_callback(void *userdata, const char *href, const ne_prop_result_set *results) {
    struct stat *st = (struct stat*) userdata;
    char fn[PATH_MAX];
    int is_dir;

    assert(st);

    strncpy(fn, href, sizeof(fn));
    fn[sizeof(fn)-1] = 0;
    strip_trailing_slash(fn, &is_dir);
    
    fill_stat(st, results, is_dir);
    stat_cache_set(fn, st);
}

static int get_stat(const char *path, struct stat *stbuf) {
    ne_session *session;

    if (!(session = session_get())) 
        return -EIO;

    if (stat_cache_get(path, stbuf) == 0) {
        return stbuf->st_mode == 0 ? -ENOENT : 0;
    } else {
        if (debug)
            fprintf(stderr, "STAT-CACHE-MISS\n");
        
        if (ne_simple_propfind(session, path, NE_DEPTH_ZERO, query_properties, getattr_propfind_callback, stbuf) != NE_OK) {
            stat_cache_invalidate(path);
            fprintf(stderr, "PROPFIND failed: %s\n", ne_get_error(session));
            return -ENOENT;
        }

        return 0;
    }
}

static int dav_getattr(const char *path, struct stat *stbuf) {
    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "getattr(%s)\n", path);
    return get_stat(path, stbuf);
}

static int dav_unlink(const char *path) {
    int r;
    struct stat st;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        fprintf(stderr, "unlink(%s)\n", path);

    if (!(session = session_get())) 
        return -EIO;

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISREG(st.st_mode))
        return -EISDIR;
    
    if (ne_delete(session, path)) {
        fprintf(stderr, "DELETE failed: %s\n", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_invalidate(path);
    dir_cache_invalidate_parent(path);
    
    return 0;
}

static int dav_rmdir(const char *path) {
    int r;
    struct stat st;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        fprintf(stderr, "rmdir(%s)\n", path);

    if (!(session = session_get())) 
        return -EIO;

    if ((r = get_stat(path, &st)) < 0)
        return r;

    if (!S_ISDIR(st.st_mode))
        return -ENOTDIR;
    
    if (ne_delete(session, path)) {
        fprintf(stderr, "DELETE failed: %s\n", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_invalidate(path);
    dir_cache_invalidate_parent(path);

    return 0;
}

static int dav_mkdir(const char *path, mode_t mode) {
    char fn[PATH_MAX];
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        fprintf(stderr, "mkdir(%s)\n", path);

    if (!(session = session_get())) 
        return -EIO;

    snprintf(fn, sizeof(fn), "%s/", path);
    
    if (ne_mkcol(session, fn)) {
        fprintf(stderr, "MKCOL failed: %s\n", ne_get_error(session));
        return -ENOENT;
    }

    stat_cache_invalidate(path);
    dir_cache_invalidate_parent(path);
    
    return 0;
}

static int dav_rename(const char *from, const char *to) {
    ne_session *session;
    int r = 0;

    from = strdup(path_cvt(from));
    to = path_cvt(to);

    if (debug)
        fprintf(stderr, "rename(%s, %s)\n", from, to);

    if (!(session = session_get())) {
        r = -EIO;
        goto finish;
    }

    if (ne_move(session, 1, from, to)) {
        fprintf(stderr, "MOVE failed: %s\n", ne_get_error(session));
        r = -ENOENT;
        goto finish;
    }
    
    stat_cache_invalidate(from);
    stat_cache_invalidate(to);

    dir_cache_invalidate_parent(from);
    dir_cache_invalidate_parent(to);

finish:

    free((char*) from);
    
    return r;
}

static int dav_release(const char *path, int flags) {
    void *f = NULL;
    int r = 0;
    ne_session *session;

    path = path_cvt(path);

    if (debug)
        fprintf(stderr, "release(%s)\n", path);

    if (!(session = session_get())) {
        r = -EIO;
        goto finish;
    }
    
    if (!(f = file_cache_get(path))) {
        fprintf(stderr, "release() called for closed file\n");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_close(f) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(f);
    
    return r;
}

static int dav_fsync(const char *path, int isdatasync) {
    void *f = NULL;
    int r = 0;
    ne_session *session;

    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "fsync(%s)\n", path);

    if (!(session = session_get())) {
        r = -EIO;
        goto finish;
    }

    if (!(f = file_cache_get(path))) {
        fprintf(stderr, "fsync() called for closed file\n");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_sync(f) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    
    if (f)
        file_cache_unref(f);

    return r;
}

static int dav_mknod(const char *path, mode_t mode, dev_t rdev) {
    char tempfile[PATH_MAX];
    int fd;
    ne_session *session;
    
    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "mknod(%s)\n", path);

    if (!(session = session_get())) 
        return -EIO;

    if (!S_ISREG(mode))
        return -ENOTSUP;

    snprintf(tempfile, sizeof(tempfile), "%s/fusedav-empty-XXXXXX", "/tmp");
    if ((fd = mkstemp(tempfile)) < 0)
        return -errno;
    
    unlink(tempfile);
    
    if (ne_put(session, path, fd)) {
        fprintf(stderr, "mknod:PUT failed: %s\n", ne_get_error(session));
        close(fd);
        return -EACCES;
    }

    close(fd);

    stat_cache_invalidate(path);
    dir_cache_invalidate_parent(path);

    return 0;
}

static int dav_open(const char *path, int flags) {
    void *f;

    if (debug)
        fprintf(stderr, "open(%s)\n", path);

    path = path_cvt(path);
    if (!(f = file_cache_open(path, flags)))
        return -errno;

    file_cache_unref(f);

    return 0;
}

static int dav_read(const char *path, char *buf, size_t size, off_t offset) {
    void *f = NULL;
    ssize_t r;
 
    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "read(%s, %lu+%lu)\n", path, (unsigned long) offset, (unsigned long) size);
    
    if (!(f = file_cache_get(path))) {
        fprintf(stderr, "read() called for closed file\n");
        r = -EFAULT;
        goto finish;
    }

    if ((r = file_cache_read(f, buf, size, offset)) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(f);
    
    return r;
}

static int dav_write(const char *path, const char *buf, size_t size, off_t offset) {
    void *f = NULL;
    ssize_t r;

    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "write(%s, %lu+%lu)\n", path, (unsigned long) offset, (unsigned long) size);

    if (!(f = file_cache_get(path))) {
        fprintf(stderr, "write() called for closed file\n");
        r = -EFAULT;
        goto finish;
    }

    if ((r = file_cache_write(f, buf, size, offset)) < 0) {
        r = -errno;
        goto finish;
    }
    
finish:
    if (f)
        file_cache_unref(f);
    
    return r;
}


static int dav_truncate(const char *path, off_t size) {
    void *f = NULL;
    int r = 0;
    ne_session *session;
    
    path = path_cvt(path);
    if (debug)
        fprintf(stderr, "truncate(%s, %lu)\n", path, (unsigned long) size);

    if (!(session = session_get()))
        r = -EIO;
        goto finish;
    
    if (!(f = file_cache_get(path))) {
        fprintf(stderr, "truncate() called for closed file\n");
        r = -EFAULT;
        goto finish;
    }

    if (file_cache_truncate(f, size) < 0) {
        r = -errno;
        goto finish;
    }

finish:
    if (f)
        file_cache_unref(f);
    
    return r;
}


static struct fuse_operations dav_oper = {
    .getattr	= dav_getattr,
    .getdir	= dav_getdir,
    .mknod	= dav_mknod,
    .mkdir	= dav_mkdir,
    .unlink	= dav_unlink,
    .rmdir	= dav_rmdir,
    .rename	= dav_rename,
/*    .chmod	= dav_chmod,*/
    .truncate	= dav_truncate,
/*    .utime	= dav_utime,*/
    .open	= dav_open,
    .read	= dav_read,
    .write	= dav_write,
    .release	= dav_release,
    .fsync	= dav_fsync
};

static void usage(char *argv0) {
    char *e;

    if ((e = strrchr(argv0, '/')))
        e++;
    else
        e = argv0;
    
    fprintf(stderr,
            "%s [-h] [-D] [-u USERNAME] [-p PASSWORD] URL MOUNTPOINT\n"
            "\t-h Show this help\n"
            "\t-D Enable debug mode\n"
            "\t-u Username if required\n"
            "\t-p Password if required\n",
            e);
}

static void exit_handler(int s) {
    static const char m[] = "*** Caught signal ***\n";
    write(2, m, strlen(m));
    if(fuse != NULL)
        fuse_exit(fuse);
}

static int setup_signal_handlers(void) {
    struct sigaction sa;
                                                                                                        
    sa.sa_handler = exit_handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;
    
    if (sigaction(SIGHUP, &sa, NULL) == -1 ||
        sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1) {
                                                                                                        
        fprintf(stderr, "Cannot set exit signal handlers: %s\n", strerror(errno));
        return -1;
    }
                                                                                                        
    sa.sa_handler = SIG_IGN;
                                                                                                        
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        fprintf(stderr, "Cannot set ignored signals: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int c;
    char *u=NULL, *p = NULL;
    int fuse_fd = -1;
    int ret = 1;
    char mountpoint[PATH_MAX];
    static const char *mount_args[] = { "-n",  NULL, "-l", "-c", NULL };

    if (ne_sock_init()) {
        fprintf(stderr, "Failed to initialize libneon.\n");
        goto finish;
    }

    openssl_thread_setup();

    mask = umask(0);
    umask(mask);

    cache_alloc();

    if (setup_signal_handlers() < 0)
        goto finish;
    
    while ((c = getopt(argc, argv, "hu:p:D")) != -1) {

        switch(c) {
            case 'u':
                u = optarg;
                break;
                
            case 'p':
                p = optarg;
                break;
                
            case 'D':
                debug = !debug;
                break;
                    
            case 'h':
            default:
                usage(argv[0]);
                goto finish;
        }
    }

    if (optind != argc-2) {
        usage(argv[0]);
        goto finish;
    }

    if (session_set_uri(argv[optind], u, p) < 0) {
        usage(argv[0]);
        goto finish;
    }

    if (argv[optind+1][0] == '/')
        snprintf(mountpoint, sizeof(mountpoint), "%s", argv[optind+1]);
    else {
        char *pwd = get_current_dir_name();
        snprintf(mountpoint, sizeof(mountpoint), "%s/%s", pwd, argv[optind+1]);
        free(pwd);
    }

    mount_args[1] = argv[optind];
    
    if ((fuse_fd = fuse_mount(mountpoint, mount_args)) < 0) {
        fprintf(stderr, "Failed to mount FUSE file system.\n");
        goto finish;
    }

    if (!(fuse = fuse_new(fuse_fd, 0, &dav_oper))) {
        fprintf(stderr, "Failed to create FUSE object.\n");
        goto finish;
    }
    
    fuse_loop_mt(fuse);
    
    ret = 0;
    
finish:

    if (fuse)
        fuse_destroy(fuse);
    
    if (fuse_fd >= 0)
        fuse_unmount(mountpoint);
    
    file_cache_close_all();
    cache_free();
    session_free();
    openssl_thread_cleanup();
    
    return ret;
}

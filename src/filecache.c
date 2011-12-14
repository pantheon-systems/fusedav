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

#include <errno.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <inttypes.h>
#include <limits.h>

#include <ne_props.h>
#include <ne_uri.h>
#include <ne_session.h>
#include <ne_utils.h>
#include <ne_socket.h>
#include <ne_auth.h>
#include <ne_dates.h>
#include <ne_basic.h>

#include "filecache.h"
#include "statcache.h"
#include "fusedav.h"
#include "session.h"

struct file_info {
    char *filename;
    int fd;
    off_t server_length, length, present;
    
    int readable;
    int writable;

    int modified;

    int ref, dead;

    pthread_mutex_t mutex;

    /* This field is locked by files_mutex, not by file_info->mutex */
    struct file_info *next;
};

static struct file_info *files = NULL;
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

static int file_cache_sync_unlocked(struct file_info *fi);

void* file_cache_get(const char *path) {
    struct file_info *f, *r = NULL;

    pthread_mutex_lock(&files_mutex);
    
    for (f = files; f; f = f->next) {
        
        pthread_mutex_lock(&f->mutex);
        if (!f->dead && f->filename && !strcmp(path, f->filename)) {
            f->ref++;
            r = f;
        }
        pthread_mutex_unlock(&f->mutex);

        if (r)
            break;
    }
    
    pthread_mutex_unlock(&files_mutex);
    return f;
}

static void file_cache_free_unlocked(struct file_info *fi) {
    assert(fi && fi->dead && fi->ref == 0);

    free(fi->filename);

    if (fi->fd >= 0)
        close(fi->fd);

    pthread_mutex_destroy(&fi->mutex);
    free(fi);
}

void file_cache_unref(void *f) {
    struct file_info *fi = f;
    assert(fi);

    pthread_mutex_lock(&fi->mutex);

    assert(fi->ref >= 1);
    fi->ref--;

    if (!fi->ref && fi->dead) {
        file_cache_sync_unlocked(fi);
        file_cache_free_unlocked(fi);
    }

    pthread_mutex_unlock(&fi->mutex);
}

static void file_cache_unlink(struct file_info *fi) {
    struct file_info *s, *prev;
    assert(fi);

    pthread_mutex_lock(&files_mutex);
    
    for (s = files, prev = NULL; s; s = s->next) {
        if (s == fi) {
            if (prev)
                prev->next = s->next;
            else
                files = s->next;

            break;
        }
        
        prev = s;
    }
    
    pthread_mutex_unlock(&files_mutex);
}

int file_cache_close(void *f) {
    struct file_info *fi = f;
    int r = 0;
    assert(fi);

    file_cache_unlink(f);

    pthread_mutex_lock(&fi->mutex);
    fi->dead = 1;
    pthread_mutex_unlock(&fi->mutex);

    return r;
}

void* file_cache_open(const char *path, int flags) {
    struct file_info *fi = NULL;
    char tempfile[PATH_MAX];
    const char *length = NULL;
    ne_request *req = NULL;
    ne_session *session;

    if (!(session = session_get(1))) {
        errno = EIO;
        goto fail;
    }

    if ((fi = file_cache_get(path))) {
        if (flags & O_RDONLY || flags & O_RDWR) fi->readable = 1;
        if (flags & O_WRONLY || flags & O_RDWR) fi->writable = 1;
        return fi;
    }

    fi = malloc(sizeof(struct file_info));
    memset(fi, 0, sizeof(struct file_info));
    fi->fd = -1;

    fi->filename = strdup(path);

    snprintf(tempfile, sizeof(tempfile), "%s/fusedav-cache-XXXXXX", "/tmp");
    if ((fi->fd = mkstemp(tempfile)) < 0)
        goto fail;
    unlink(tempfile);

    req = ne_request_create(session, "HEAD", path);
    assert(req);

    if (ne_request_dispatch(req) != NE_OK) {
        fprintf(stderr, "HEAD failed: %s\n", ne_get_error(session));
        errno = ENOENT;
        goto fail;
    }

    if (!(length = ne_get_response_header(req, "Content-Length")))
        /* dirty hack, since Apache doesn't send the file size if the file is empty */
        fi->server_length = fi->length = 0; 
    else
        fi->server_length = fi->length = atoi(length);

    ne_request_destroy(req);
    
    if (flags & O_RDONLY || flags & O_RDWR) fi->readable = 1;
    if (flags & O_WRONLY || flags & O_RDWR) fi->writable = 1;

    pthread_mutex_init(&fi->mutex, NULL);
    
    pthread_mutex_lock(&files_mutex);
    fi->next = files;
    files = fi;
    pthread_mutex_unlock(&files_mutex);

    fi->ref = 1;
    
    return fi;

fail:

    if (req)
        ne_request_destroy(req);

    if (fi) {
        if (fi->fd >= 0)
            close(fi->fd);
        free(fi->filename);
        free(fi);
    }
        
    return NULL;
}

static int load_up_to_unlocked(struct file_info *fi, off_t l) {

    ne_content_range range;
    ne_session *session;

    assert(fi);

    if (!(session = session_get(1))) {
        errno = EIO;
        return -1;
    }

    if (l > fi->server_length)
        l = fi->server_length;
    
    if (l <= fi->present)
        return 0;

    if (lseek(fi->fd, fi->present, SEEK_SET) != fi->present)
        return -1;
    
    range.start = fi->present;
    range.end = l-1;
    range.total = 0;
    
    if (ne_get_range(session, fi->filename, &range, fi->fd) != NE_OK) {
        fprintf(stderr, "GET failed: %s\n", ne_get_error(session));
        errno = ENOENT;
        return -1;
    }

    fi->present = l;
    return 0;
}

int file_cache_read(void *f, char *buf, size_t size, off_t offset) {
    struct file_info *fi = f;
    ssize_t r = -1;
    
    assert(fi && buf && size);

    pthread_mutex_lock(&fi->mutex);

    if (load_up_to_unlocked(fi, offset+size) < 0)
        goto finish;

    if ((r = pread(fi->fd, buf, size, offset)) < 0)
        goto finish;

finish:
    
    pthread_mutex_unlock(&fi->mutex);

    return r;
}

int file_cache_write(void *f, const char *buf, size_t size, off_t offset) {
    struct file_info *fi = f;
    ssize_t r = -1;

    assert (fi);

    pthread_mutex_lock(&fi->mutex);

    if (!fi->writable) {
        errno = EBADF;
        goto finish;
    }

    if (load_up_to_unlocked(fi, offset) < 0)
        goto finish;
        
    if ((r = pwrite(fi->fd, buf, size, offset)) < 0)
        goto finish;

    if (offset+size > fi->present)
        fi->present = offset+size;

    if (offset+size > fi->length)
        fi->length = offset+size;

    fi->modified = 1;

finish:
    pthread_mutex_unlock(&fi->mutex);
    
    return r;
}

int file_cache_truncate(void *f, off_t s) {
    struct file_info *fi = f;
    int r;

    assert(fi);

    pthread_mutex_lock(&fi->mutex);

    fi->length = s;
    r = ftruncate(fi->fd, fi->length);

    pthread_mutex_unlock(&fi->mutex);

    return r;
}

int file_cache_sync_unlocked(struct file_info *fi) {
    int r = -1;
    ne_session *session;

    assert(fi);
    
    if (!fi->writable) {
        errno = EBADF;
        goto finish;
    }

    if (!fi->modified) {
        r = 0;
        goto finish;
    }
    
    if (load_up_to_unlocked(fi, (off_t) -1) < 0)
        goto finish;

    if (lseek(fi->fd, 0, SEEK_SET) == (off_t)-1)
        goto finish;

    if (!(session = session_get(1))) {
        errno = EIO;
        goto finish;
    }
    
    if (ne_put(session, fi->filename, fi->fd)) {
        fprintf(stderr, "PUT failed: %s\n", ne_get_error(session));
        errno = ENOENT;
        goto finish;
    }

    stat_cache_invalidate(fi->filename);
    dir_cache_invalidate_parent(fi->filename);

    r = 0;

finish:
    
    return r;
}

int file_cache_sync(void *f) {
    struct file_info *fi = f;
    int r = -1;
    assert(fi);

    pthread_mutex_lock(&fi->mutex);
    r = file_cache_sync_unlocked(fi);
    pthread_mutex_unlock(&fi->mutex);
    
    return r;
}

int file_cache_close_all(void) {
    int r = 0;

    pthread_mutex_lock(&files_mutex);

    while (files) {
        struct file_info *fi = files;
        
        pthread_mutex_lock(&fi->mutex);
        fi->ref++;
        pthread_mutex_unlock(&fi->mutex);

        pthread_mutex_unlock(&files_mutex);
        file_cache_close(fi);
        file_cache_unref(fi);
        pthread_mutex_lock(&files_mutex);
    }

    pthread_mutex_unlock(&files_mutex);

    return r;
}

off_t file_cache_get_size(void *f) {
    struct file_info *fi = f;

    assert(fi);

    return fi->length;
}

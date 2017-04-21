#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

#define PATH_MAX 4096

static bool verbose = false;

static void usage() {
    printf("One arg, -v for verbose\n");
    exit(0);
}

static void v_printf(const char *fmt, ...) {
    if (verbose) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stdout, fmt, ap);
        va_end(ap);
    }
}

static int readdirectory(char *dirname, int *dirsread, int *filesread, int *errors) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    DIR * dir;
    int fd;

    dir = opendir(dirname);

    if (dir == NULL) {
        printf("FAIL: dir is NULL %d %s\n", errno, strerror(errno));
        return -1;
    }

    diriter = readdir(dir);

    while (diriter != NULL) {
        struct stat stbuf;
        v_printf("d_name %s\n", diriter->d_name);
        if (!strcmp(diriter->d_name, ".") || !strcmp(diriter->d_name, "..")) {
            diriter = readdir(dir);
            continue;
        }
        snprintf(fn, PATH_MAX , "%s/%s", dirname, diriter->d_name) ;
        if (stat(fn, &stbuf) == -1) {
            v_printf("stat -1 on %s :: %d %s\n", fn, errno, strerror(errno));
            ++*errors;
            diriter = readdir(dir);
            continue;
        }

        if (S_ISDIR(stbuf.st_mode)) {
            v_printf("directory: %s\n", fn);
            ++*dirsread;
            readdirectory(fn, dirsread, filesread, errors);
        }
        else {
            int bytes_read;
            char rbuf [1025];
            fd = open(fn, O_RDONLY);
            v_printf("file: %s\n", fn);
            ++*filesread;
            bytes_read = read(fd, rbuf, 1024);
            if (bytes_read < 0) {
                v_printf("read -1 on %s :: %d %s\n", fn, errno, strerror(errno));
            }
            close(fd);
        }
        diriter = readdir(dir);
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    char cwdbuf[PATH_MAX];
    // char *cvalue = NULL;
    int opt;
    int dirsread = 0;
    int filesread = 0;
    int errors = 0;

    while ((opt = getopt (argc, argv, "vh")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            //case 'c':
                //cvalue = optarg;
                //break;
            case 'h':
            case '?':
            default:
                usage ();
        }
    }

    getcwd(cwdbuf, PATH_MAX);
    if (readdirectory(cwdbuf, &dirsread, &filesread, &errors) < 0) {
        printf("FAIL: dirs read: %d files read:%d\n", dirsread, filesread);
        return(-1);
    }
    if (errors) {
        printf("FAIL: dirs read: %d; files read: %d; errors: %d\n", dirsread, filesread, errors);
    }
    else {
        printf("PASS: dirs read: %d files read:%d\n", dirsread, filesread);
    }
    return 0;
}

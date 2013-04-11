#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>

#define PATH_MAX 4096

bool verbose = false;

static void v_printf() {
    if (verbose) {
        printf();
    }
}

static int readdirectory(char *dirname) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    DIR * dir;
    int fd;

    for (int idx = 0; idx < 4096; idx++) {
        wbuf[idx] = ch;
        ++ch;
        if (ch > 'z') ch = 'A';
    }

    printf("dirname %s\n", dirname);

    dir = opendir(dirname);

    if (dir == NULL) {
        printf("dir is NULL %d %s\n", errno, strerror(errno));
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
            diriter = readdir(dir);
            continue;
        }

        if (S_ISDIR(stbuf.st_mode)) {
            v_printf("directory: %s\n", fn);
            readdirectory(fn);
        }
        else {
            fd = open(fn, O_RDWR);
            v_printf("file: %s :: %s :: %s\n", fn, cpfn, rnfn);
            close(fd);
        }
        diriter = readdir(dir);
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    char cwdbuf[PATH_MAX];

    char *cvalue = NULL;
    int index;
    int opt;

    opterr = 0;

    while ((opt = getopt (argc, argv, "abc:")) != -1) {
        switch (opt)
        {
            case 'v':
            verbose = 1;
            break;
            case 'b':
            bflag = 1;
            break;
            case 'c':
            cvalue = optarg;
            break;
            case '?':
            if (optopt == 'c')
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
            fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
            fprintf (stderr,
            "Unknown option character `\\x%x'.\n",
            optopt);
            return 1;
            default:
            abort ();
        }
    }

    printf ("aflag = %d, bflag = %d, cvalue = %s\n",
    aflag, bflag, cvalue);

    for (index = optind; index < argc; index++)
    printf ("Non-option argument %s\n", argv[index]);
    return 0;
    getcwd(cwdbuf, PATH_MAX);
    if (readdirectory(cwdbuf) < 0) {
        printf("EXIT\n");
        return(-1);
    }
    return 0;
}

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <getopt.h>

#define PATH_MAX 4096
static const int write_size = 1024;

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

static char randomchar() {
    int randval;

    randval = rand() % 52;
    randval += 'A';
    return (char)randval;
}

static int writeread(char *origfilename, char *newfilename) {
    char wbuf[write_size];
    int fd;

    for (int idx = 0; idx < write_size; idx++) {
        wbuf[idx] = randomchar();
    }

    v_printf("write: ");
    int bytes_written;
    fd = open(origfilename, O_RDWR | O_CREAT, 0640);
    if (fd < 0) {
        v_printf("OPEN ERROR: open failed on %s : %d %s\n", origfilename, errno, strerror(errno));
        return -1;
    }
    bytes_written = write(fd, wbuf, write_size);
    if (bytes_written != write_size) {
        v_printf("WRITE ERROR: bytes_written = %d, write_size = %d\n", bytes_written, write_size);
        return -3;
    }
    else {
        v_printf("Write Success: %s\n", origfilename);
    }

    sleep(10);

    if (rename(origfilename, newfilename) != 0) {
        v_printf("RENAME ERROR: old: %s; new: %s; errno: %d; err: %s\n", origfilename, newfilename, errno, strerror(errno));
        return -4;
    }

    close(fd);

    return 0;
}

int main(int argc, char *argv[]) {
    char dirname[] = "rename";
    char origfilename[] = "origfilename";
    char newfilename[] = "newfilename";
    char pathtofile[] = "rename/newfilename";
    int ret;
    int opt;
    bool fail = false;

    while ((opt = getopt (argc, argv, "uvh")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 'h':
            case '?':
            default:
                usage ();
        }
    }

    if (unlink(pathtofile) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete file %s. errno: %d; err: %s\n", pathtofile, errno, strerror(errno));
            exit(1);
        }
    }

    if (remove(dirname) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory. errno: %d; err: %s\n", errno, strerror(errno));
            exit(1);
        }
    }

    ret = mkdir(dirname, 0755);
    if (ret < 0) {
        printf("FAIL: Couldn't make directory %s. Exiting\n", dirname);
        exit(1);
    }
    ret = chdir(dirname);
    if (ret < 0) {
        printf("FAIL: Couldn't change to directory %s. Exiting\n", dirname);
        exit(1);
    }

    ret = writeread(origfilename, newfilename);
    if (ret < 0) {
        printf("writeread failed. exitcode: %d\n", ret);
        fail = true;
    }

    if (fail) {
        printf("FAIL:\n");
    }
    else {
        printf("PASS:\n");
    }
}

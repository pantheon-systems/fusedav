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

static int writeread(char *filename) {
    char wbuf[write_size];
    int fd;

    for (int idx = 0; idx < write_size; idx++) {
        wbuf[idx] = randomchar();
    }

    v_printf("write: ");
    int bytes_written;
    fd = open(filename, O_RDWR | O_CREAT, 0640);
    if (fd < 0) {
        v_printf("OPEN ERROR: open failed on %s : %d %s\n", filename, errno, strerror(errno));
        return -1;
    }
    v_printf("Unlinking %s\n", filename);
    if (unlink(filename) < 0) {
        v_printf("UNLINK ERROR: unlink failed on %s : %d %s\n", filename, errno, strerror(errno));
        return -2;
    }
    bytes_written = write(fd, wbuf, write_size);
    if (bytes_written != write_size) {
        v_printf("WRITE ERROR: bytes_written = %d, write_size = %d\n", bytes_written, write_size);
        return -3;
    }
    else {
        v_printf("Write Success: %s\n", filename);
    }
    close(fd);

    return 0;
}

int main(int argc, char *argv[]) {
    char dirname[] = "openunlinkclose";
    int ret;
    int opt;
    bool fail = false;

    while ((opt = getopt (argc, argv, "uvhf:")) != -1) {
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

    if (remove(dirname) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory\n");
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

    if (writeread(dirname) < 0) { // dirname is, oddly enough, the name of the file
        printf("writeread failed.\n");
        fail = true;
    }

    if (fail) {
        printf("FAIL:\n");
    }
    else {
        printf("PASS:\n");
    }
}

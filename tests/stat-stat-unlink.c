#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdlib.h>

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

int process(const int write_size, const int write_iters) {
    int failed = 0;
    int fd;
    struct stat sbuf;
    char ch = 'A';
    char buf[write_size];
    char filename[4096];
    int ret;

    v_printf("s%d i%d\n", write_size, write_iters);

    for (int idx = 0; idx < write_size; idx++) {
        buf[idx] = ch;
        ++ch;
        if (ch > 'z') ch = 'A';
    }

    strcpy(filename, "files/stat-stat");

    // Create a series of files
    fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0);

    // Make each file a larger size than the one before
    for (int kdx = 0; kdx < write_iters; kdx++) {
        write(fd, buf, write_size);
    }

    ret = unlink(filename);
    if (ret < 0) {
        v_printf("ERROR on unlink: %d: %s\n", errno, strerror(errno));
        ++failed;
    }
    ret = stat(filename, &sbuf);
    if (ret < 0) {
        v_printf("ERROR on stat or fstat: %d: %s\n", errno, strerror(errno));
        ++failed;
    }
    else {
        int expected_size;
        expected_size = write_size * write_iters;

        // fstat
        if (sbuf.st_size == expected_size) {
            v_printf("stat-stat After write, fstat got expected size of %d\n", sbuf.st_size);
        }
        else {
            v_printf("stat-stat After write, fstat ERROR expected %d size is %d\n", expected_size, sbuf.st_size);
            ++failed;
        }
    }
    close(fd);
    return failed;
}

int main(int argc, char *argv[]) {
    int ret;
    int opt;
    int write_size = 32;
    int write_iters = 16;
    int failed;

    while ((opt = getopt (argc, argv, "vhf:r:s:i:")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 's':
                write_size = strtol(optarg, NULL, 10);
                break;
            case 'i':
                write_iters = strtol(optarg, NULL, 10);
                break;
            case 'h':
            case '?':
            default:
                usage ();
        }
    }

    failed = process(write_size, write_iters);
    if (failed > 0) {
        printf("FAIL: failures %d\n", failed);
    }
    else {
        printf("PASS:\n");
    }
}

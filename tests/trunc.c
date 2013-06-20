#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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

int process(const int rounds, const int num_files, const int write_size, const int write_iters) {
    int failed = 0;
    int fd[num_files];
    struct stat sbuf[num_files];
    char ch = 'A';
    char buf[write_size];
    char basename[4096];
    char filename[4096];
    int ret;

    v_printf("r%d n%d s%d i%d\n", rounds, num_files, write_size, write_iters);

    for (int idx = 0; idx < write_size; idx++) {
        buf[idx] = ch;
        ++ch;
        if (ch > 'z') ch = 'A';
    }

    strcpy(basename, "zerolength-");

    for (int hdx = 0; hdx < rounds; hdx++) {
        v_printf("Round: %d\n", hdx);
        for (int idx = 0; idx < num_files; idx++) {
            int curidx = idx;
            sprintf(filename, "%s%d", basename, curidx);
            if (hdx == 0) unlink(filename);
            fd[curidx] = open(filename, O_RDWR | O_CREAT | O_APPEND, 0);
            ret = fstat(fd[curidx], &sbuf[curidx]);
            if (ret < 0) {
                v_printf("ERROR on fstat\n");
                ++failed;
            }
            else {
                int expected_size;
                if (hdx == 0) expected_size = 0;
                else if (idx % 2 == 0) expected_size = 0;
                else expected_size = (hdx * (num_files - idx)) * (write_iters * write_size);
                if (sbuf[curidx].st_size == expected_size) {
                    v_printf("%d. %s On create, got expected size %d\n", hdx, filename, sbuf[curidx].st_size);
                }
                else {
                    v_printf("%d: %s On create, ERROR expected %d size is %d\n", hdx, filename, expected_size, sbuf[curidx].st_size);
                    ++failed;
                }
            }
            for (int jdx = 0; jdx <= curidx; jdx++) {
                for (int kdx = 0; kdx < write_iters; kdx++) {
                    write(fd[jdx], buf, write_size);
                }
            }
        }
        for (int idx = 0; idx < num_files; idx++) {
            ret = fstat(fd[idx], &sbuf[idx]);
            if (ret < 0) {
                v_printf("ERROR on fstat\n");
                ++failed;
            }
            else {
                int expected_size;
                if (idx % 2 == 0) {
                    expected_size = (num_files - idx) * (write_iters * write_size);
                }
                else {
                    expected_size = ((hdx + 1) * (num_files - idx)) * (write_iters * write_size);
                }
                if (sbuf[idx].st_size == expected_size) {
                    v_printf("%d. zerolength-%d After write, got expected size of %d\n", hdx, idx, sbuf[idx].st_size);
                }
                else {
                    v_printf("%d. zerolength-%d After write, ERROR expected %d size is %d\n", hdx, idx, expected_size, sbuf[idx].st_size);
                    ++failed;
                }
            }
            close(fd[idx]);
        }
        for (int idx = 0; idx < num_files; idx++) {
            int curidx = idx;
            int flags;
            sprintf(filename, "%s%d", basename, curidx);
            if (idx % 2 == 0) flags = O_RDWR | O_TRUNC;
            else flags = O_RDWR;
            fd[curidx] = open(filename, flags, 0);
            ret = fstat(fd[curidx], &sbuf[curidx]);
            if (ret < 0) {
                v_printf("ERROR on fstat\n");
                ++failed;
            }
            else {
                int expected_size;
                if (flags & O_TRUNC) expected_size = 0;
                else expected_size = sbuf[curidx].st_size; // tautology
                if (sbuf[curidx].st_size == expected_size) {
                    v_printf("%d. %s After reopen, expect %d size is %d\n", hdx, filename, expected_size, sbuf[curidx].st_size);
                }
                else {
                    v_printf("%d. %s After reopen, ERROR expect %d size is %d\n", hdx, filename, expected_size, sbuf[curidx].st_size);
                    ++failed;
                }
            }
        }
    }
    return failed;
}

int main(int argc, char *argv[]) {
    int ret;
    int opt;
    int num_files = 8; // default for unit test
    int rounds = 8;
    int write_size = 32;
    int write_iters = 16;
    int failed;

    while ((opt = getopt (argc, argv, "vhf:r:s:i:")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 'f':
                num_files = strtol(optarg, NULL, 10);
                break;
            case 'r':
                rounds = strtol(optarg, NULL, 10);
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

    failed = process(rounds, num_files, write_size, write_iters);
    if (failed > 0) {
        printf("FAIL: failures %d\n", failed);
    }
    else {
        printf("PASS:\n");
    }
}

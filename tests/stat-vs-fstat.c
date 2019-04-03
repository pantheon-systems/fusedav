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
    struct stat fsbuf[num_files];
    struct stat sbuf[num_files];
    char ch = 'A';
    char buf[write_size];
    char basename[4096];
    char filename[4096];
    int sret;
    int fsret;

    v_printf("r%d n%d s%d i%d\n", rounds, num_files, write_size, write_iters);

    for (int idx = 0; idx < write_size; idx++) {
        buf[idx] = ch;
        ++ch;
        if (ch > 'z') ch = 'A';
    }

    strcpy(basename, "files/stat-vs-fstat-");

    // Create a series of files
    for (int idx = 1; idx <= num_files; idx++) {
        sprintf(filename, "%s%d", basename, idx-1);
        fd[idx] = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0);

        // Make each file a larger size than the one before
        for (int kdx = 0; kdx < write_iters; kdx++) {
            write(fd[idx], buf, idx * write_size);
        }
    }
    for (int idx = 1; idx <= num_files; idx++) {
        sprintf(filename, "%s%d", basename, idx);
        fsret = fstat(fd[idx], &fsbuf[idx]);
        // sret = stat(filename, &sbuf[idx]);
        if (fsret < 0 || sret < 0) {
            v_printf("ERROR on stat or fstat\n");
            ++failed;
        }
        else {
            int expected_size;
            expected_size = idx * write_size * write_iters;

            // fstat
            if (fsbuf[idx].st_size == expected_size) {
                v_printf("stat-vs-fstat-%d After write, fstat got expected size of %d\n", idx, fsbuf[idx].st_size);
            }
            else {
                v_printf("stat-vs-fstat-%d After write, fstat ERROR expected %d size is %d\n", idx, expected_size, fsbuf[idx].st_size);
                ++failed;
            }
   
            /*
            // stat
            if (sbuf[idx].st_size == expected_size) {
                v_printf("stat-vs-fstat-%d After write, stat got expected size of %d\n", idx, sbuf[idx].st_size);
            }
            else {
                v_printf("stat-vs-fstat-%d After write, stat ERROR expected %d size is %d\n", idx, expected_size, sbuf[idx].st_size);
                ++failed;
            }
            */
        }
        close(fd[idx]);
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

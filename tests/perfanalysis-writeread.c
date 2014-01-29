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
static const int xl = 0;
static const int lg = 1;
static const int med = 2;
static const int sm = 3;
static const int xs = 4;
static const int num_sizes = 5;

static const int xlfile_size = 1024 * 1024 * 100;
static const int lgfile_size = 1024 * 1024 * 10;
static const int medfile_size = 1024 * 1024;
static const int smfile_size = 1024 * 100;
static const int xsfile_size = 1024 * 10;

static const int Reads = 0;
static const int ReadErrors = 1;
static const int Writes = 2;
static const int WriteErrors = 3;
static const int OpenErrors = 4;

/* Update ResultSize after adding more entries above */
static const int ResultSize = 5; // OpenErrors + 1;

static const int max_iters = 64; // Can't have more than 64 iters
static const int collection_points = 4; // read/write start/end
static const int write_start = 0;
static const int write_end = 1;
static const int read_start = 2;
static const int read_end = 3;

static bool verbose = false;
static bool doing_write = true;

struct size_s {
    char name[16];
    int size;
    int interval;
};

struct size_s sizes[] = { {"xl", 1024 * 1024 * 100, 40},
                        {"lg", 1024 * 1024 * 10, 20},
                        {"med", 1024 * 1024, 4},
                        {"sm", 1024 * 100, 2},
                        {"xs", 1024 * 10, 2}
                      };


static void usage() {
    printf("-t <start_time> unix epoch time to start write at (REQUIRED)\n");
    printf("-n <interval> time between write starts, 10 by default\n");
    printf("-i <iters> number of writes, 16 by default\n");
    printf("-v for verbose\n");
    printf("-h for help\n");
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

static int writeread(char *basename, int results[], time_t start_time, unsigned num_iters, unsigned interval,
        time_t latencyResults[2][max_iters][collection_points]) {
    char *wbuf;
    char filename[PATH_MAX];
    int fd;
    time_t current_time;

    wbuf = calloc(xlfile_size, sizeof(char));

    // Make one buffer at max size
    for (int idx = 0; idx < xlfile_size; idx++) {
        wbuf[idx] = randomchar();
    }

    current_time = time(NULL);
    if (current_time > start_time) {
        printf("ERROR: start_time is in the past\n");
        printf("Exiting ...\n");
        return -1;
    }
    sleep(start_time - current_time);

    for (int idx = 0; idx < num_sizes; idx++) {
        for (int iter = 0; iter < num_iters; iter++) {
            time_t sleep_time;

            if (doing_write) {
                int bytes_written;
                v_printf("write: ");
                sprintf(filename, "%s-%s-%d", basename, sizes[idx].name, iter);
                unlink(filename);
                latencyResults[idx][iter][write_start] = time(NULL);
                fd = open(filename, O_RDWR | O_CREAT, 0640);
                if (fd < 0) {
                    ++results[OpenErrors];
                    v_printf("OPEN ERROR: open failed on %s : %d %s\n", filename, errno, strerror(errno));
                    latencyResults[idx][iter][write_end] = time(NULL);
                }
                else {
                    v_printf(".");
                    v_printf("%d: %lu: ", idx, latencyResults[idx][iter][write_start]);
                    bytes_written = write(fd, wbuf, sizes[idx].size);
                    latencyResults[idx][iter][write_end] = time(NULL);
                    v_printf("%d: %lu: ", idx, latencyResults[idx][iter][write_end]);
                    if (bytes_written != sizes[idx].size) {
                        ++results[WriteErrors];
                        v_printf("WRITE ERROR: bytes_written = %d, write_size = %d\n", bytes_written, sizes[idx].size);
                    }
                    else {
                        ++results[Writes];
                        v_printf("Write Success: %s\n", filename);
                    }
                    close(fd);
                }
            }
            else {
                int bytes_read;
                char *rbuf = wbuf;
                v_printf("read: ");
                sprintf(filename, "%s-%s-%d", basename, sizes[idx].name, iter);
                latencyResults[idx][iter][read_start] = time(NULL);
                fd = -1;
                for (int idx = 0; idx < 4, fd < 0; idx++) {
                    fd = open(filename, O_RDWR , 0640);
                    if (fd < 0) sleep(1);
                }
                if (fd < 0) {
                    ++results[OpenErrors];
                    v_printf("OPEN ERROR: open failed on %s : %d %s\n", filename, errno, strerror(errno));
                    latencyResults[idx][iter][read_end] = time(NULL);
                }
                else {
                    v_printf(".");
                    v_printf("%d: %lu: ", idx, latencyResults[idx][iter][read_start]);
                    bytes_read = read(fd, rbuf, sizes[idx].size);
                    latencyResults[idx][iter][read_end] = time(NULL);
                    v_printf("%d: %lu: ", idx, latencyResults[idx][iter][read_end]);
                    if (bytes_read != sizes[idx].size) {
                        ++results[ReadErrors];
                        v_printf("READ ERROR: bytes_read = %d, read_size = %d : %d %s\n", bytes_read, sizes[idx].size, errno, strerror(errno));
                    }
                    else {
                        ++results[Reads];
                        v_printf("Read Success: %s\n", filename);
                    }
                    close(fd);
                }
            }
            
            v_printf("\n");
            start_time += sizes[idx].interval;
            current_time = time(NULL);
            sleep_time = start_time - current_time;
            if (sleep_time < 0) {
                printf("ERROR: The next start_time is in the past: st-%lu, ct-%lu\n", start_time, current_time);
                printf("Exiting ...\n");
                return -1;
            }
            sleep(sleep_time);
        }
    }
    
    return 0;
}

void calculate_latencies(time_t latencyResults[num_sizes][max_iters][collection_points], int num_iters) {
    time_t latency[num_sizes];

    for (int idx = 0; idx < num_sizes; idx++) { // big-little files
        latency[idx] = 0;
        for (int jdx = 0; jdx < num_iters; jdx++) {
            if (doing_write) {
                latency[idx] += (latencyResults[idx][jdx][write_end] - latencyResults[idx][jdx][write_start]);
                v_printf("wl: %lu\n", latency[idx]);
            }
            else {
                latency[idx] += (latencyResults[idx][jdx][read_end] - latencyResults[idx][jdx][read_start]);
                v_printf("rl: %lu\n", latency[idx]);
            }
        }
        printf("%s file latency = %f\n", sizes[idx].name, (double)latency[idx] / num_iters);
    }
}

int main(int argc, char *argv[]) {
    char filename[] = "perfanalysis";
    int ret;
    int opt;
    unsigned num_iters = 8; // default for unit test, 8 big, 8 little files
    unsigned interval = 20; // default number of seconds between write starts
    time_t start_time = 0; // Need a start time to coordinate two processes
    int errors = 0;
    int results[ResultSize];
    time_t latencyResults[2][max_iters][collection_points];
    bool fail = false;

    while ((opt = getopt (argc, argv, "vhi:t:")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 'i':
                num_iters = strtol(optarg, NULL, 10);
                break;
            case 't':
                start_time = strtol(optarg, NULL, 10);
                start_time += 60; // You've got 60 seconds to get everything setup!
                break;
            case 'n':
                interval = strtol(optarg, NULL, 10);
                break;
            case 'h':
            case '?':
            default:
                usage ();
        }
    }

    if (start_time == 0) {
        printf("Requires -t <start_time>\n");
        usage();
    }

    if (num_iters > max_iters) num_iters = max_iters;

    if (strstr(argv[0], "write")) {
        doing_write = true;
    }
    else {
        doing_write = false;
        start_time += 1; // Make reads start a second later; they will self-correct to start after the write has finished
    }

    for (int idx = 0; idx < ResultSize; idx++) {
        results[idx] = 0;
    }

    if (writeread(filename, results, start_time, num_iters, interval, latencyResults) < 0) {
        printf("writeread returns error.\n");
        fail = true;
    }

    if (!fail) calculate_latencies(latencyResults, num_iters);
    
    if (results[ReadErrors] > 0 || results[WriteErrors] > 0 || results[OpenErrors] > 0) {
        fail = true;
    }
    if (fail) {
        printf("FAIL: reads %d writes %d read errors %d write errors %d open errors %d\n",
               results[Reads], results[Writes], results[ReadErrors], results[WriteErrors], results[OpenErrors]);
    }
    else {
        printf("PASS: reads %d writes %d\n",
               results[Reads], results[Writes]);
    }
}

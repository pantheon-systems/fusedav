/* About this test:
 * Run this test in conjunction with inject-error test filecache_forensic_haven_test
 * (in util.c). It will inject a series of errors. This test is still beta in that
 * it does not return any pass/fail notification (it is designed to have lots
 * of errors in any case).
 * In principle, it dumps errors to <...>/files/forensic-haven-test-errors. This file can be
 * merged with the journalctl output and checked to see which errors at
 * the application level cause which errors at the fusedav level.
 * In practice, if you run this test overnight and there are no failures
 * (e.g. segmentation violation), then "touchdown!"
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define bufsz 26
#define filenames 64
// if writes is 1024 * 128, it takes about 17 seconds per filename loop, which is what
// the sleep in the inject error routine is set to.
#define writes 1024*128

static char * mytime(char *fstr, int strsz) {
    time_t tm = time(NULL);
    strftime(fstr, strsz, "%b %d %H:%M:%S", gmtime(&tm));
    return fstr;
}

int main() {
    int fd[filenames];
    int res;
    char filename[filenames][80];
    char wbuf[bufsz] = "abcdefghijklmnopqrstuvwxyz";
    char rbuf[bufsz];
    const int iters = 1024 * 1024;
    int errfd;
    char errstr[1024];
    
    // unlink("forensic-haven-test-errors");
    errfd = open("forensic-haven-test-errors", O_WRONLY | O_CREAT);
    if (errfd < 0) {
        printf("Error opening error file (%d %s). Exiting...\n", errno, strerror(errno));
        exit(1);
    }
    
    for(int jdx = 0; jdx < iters; jdx++) {
        for(int idx = 0; idx < filenames; idx++) {
            char fstr[80];
            sprintf(filename[idx], "forensic-haven-test-%d", idx);
            printf("Opening %s\n", filename[idx]);
            sleep(3); // Give fusedav a chance to reset an injected error that might affect open
            fd[idx] = open(filename[idx], O_RDWR | O_CREAT);
            if (fd[idx] < 0) {
                printf("%s zError on open: %s; %d %s\n", mytime(fstr, sizeof(fstr)), filename[idx], errno, strerror(errno));
                continue;
            }
            printf("Writing %s\n", filename[idx]);
            for (int jdx = 0; jdx < writes; jdx++) {
                // No need to sleep for writes for injected errors since we do enough of them to take up time
                int bytes_written = write(fd[idx], wbuf, bufsz);
                if (bytes_written < 1) {
                    sprintf(errstr, "%s zError on write %s: %d %s\n", mytime(fstr, sizeof(fstr)), filename[idx], errno, strerror(errno));
                    printf("%s", errstr);
                    write(errfd, errstr, sizeof(errstr));
                }
            }
            
            printf("lseek on %s\n", filename[idx]);
            sleep(3); // Give fusedav a chance to reset an injected error that might affect lseek
            res = lseek(fd[idx], 0, SEEK_SET);
            if (res) {
                sprintf(errstr, "%s zError on lseek on %s: %d %s\n", mytime(fstr, sizeof(fstr)), filename[idx], errno, strerror(errno));
                printf("%s", errstr);
                write(errfd, errstr, sizeof(errstr));
            }
            
            printf("Reading %s\n", filename[idx]);
            for (int jdx = 0; jdx < writes; jdx++) {
                int bytes_read = read(fd[idx], rbuf, bufsz);
                if (bytes_read < 1) {
                    sprintf(errstr, "%s zError on read %s: %d %s\n", mytime(fstr, sizeof(fstr)), filename[idx], errno, strerror(errno));
                    printf("%s", errstr);
                    write(errfd, errstr, sizeof(errstr));
                }
            }
    
            printf("Closing %s\n", filename[idx]);
            close(fd[idx]);
            if (idx % 2 == 0) {
                printf("Unlinking %s\n", filename[idx]);
                sleep(3); // Give fusedav a chance to reset an injected error that might affect unlink
                res = unlink(filename[idx]);
                if (res) {
                    sprintf(errstr, "%s zError on unlink %s: %d %s\n", mytime(fstr, sizeof(fstr)), filename[idx], errno, strerror(errno));
                    printf("%s", errstr);
                    write(errfd, errstr, sizeof(errstr));
                }
            }
        }
    }
}

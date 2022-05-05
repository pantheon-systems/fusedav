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

static const int Reads = 0;
static const int ReadErrors = 1;
static const int Writes = 2;
static const int WriteErrors = 3;
static const int Compares = 4;
static const int CompareErrors = 5;
static const int DirReads = 6;
static const int FileReads = 7;
static const int FilesizeErrors = 8;
static const int StatErrors = 9;
static const int OpenErrors = 10;
static const int UnlinkErrors = 11;

/* Update ResultSize after adding more entries above */
static const int ResultSize = 12; // UnlinkErrors + 1;

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

static int writeread(char *basename, int results[], bool do_unlink, const int num_files) {
    char wbuf[num_files][write_size];
    char rbuf[num_files][write_size];
    char filename[PATH_MAX];
    const int write_iters = 16;
    int fd[num_files];

    for (int jdx = 0; jdx < num_files; jdx++) {
        for (int idx = 0; idx < write_size; idx++) {
            wbuf[jdx][idx] = randomchar();
        }
    }

    v_printf("write: ");
    for (int idx = 0; idx < num_files; idx++) {
        int bytes_written;
        sprintf(filename, "%s-%d", basename, idx);
        fd[idx] = open(filename, O_RDWR | O_CREAT, 0640);
        if (fd[idx] < 0) {
            ++results[OpenErrors];
            v_printf("OPEN ERROR: open failed on %s : %d %s\n", filename, errno, strerror(errno));
        }
        else {
            v_printf(".");
            /* Unlink and see if we still succeed with bare file descriptors */
            if (do_unlink) {
                v_printf("Unlinking %s\n", filename);
                if (unlink(filename) < 0) {
                    ++results[UnlinkErrors];
                    v_printf("UNLINK ERROR: unlink failed on %s : %d %s\n", filename, errno, strerror(errno));
                }
            }
            bytes_written = write(fd[idx], wbuf[idx], write_size);
            if (bytes_written != write_size) {
                ++results[WriteErrors];
                v_printf("WRITE ERROR: bytes_written = %d, write_size = %d\n", bytes_written, write_size);
            }
            else {
                ++results[Writes];
                v_printf("Write Success: %s\n", filename);
            }
            close(fd[idx]);
        }
    }

    // If we've unlinked the file above, there's no file to open and read from here.
    // This gives us a new, empty file to read from.
    // So just return.
    if (do_unlink) return 0;

    v_printf("\n\nread");
    for (int idx = 0; idx < num_files; idx++) {
        int bytes_read;
        sprintf(filename, "%s-%d", basename, idx);
        fd[idx] = open(filename, O_RDWR | O_CREAT, 0640);
        if (fd[idx] < 0) {
            ++results[OpenErrors];
        }
        else {
            bytes_read = read(fd[idx], rbuf[idx], write_size);
            if (bytes_read != write_size) {
                ++results[ReadErrors];
                v_printf("Read Error: %s: bytes_read = %d, write_size = %d\n", filename, bytes_read, write_size);
            }
            else {
                ++results[Reads];
                v_printf("Read Success: %s\n", filename);

                close(fd[idx]);
                if (strncmp(rbuf[idx], wbuf[idx], write_size)) {
                    char wtmp[81];
                    char rtmp[81];
                    wtmp[80] = '\0';
                    rtmp[80] = '\0';
                    strncpy(wtmp, wbuf[idx], 80);
                    strncpy(rtmp, rbuf[idx], 80);
                    v_printf("Compare Error on %s\n", filename);
                    v_printf("wbuf: %s\n", wtmp);
                    v_printf("rbuf: %s\n", rtmp);
                    ++results[CompareErrors];
                }
                else {
                    ++results[Compares];
                    v_printf(".");
                }
            }
        }
    }
    v_printf("\n");
    return 0;
}

static int check_filesizes(char *dirname, bool rm, int results[]) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    DIR * dir;

    v_printf("dirname %s\n", dirname);

    dir = opendir(dirname);

    if (dir == NULL) {
        if (!rm) v_printf("FAIL: dir is NULL %d %s\n", errno, strerror(errno));
        return -1;
    }

    diriter = readdir(dir);

    while (diriter != NULL) {
        struct stat stbuf;
        // v_printf("d_name %s\n", diriter->d_name);
        if (!strcmp(diriter->d_name, ".") || !strcmp(diriter->d_name, "..")) {
            diriter = readdir(dir);
            continue;
        }
        snprintf(fn, PATH_MAX , "%s/%s", dirname, diriter->d_name) ;
        if (stat(fn, &stbuf) == -1) {
            v_printf("stat -1 on %s :: %d %s\n", fn, errno, strerror(errno));
            ++results[StatErrors];
            diriter = readdir(dir);
            continue;
        }

        if (S_ISDIR(stbuf.st_mode)) {
            ++results[DirReads];
            v_printf("directory: %s\n", fn);
            check_filesizes(fn, false, results);
        }
        else {
            if (rm) {
                remove(fn);
            }
            else if (stbuf.st_size != write_size) {
                ++results[FilesizeErrors];
                v_printf("ERROR: file: %s -- st_size: %d (expected %d)\n", fn, stbuf.st_size, write_size);
            }
            else {
                ++results[FileReads];
            }
        }
        diriter = readdir(dir);
    }
    closedir(dir);
    return 0;
}

int main(int argc, char *argv[]) {
    char dirname[] = "readwhatwaswritten";
    int ret;
    bool do_unlink = false;
    int opt;
    int num_files = 16; // default for unit test
    int dirsread = 0;
    int filesread = 0;
    int errors = 0;
    int results[ResultSize];
    bool fail = false;

    while ((opt = getopt (argc, argv, "uvhf:")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 'u':
                do_unlink = true;
                break;
            case 'f':
                num_files = strtol(optarg, NULL, 10);
                break;
            case 'h':
            case '?':
            default:
                usage ();
        }
    }

    for (int idx = 0; idx < ResultSize; idx++) {
        results[idx] = 0;
    }

    if (check_filesizes(dirname, true, results) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory contents\n");
            exit(1);
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
        printf("FAIL: Couldn't make directory %s (%s: %i). Exiting\n", dirname, strerror(errno), errno);
        exit(1);
    }
    ret = chdir(dirname);
    if (ret < 0) {
        printf("FAIL: Couldn't change to directory %s (%s: %i). Exiting\n", dirname, strerror(errno), errno);
        exit(1);
    }

    if (writeread(dirname, results, do_unlink, num_files) < 0) { // dirname is, oddly enough, the name of the file
        printf("Couldn't read directory.\n");
        fail = true;
    }

    if (check_filesizes(".", false, results) < 0) {
        v_printf("Failed to read directory.\n");
        fail = true;
    }

    if (results[ReadErrors] > 0 || results[WriteErrors] > 0 || results[CompareErrors] > 0 ||
        results[FilesizeErrors] > 0 || results[StatErrors] > 0 || results[UnlinkErrors] > 0) {
        fail = true;
    }
    if (fail) {
        printf("FAIL: reads %d writes %d compares %d dir reads %d file reads %d "
               "read errors %d write errors %d compare errors %d filesize errors %d stat errors %d open errors %d "
               "unlink errors %d\n",
               results[Reads], results[Writes], results[Compares], results[DirReads], results[FileReads],
               results[ReadErrors], results[WriteErrors], results[CompareErrors], results[FilesizeErrors],
               results[StatErrors], results[OpenErrors], results[UnlinkErrors]);
    }
    else {
        printf("PASS: reads %d writes %d compares %d dir reads %d file reads %d\n",
               results[Reads], results[Writes], results[Compares], results[DirReads], results[FileReads]);
    }
}

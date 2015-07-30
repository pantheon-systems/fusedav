/* About this test:
 * This test is derived from continualwrites.c
 * Start this test, then in the middle of the writes, stop valhalla
 * (systemctl stop nginx_valhalla.service is one approach). Then
 * see what happens.
 */
 

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
#define FHFMAX 256
#define FHFSIZE 64
#define RBUFSZ 1025
#define one_write_size 1024
#define write_iters 16
#define total_write_size (one_write_size * write_iters)

static const int Writes = 0;
// static const int CorrectSize = 1;
// static const int FHFound = 2;
static const int WriteErrors = 3;
// static const int DirReads = 4;
// static const int FilesizeErrors = 5;
// static const int StatErrors = 6;
static const int OpenErrors = 7;
// static const int FHOpenErrors = 8;
// static const int FHReadErrors = 9;
// static const int FHMissingErrors = 10;
// static const int CWOpenErrors = 11;
 
/* Update ResultSize after adding more entries above */
static const int ResultSize = 12; // CWOpenErrors + 1;

static bool verbose = false;
static bool vverbose = false;

static void usage() {
    printf("-v for verbose; -w for very verbose; -f# for number of files (over 16 corrupts stack)\n");
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

static void vv_printf(const char *fmt, ...) {
    if (vverbose) {
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

static int writeread(char *basename, int results[], const int num_files, char failedfiles[FHFMAX][FHFSIZE]) {
    char wbuf[num_files][write_iters][one_write_size];
    char filename[PATH_MAX];
    int fd[num_files];
    int cdx = 0;

    for (int idx = 0; idx < num_files; idx++) {
        for (int jdx = 0; jdx < write_iters; jdx++) {
            for (int kdx = 0; kdx < one_write_size; kdx++) {
                wbuf[idx][jdx][kdx] = randomchar();
            }
        }
    }

    vv_printf("write: ");
    for (int idx = 0; idx < num_files; idx++) {
        int bytes_written;
        sprintf(filename, "%s-%d", basename, idx);
        fd[idx] = open(filename, O_RDWR | O_CREAT, 0640);
        if (fd[idx] < 0) {
            ++results[OpenErrors];
            v_printf("OPEN ERROR: open failed on %s : %d %s\n", filename, errno, strerror(errno));
        }
        else {
            if (!verbose) printf(".");
            printf("Shut valhalla down now! (systemctl stop nginx_valhalla.service\n");
            sleep(23);

            for (int jdx = 0; jdx < write_iters; jdx++) {
                bytes_written = write(fd[idx], wbuf[idx][jdx], one_write_size);
                if (bytes_written == -1) {
                    ++results[WriteErrors];
                    v_printf("WRITE ERROR: %s: bytes_written = -1, errno = %d (%s)\n", filename, errno, strerror(errno));
                    strcpy(failedfiles[cdx++], filename);
                }
                else if (bytes_written != one_write_size) {
                    ++results[WriteErrors];
                    v_printf("WRITE ERROR: %s: bytes_written = %d, one_write_size = %d\n", filename, bytes_written, one_write_size);
                }
                else {
                    ++results[Writes];
                    vv_printf("Write Success: %s\n", filename);
                }
                printf("Sleep between writes to better view journalctl output\n");
                sleep(2);
            }
            close(fd[idx]);
        }
    }

    v_printf("\n");
    return 0;
}

/*
static int check_continualwrites_dir(char *dirname, int results[], char failedfiles[FHFMAX][FHFSIZE]) {
    char fn[PATH_MAX];
    int numff = 0;

    vv_printf("dirname %s\n", dirname);
    
    for (int idx = 0; failedfiles[idx][0] != '\0'; idx++) {
        ++numff;
    }

    // Failed files should not be in the diretory; they should fail the open
    for (int idx = 0; idx < numff; idx++) {
        int fd;
        snprintf(fn, PATH_MAX , "%s/%s", dirname, failedfiles[idx]) ;
        vv_printf("continualwrites: opening %s\n", fn);

        fd = open(fn, O_RDONLY);
        if (fd >= 0) {
            ++results[CWOpenErrors];
            v_printf("FAIL: opened %s in continualwrites (should've failed)\n", fn);
        }
        else {
            vv_printf("SUCCESS: correctly failed to open %s in continualwrites: %d %s\n", fn, errno, strerror(errno));
        }
        close(fd);
    }
}
*/

/*
static int check_forensic_haven(char *dirname, int results[], char failedfiles[FHFMAX][FHFSIZE]) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    char rbuf[RBUFSZ];
    DIR * dir;
    int numff = 0;

    vv_printf("dirname %s\n", dirname);
    
    for (int idx = 0; failedfiles[idx][0] != '\0'; idx++) {
        ++numff;
    }

    dir = opendir(dirname);

    if (dir == NULL) {
        v_printf("FAIL: dir %s is NULL %d %s\n", dirname, errno, strerror(errno));
        return -1;
    }

    while ((diriter = readdir(dir)) != NULL) {
        int res = -1;
        bool success = false;
        int fd;
        
        if (!strcmp(diriter->d_name, ".") || !strcmp(diriter->d_name, "..")) {
            vv_printf("ignoring . and ..\n");
            continue;
        }
        
        // Only interested in .txt files
        if (!strstr(diriter->d_name, ".txt")) continue;
         
        snprintf(fn, PATH_MAX , "%s/%s", dirname, diriter->d_name) ;
        
        vv_printf("forensic-haven: opening %s\n", fn);

        fd = open(fn, O_RDONLY);
        if (fd < 0) {
            ++results[FHOpenErrors];
            v_printf("FAIL: failed to open %s in forensic-haven: %d %s\n", diriter->d_name, errno, strerror(errno));
            continue;
        }
        
        res = read(fd, rbuf, RBUFSZ - 1);
        if (res < 0) {
            ++results[FHReadErrors];
            v_printf("FAIL: failed to read %s in forensic-haven: %d %s\n", diriter->d_name, errno, strerror(errno));
            continue;
        }
        
        close(fd);
        
        rbuf[RBUFSZ - 1] = '\0';
        for (int idx = 0; idx < numff; idx++) {
            char rbuf80[80];
            strncpy(rbuf80, rbuf, 80);
            vv_printf("%s\n%s\n", failedfiles[idx], rbuf80);
            if (strstr(rbuf, failedfiles[idx])) {
                // do something to show this file has been found
                failedfiles[idx][0] = 'F';
                ++results[FHFound];
                break;
            }
        }
    }
    // See who's left
    for (int idx = 0; idx < numff; idx++) {
        if (failedfiles[idx][0] != 'F') {
            v_printf("check_forensic_haven: failed to find %s in forensic haven\n", failedfiles[idx]);
            ++results[FHMissingErrors];
        }
    }
}
*/

static int clear_directory(char *dirname) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    DIR * dir;

    vv_printf("dirname %s\n", dirname);

    dir = opendir(dirname);

    if (dir == NULL) {
        v_printf("FAIL: dir is NULL %d %s\n", errno, strerror(errno));
        return -1;
    }

    diriter = readdir(dir);
    
    if (diriter == NULL) {
        v_printf("FAIL: diriter is NULL %d %s\n", errno, strerror(errno));
    }

    while (diriter != NULL) {
        struct stat stbuf;
        vv_printf("d_name %s\n", diriter->d_name);
        if (!strcmp(diriter->d_name, ".") || !strcmp(diriter->d_name, "..")) {
            vv_printf("ignoring . and ..\n");
            diriter = readdir(dir);
            continue;
        }
        snprintf(fn, PATH_MAX , "%s/%s", dirname, diriter->d_name) ;

        if (S_ISDIR(stbuf.st_mode)) {
            vv_printf("directory: %s\n", fn);
            clear_directory(fn);
        }
        else {
            remove(fn);
        }
        diriter = readdir(dir);
    }
    closedir(dir);
    return 0;
}

/*
static int check_filesizes(char *dirname, bool rm, int results[]) {
    struct dirent *diriter;
    char fn[PATH_MAX];
    DIR * dir;

    vv_printf("dirname %s\n", dirname);

    dir = opendir(dirname);

    if (dir == NULL) {
        if (!rm) v_printf("FAIL: dir is NULL %d %s\n", errno, strerror(errno));
        return -1;
    }

    diriter = readdir(dir);
    
    if (diriter == NULL) {
        v_printf("FAIL: diriter is NULL %d %s\n", errno, strerror(errno));
    }

    while (diriter != NULL) {
        struct stat stbuf;
        vv_printf("d_name %s\n", diriter->d_name);
        if (!strcmp(diriter->d_name, ".") || !strcmp(diriter->d_name, "..")) {
            vv_printf("ignoring . and ..\n");
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
            vv_printf("directory: %s\n", fn);
            check_filesizes(fn, false, results);
        }
        else {
            if (rm) {
                remove(fn);
            }
            else if (stbuf.st_size != total_write_size) {
                ++results[FilesizeErrors];
                v_printf("ERROR: file: %s -- st_size: %d (expected %d)\n", fn, stbuf.st_size, total_write_size);
            }
            else {
                ++results[CorrectSize];
                vv_printf("SUCCESS: file: %s -- st_size: %d (expected %d)\n", fn, stbuf.st_size, total_write_size);
            }
        }
        diriter = readdir(dir);
    }
    closedir(dir);
    return 0;
}
*/

int main(int argc, char *argv[]) {
    char dirname[] = "one-open-many-writes";
    char failedfiles[FHFMAX][FHFSIZE]; // Max files 256 (more than 16 segv's anyway); max filename size 64 (actually 19)
    int ret;
    int opt;
    int num_files = 1; // default for unit test
    int dirsread = 0;
    int filesread = 0;
    int errors = 0;
    int results[ResultSize];
    bool fail = false;

    while ((opt = getopt (argc, argv, "uvwhf:")) != -1) {
        switch (opt)
        {
            case 'v':
                verbose = true;
                break;
            case 'w':
                vverbose = true;
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
    
    // An empty string ("") is the sentinel
    for (int idx = 0; idx < FHFMAX; idx++) {
        failedfiles[idx][0] = '\0';
    }

    /*
    if (check_filesizes(dirname, true, results) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory contents\n");
            exit(1);
        }
    }
    */

    if (clear_directory(dirname) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory contents\n");
            exit(1);
        }
    }

    if (remove(dirname) < 0) {
        if (errno != ENOENT) {
            printf("FAIL: Couldn't delete directory \'%s\'\n", dirname);
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

    if (writeread(dirname, results, num_files, failedfiles) < 0) { // dirname is, oddly enough, the base name of the file
        printf("FAIL: writeread.\n");
        fail = true;
    }
    
    /*
    if (check_filesizes(".", false, results) < 0) {
        v_printf("FAIL: check_filesizes.\n");
        fail = true;
    }
    */
    
    /*
    if (check_continualwrites_dir(".", results, failedfiles) < 0) {
        v_printf("FAIL: check_continualwrites_dir.\n");
        fail = true;
    }
    */
    
    for (int idx = 0; failedfiles[idx][0] != '\0'; idx++) {
        vv_printf("%s\n", failedfiles[idx]);
    }

    /*
    // hard-coding the path is not pretty, but it is clear ...
    // We did a chdir to continualwrites, hence the need to ../..
    ret = chdir("../../cache/forensic-haven");
    if (ret < 0) {
        printf("FAIL: Couldn't change to directory %s. Exiting\n", dirname);
        exit(1);
    }

    if (check_forensic_haven(".", results, failedfiles) < 0) {
        printf("FAIL: check_forensic_haven.\n");
    }
    */

    /*
    if (results[FilesizeErrors] > 0 || results[StatErrors] > 0 || results[OpenErrors] > 0 || 
        results[FHOpenErrors] > 0 || results[FHReadErrors] > 0 || results[FHMissingErrors] > 0 || 
        results[CWOpenErrors] > 0) {

        fail = true;
    }
    if (fail) {
        printf("FAIL: writes %d correct size %d dir reads %d fh found %d "
               "write errors %d filesize errors %d stat errors %d open errors %d "
               "fh open errors %d fh read errors %d fh missing errors %d\n",
               results[Writes], results[CorrectSize], results[DirReads], results[FHFound],
               results[WriteErrors], results[FilesizeErrors], results[StatErrors], results[OpenErrors],
               results[FHOpenErrors], results[FHReadErrors], results[FHMissingErrors], results[CWOpenErrors]);
    }
    else {
        printf("PASS: writes %d correct size %d dir reads %d fh found %d\n",
               results[Writes], results[CorrectSize], results[DirReads], results[FHFound]);
    }
    */
}

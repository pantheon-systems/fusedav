/***
  This file is part of fusedav.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "log.h"
#include "log_sections.h"

// Return value is allocated and must be freed.
char *path_parent(const char *uri) {
    size_t len = strlen(uri);
    const char *pnt = uri + len - 1;

    // find previous slash
    while (pnt > uri && *pnt != '/') {
        pnt--;
    }

    // Move up past the trailing slash. But if we are already at the
    // beginning of uri (aka at the root directory's slash), don't move
    // past it.
    if (pnt > uri) {
        pnt--;
    }

    // If there are no slashes in the string and we get to the front of the
    // string and the first character is not a slash, then we don't have a
    // legitimate directory to return
    if (pnt == uri && *pnt != '/') {
        return NULL;
    }

    // Returns everything up to but not including the last slash in the string
    // But if the slash is the first character, return it.
    return strndup(uri, (pnt - uri) + 1);
}

#if INJECT_ERRORS

/* To invoke the inject error mechanism:
 * 1. make clean
 * 2. make INJECT_ERRORS=1
 */

// The list of inject_error locations
static bool *inject_error_list = NULL;

// specific error tests.
/* This test's main use is to ensure that we don't cause serious errors,
 * e.g. segv, when we process a gerr. It just randomly sets an error.
 * Of course, if the program running doesn't hit that point in the code
 * where the inject error is set while it is set, it will not execute.
 */
static void rand_test(void) {
    static int fdx = no_error;
    const int iters = 1024 * 1024;

    for (int iter = 0; iter < iters; iter++) {
        int tdx;
        // Sleep 11 seconds between injections
        sleep(11);

        // Figure out which error location to set
        tdx = rand() % inject_error_count;

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
}

/* test what happens on a write error */
static void enhanced_logging_test(void) {
    static int fdx = no_error;
    static int tdx = no_error;
    const int iters = 4096; // @TODO I just made this number up; figure out a better one!

    for (int iter = 0; iter < iters; iter++) {
        // Sleep 11 seconds between injections
        sleep(11);

        // flop between writewrite and no_error

        if (tdx == no_error) tdx = filecache_error_enhanced_logging;
        else tdx = no_error;

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
}

/* test what happens on a leveldb error */
static void leveldb_error_test(void) {
    static int fdx = no_error;
    static int tdx = no_error;
    const int iters = 4096; // @TODO I just made this number up; figure out a better one!

    for (int iter = 0; iter < iters; iter++) {
        // Sleep 61 seconds between injections
        sleep(61);

        // flop between leveldb error and no_error

        if (tdx == no_error) tdx = statcache_error_getldb; // statcache_error_childrenldb statcache_error_readchildrenldb statcache_error_setldb
        else tdx = no_error;

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
}

/* test what happens on a write error */
static void writewrite_test(void) {
    static int fdx = no_error;
    static int tdx = no_error;
    const int iters = 4096; // @TODO I just made this number up; figure out a better one!

    for (int iter = 0; iter < iters; iter++) {
        // Sleep 11 seconds between injections
        sleep(11);

        // flop between writewrite and no_error

        if (tdx == no_error) tdx = filecache_error_writewrite;
        else tdx = no_error;

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
}

/* Recreate the kinds of errors we might see on propfinds */
static void propfind_test(void) {
    int fdx = no_error;
    const int iters = 4096; // @TODO I just made this number up. Figure out a better one!
    struct error_name_s {
        int error;
        const char *name;
    };
    struct error_name_s error_name[] = {
        {fusedav_error_propfindsession, "fusedav_error_propfindsession"},
        {fusedav_error_propfindhead, "fusedav_error_propfindhead"},
        {props_error_spropfindsession, "props_error_spropfindsession"},
        {props_error_spropfindcurl, "props_error_spropfindcurl"},
        {props_error_spropfindstatefailure, "props_error_spropfindstatefailure"},
        {props_error_spropfindxmlparse, "props_error_spropfindxmlparse"},
        {props_error_spropfindunkcode, "props_error_spropfindunkcode"},
        {-1, ""}, // sentinel
    };

    for (int iter = 0; iter < iters; iter++) {
        for (int idx = 0; error_name[idx].error != -1; idx++) {
            const char *name;
            int tdx;

            tdx = error_name[idx].error;
            name = error_name[idx].name;

            log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d (%s)", inject_error_count, fdx, tdx, name);

            // Make the new location true but turn off the locations for the old location.
            inject_error_list[tdx] = true;
            inject_error_list[fdx] = false;
            fdx = tdx;
            sleep(17);
        }
    }
}

/* test what happens on a GET 400 error  */
static void curl_error_capture_test(void) {
    static int fdx = no_error;
    static int tdx = no_error;
    const int iters = 4096; // @TODO I just made this number up; figure out a better one!

    for (int iter = 0; iter < iters; iter++) {
        // Sleep 11 seconds between injections
        sleep(11);

        // flop between filecache_error_fresh404 and no_error

        if (tdx == no_error) tdx = filecache_error_fresh404;
        else tdx = no_error;

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
}

/* test conditions which might or might not land a file in the forensic haven
 * This is a pretty extensive test of the filecache errors, but not a complete one.
 */
static void filecache_forensic_haven_test(void) {
    int fdx = no_error;
    const int iters = 4096; // @TODO I just made this number up. Figure out a better one!
    struct error_name_s {
        int error;
        const char *name;
    };
    struct error_name_s error_name[] = {
        {filecache_error_newcachefile, "filecache_error_newcachefile"},
        {filecache_error_setpdata, "filecache_error_setpdata"},
        {filecache_error_setldb, "filecache_error_setldb"},
        {filecache_error_createcalloc, "filecache_error_createcalloc"},
        {filecache_error_getldb, "filecache_error_getldb"},
        {filecache_error_getvallen, "filecache_error_getvallen"},
        {filecache_error_freshopen1, "filecache_error_freshopen1"},
        /* {filecache_error_freshflock1, "filecache_error_freshflock1"}, this will leave lock locked */
        {filecache_error_freshftrunc, "filecache_error_freshftrunc"},
        {filecache_error_freshflock2, "filecache_error_freshflock2"},
        {filecache_error_freshsession, "filecache_error_freshsession"},
        {filecache_error_freshcurl1, "filecache_error_freshcurl1"},
        {filecache_error_fresh404, "filecache_error_fresh404"},
        {filecache_error_freshcurl2, "filecache_error_freshcurl2"},
        {filecache_error_freshopen2, "filecache_error_freshopen2"},
        {filecache_error_freshpdata, "filecache_error_freshpdata"},
        {filecache_error_opencalloc, "filecache_error_opencalloc"},
        {filecache_error_readsdata, "filecache_error_readsdata"},
        {filecache_error_readread, "filecache_error_readread"},
        {filecache_error_writesdata, "filecache_error_writesdata"},
        {filecache_error_writewriteable, "filecache_error_writewriteable"},
        /* {filecache_error_writeflock1, "filecache_error_writeflock1"}, this will leave lock locked */
        {filecache_error_writewrite, "filecache_error_writewrite"},
        {filecache_error_writeflock2, "filecache_error_writeflock2"},
        {filecache_error_closesdata, "filecache_error_closesdata"},
        {filecache_error_closefd, "filecache_error_closefd"},
        {filecache_error_closeclose, "filecache_error_closeclose"},
        {filecache_error_etagflock1, "filecache_error_etagflock1"},
        {filecache_error_etagfstat, "filecache_error_etagfstat"},
        {filecache_error_etagcurl1, "filecache_error_etagcurl1"},
        {filecache_error_etagcurl2, "filecache_error_etagcurl2"},
        {filecache_error_etagflock2, "filecache_error_etagflock2"},
        {filecache_error_syncsdata, "filecache_error_syncsdata"},
        {filecache_error_syncpdata, "filecache_error_syncpdata"},
        {filecache_error_synclseek, "filecache_error_synclseek"},
        {filecache_error_deleteldb, "filecache_error_deleteldb"},
        {-1, ""}, // sentinel
    };

    for (int iter = 0; iter < iters; iter++) {
        for (int idx = 0; error_name[idx].error != -1; idx++) {
            const char *name;
            int tdx;

            tdx = error_name[idx].error;
            name = error_name[idx].name;

            log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d (%s)", inject_error_count, fdx, tdx, name);

            // Make the new location true but turn off the locations for the old location.
            inject_error_list[tdx] = true;
            inject_error_list[fdx] = false;
            fdx = tdx;
            sleep(17);
        }
    }
}

// The routine which the pthread calls to get things started
void *inject_error_mechanism(__unused void *ptr) {

    /* We are going to make a list of all error injection locations for all three
     * files, fusedav.c, filecache.c, and statcache.c. Then we are going to tell
     * each of the files which section of the list is theirs. We do this by
     * getting the number of locations in the code where we have added
     * inject_error calls for each of the three files. We roll the dice, set one of
     * the inject_error locations to true, and tell all three files where it is.
     * Each file's location then decides if it is the one which has been turned
     * to true.
     */

    // See the random number generator
    srand(time(NULL));

    inject_error_list = calloc(sizeof(bool), inject_error_count);
    if (inject_error_list == NULL) {
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: failed to calloc inject_error_list");
        return NULL;
    }

    while (true) {

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting rand_test");
        rand_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting filecache_forensic_haven_test");
        filecache_forensic_haven_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting writewrite_test");
        writewrite_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting propfind_test");
        propfind_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting fusedav_triggers_vallhalla_logging");
        enhanced_logging_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting raise SIGINT on leveldb error");
        leveldb_error_test();

        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: Starting curl error capture test");
        curl_error_capture_test();
    }

    free(inject_error_list);
    return NULL;
}

bool inject_error(int edx) {
    // See if the error location has been set by the mechanism
    if (inject_error_list && inject_error_list[edx]) {
        inject_error_list[edx] = false;
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error(%d)", edx);
        errno = ENOTTY;
        return true;
    }
    return false;
}

#else

void *inject_error_mechanism(__unused void *ptr) {
    return NULL;
}

#endif

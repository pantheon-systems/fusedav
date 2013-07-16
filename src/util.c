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

#include "util.h"
#include "log.h"
#include "log_sections.h"

// Return value is allocated and must be freed.
char *path_parent(const char *uri) {
    size_t len = strlen(uri);
    const char *pnt = uri + len - 1;
    // skip trailing slash (parent of "/foo/" is "/")
    if (pnt >= uri && *pnt == '/')
        pnt--;
    // find previous slash
    while (pnt > uri && *pnt != '/')
        pnt--;
    if (pnt < uri || (pnt == uri && *pnt != '/'))
        return NULL;
    return strndup(uri, pnt - uri + 1);
}

char *strip_trailing_slash(char *fn, int *is_dir) {
    size_t l = strlen(fn);
    assert(fn);
    assert(is_dir);
    assert(l > 0);

    if ((*is_dir = (fn[l-1] == '/')))
        fn[l-1] = 0;

    return fn;
}

#if INJECT_ERRORS

/* To invoke the inject error mechanism:
 * 1. make clean
 * 2. make INJECT_ERRORS=1
 */

/* In this implementation, we randomly set one inject_error location to true for
 * a set amount of time. We can in the future design it in a more tailored fashion
 * to simulate something resembling the kinds of storms of errors we see.
 */

// error injection routines
// The list of inject_error locations
static bool *inject_error_list;

// fusedav will take the 0'th element and the next however many it needs
// filecache will take the section of the list where fusedav leaves off;
// statcache where fusedav leaves off
static int fusedav_start;
static int filecache_start;
static int statcache_start;

// number of inject_error locations in fusedav, bzw filecache, statcache
static int fderrors;
static int fcerrors;
static int scerrors;

// The routine which the pthread calls to get things started
void *inject_error_mechanism(void *ptr) {
    int fdx = 0;

    // ptr stuff just to get rid of warning message about unused parameter
    log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "INJECTING ERRORS! %p", ptr ? ptr : 0);

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

    // fusedav starts the list at 0
    fderrors = fusedav_errors();
    fusedav_start = 0;
    fcerrors = filecache_errors();
    // filecache starts the list where fusedav leaves off
    filecache_start = fderrors;
    scerrors = statcache_errors();
    // statcache starts where filecache leaves off
    statcache_start = filecache_start + fcerrors;
    // create the list large enough for inject_error locations from all three files
    inject_error_list = calloc(sizeof(bool), fderrors + fcerrors + scerrors);
    if (inject_error_list == NULL) {
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: failed to calloc inject_error_list");
        return NULL;
    }

    // Generate errors forever!
    while (true) {
        int tdx;
        // Sleep 4 seconds between injections
        sleep(4);

        // Figure out which error location to set
        tdx = rand() % (fderrors + fcerrors + scerrors);
        log_print(LOG_DEBUG, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", fcerrors, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
    free(inject_error_list);
    return NULL;
}

// fusedav.c bzw filecache.c, statcache.c, will call these routines to decide whether to throw an injected error
// The basic routine; it will figure out if the given location is in this file's section of the list

// edx is relative to the file itself, that is, each file numbers its inject_error locations starting at 0.
static bool inject_error(int edx, int start, int numerrors) {
    // Move to the section of the list where this file's inject_error locations start
    edx += start;
    // See if the error location has been set by the mechanism
    if (inject_error_list[edx]) {
        inject_error_list[edx] = false;
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error(%d, %d, %d)", edx - start, start, numerrors);
        return true;
    }
    return false;
}

bool fd_inject_error(int edx) {
    return inject_error(edx, fusedav_start, fderrors);
}

bool fc_inject_error(int edx) {
    return inject_error(edx, filecache_start, fcerrors);
}

bool sc_inject_error(int edx) {
    return inject_error(edx, statcache_start, scerrors);
}

#else

void *inject_error_mechanism(__unused void *ptr) {
    return NULL;
}

#endif

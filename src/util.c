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

/* In this implementation, we randomly set one inject_error location to true for
 * a set amount of time. We can in the future design it in a more tailored fashion
 * to simulate something resembling the kinds of storms of errors we see.
 */

// error injection routines
// The list of inject_error locations
static bool *inject_error_list = NULL;

// The routine which the pthread calls to get things started
void *inject_error_mechanism(void *ptr) {
    int fdx = no_error;
    int tdx = no_error;

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

    inject_error_list = calloc(sizeof(bool), inject_error_count);
    if (inject_error_list == NULL) {
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error_mechanism: failed to calloc inject_error_list");
        return NULL;
    }

    // Generate errors forever!
    while (true) {
        // Sleep 11 seconds between injections
        sleep(11);

        // Figure out which error location to set
        // JB tdx = rand() % inject_error_count;
        // flop between writewrite and no_error
        if (tdx == no_error) tdx = filecache_error_writewrite;
        else tdx = no_error;
        
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "fce: %d Uninjecting %d; injecting %d", inject_error_count, fdx, tdx);

        // Make the new location true but turn off the locations for the old location.
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
    free(inject_error_list);
    return NULL;
}

bool inject_error(int edx) {
    // See if the error location has been set by the mechanism
    if (inject_error_list && inject_error_list[edx]) {
        inject_error_list[edx] = false;
        log_print(LOG_NOTICE, SECTION_UTIL_DEFAULT, "inject_error(%d)", edx);
        return true;
    }
    return false;
}

#else

void *inject_error_mechanism(__unused void *ptr) {
    return NULL;
}

#endif

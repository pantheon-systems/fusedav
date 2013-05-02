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

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "util.h"
#include "log.h"

#define PS (0x0001) /* "+" */
#define PC (0x0002) /* "%" */
#define DS (0x0004) /* "-" */
#define DT (0x0008) /* "." */
#define US (0x0010) /* "_" */
#define TD (0x0020) /* "~" */
#define FS (0x0040) /* "/" */
#define CL (0x0080) /* ":" */
#define AT (0x0100) /* "@" */
#define QU (0x0200) /* "?" */

#define DG (0x0400) /* DIGIT */
#define AL (0x0800) /* ALPHA */

#define GD (0x1000) /* gen-delims    = "#" / "[" / "]"
                     * ... except ":", "/", "@", and "?" */

#define SD (0x2000) /* sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
                     *               / "*" / "+" / "," / ";" / "="
                     * ... except "+" which is PS */

#define OT (0x4000) /* others */

#define URI_ALPHA (AL)
#define URI_DIGIT (DG)

/* unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~" */
#define URI_UNRESERVED (AL | DG | DS | DT | US | TD)
/* scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) */
#define URI_SCHEME (AL | DG | PS | DS | DT)
/* real sub-delims definition, including "+" */
#define URI_SUBDELIM (PS | SD)
/* real gen-delims definition, including ":", "/", "@" and "?" */
#define URI_GENDELIM (GD | CL | FS | AT | QU)
/* userinfo = *( unreserved / pct-encoded / sub-delims / ":" ) */
#define URI_USERINFO (URI_UNRESERVED | PC | URI_SUBDELIM | CL)
/* pchar = unreserved / pct-encoded / sub-delims / ":" / "@" */
#define URI_PCHAR (URI_UNRESERVED | PC | URI_SUBDELIM | CL | AT)
/* invented: segchar = pchar / "/" */
#define URI_SEGCHAR (URI_PCHAR | FS)
/* query = *( pchar / "/" / "?" ) */
#define URI_QUERY (URI_PCHAR | FS | QU)
/* fragment == query */
#define URI_FRAGMENT URI_QUERY

/* any characters which should be path-escaped: */
#define URI_ESCAPE ((URI_GENDELIM & ~(FS)) | URI_SUBDELIM | OT | PC)

static const unsigned int uri_chars[256] = {
/* 0xXX    x0      x2      x4      x6      x8      xA      xC      xE     */
/*   0x */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   1x */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   2x */ OT, SD, OT, GD, SD, PC, SD, SD, SD, SD, SD, PS, SD, DS, DT, FS,
/*   3x */ DG, DG, DG, DG, DG, DG, DG, DG, DG, DG, CL, SD, OT, SD, OT, QU,
/*   4x */ AT, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL,
/*   5x */ AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, GD, OT, GD, OT, US,
/*   6x */ OT, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL,
/*   7x */ AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, AL, OT, OT, OT, TD, OT,
/*   8x */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   9x */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Ax */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Bx */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Cx */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Dx */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Ex */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT,
/*   Fx */ OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT, OT
};

#define uri_lookup(ch) (uri_chars[(unsigned char)ch])

/* CH must be an unsigned char; evaluates to 1 if CH should be
 * percent-encoded. */
#define path_escape_ch(ch) (uri_lookup(ch) & URI_ESCAPE)

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

char *path_escape(const char *path) {
    const unsigned char *pnt;
    char *ret, *p;
    size_t count = 0;

    for (pnt = (const unsigned char *)path; *pnt != '\0'; pnt++) {
        count += path_escape_ch(*pnt);
    }

    if (count == 0) {
        return strdup(path);
    }

    p = ret = malloc(strlen(path) + 2 * count + 1);
    for (pnt = (const unsigned char *)path; *pnt != '\0'; pnt++) {
        if (path_escape_ch(*pnt)) {
            /* Escape it - %<hex><hex> */
            sprintf(p, "%%%02x", (unsigned char) *pnt);
            p += 3;
        } else {
            *p++ = *pnt;
        }
    }
    *p = '\0';
    return ret;
}

#if INJECTING_ERRORS
// error injection routines
// Set to true to inject errors; Make sure it is false for production
// If you change to true, also include an all-caps comment so it will be obvious if
// you diff before push that you have done this, and you can't correct before push
bool injecting_errors = true;
static bool *inject_error_list;
static int fusedav_start;
static int filecache_start;
static int statcache_start;
static int fcerrors; // number of error locations in filecache
static int scerrors; // number of error locations in statcache
static int fderrors; // number of error locations in statcache

void *inject_error_mechanism(void *ptr) {
    int fdx = 0;
    if(!injecting_errors) return NULL;

    // ptr stuff just to get rid of warning message about unused parameter
    log_print(LOG_NOTICE, "INJECTING ERRORS! %p", ptr ? ptr : 0);

    srand(time(NULL));
    fderrors = fusedav_errors();
    fusedav_start = 0;
    fcerrors = filecache_errors();
    filecache_start = fderrors;
    scerrors = statcache_errors();
    statcache_start = filecache_start + fcerrors;
    inject_error_list = calloc(sizeof(bool), fderrors + fcerrors + scerrors);
    if (inject_error_list == NULL) {
        log_print(LOG_NOTICE, "inject_error_mechanism: failed to calloc inject_error_list");
        return NULL;
    }

    // Limits the extent of the storm. Some protection against accidental setting.
    for (int idx = 0; idx < 512; idx++) {
        int tdx;
        sleep(4);
        tdx = rand() % (fderrors + fcerrors + scerrors);
        log_print(LOG_DEBUG, "fce: %d Uninjecting %d; injecting %d", fcerrors, fdx, tdx);
        inject_error_list[tdx] = true;
        inject_error_list[fdx] = false;
        fdx = tdx;
    }
    free(inject_error_list);
    return NULL;
}

// fusedav.c bzw filecache.c, statcache.c, will call these routines to decide whether to throw an injected error
static bool inject_error(int edx, int start, int numerrors) {
    edx += start;
    if ((edx < numerrors + start) && inject_error_list[edx]) {
        inject_error_list[edx] = false;
        log_print(LOG_NOTICE, "inject_error(%d, %d, %d)", edx - start, start, numerrors);
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
bool injecting_errors = false;
#endif


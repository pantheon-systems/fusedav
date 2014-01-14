#ifndef fooutilhfoo
#define fooutilhfoo

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

#ifdef __GNUC__
#define __unused __attribute__ ((unused))
#else
#define __unused
#endif

#include <glib.h>
#include <stdbool.h>

char *path_parent(const char *uri);

// For GError
#ifndef G_DEFINE_QUARK

#define             G_DEFINE_QUARK(QN, q_n)\
GQuark \
q_n##_quark (void) \
{ \
  static GQuark g_define_quark = 0; \
  if (G_UNLIKELY (g_define_quark == 0)) \
    g_define_quark = g_quark_from_string (#QN); \
  return g_define_quark; \
}

#endif
void *inject_error_mechanism(void *ptr);

#if INJECT_ERRORS

#define fusedav_error_fillstsize 0
#define fusedav_error_updatepropfind1 1
#define fusedav_error_updatepropfind2 2
#define fusedav_error_statignorefreshness 3
#define fusedav_error_statstmode 4
#define fusedav_error_cunlinkisdir 5
#define fusedav_error_cunlinksession 6
#define fusedav_error_cunlinkcurl 7
#define fusedav_error_propfindsession 8
#define fusedav_error_propfindhead 9

#define filecache_error_init1 10
#define filecache_error_init2 11
#define filecache_error_init3 12
#define filecache_error_newcachefile 13
#define filecache_error_setpdata 14
#define filecache_error_setldb 15
#define filecache_error_createcalloc 16
#define filecache_error_getldb 17
#define filecache_error_getvallen 18
#define filecache_error_freshopen1 19
#define filecache_error_freshflock1 20
#define filecache_error_freshftrunc 21
#define filecache_error_freshflock2 22
#define filecache_error_freshsession 23
#define filecache_error_freshcurl1 24
#define filecache_error_freshcurl2 25
#define filecache_error_freshopen2 26
#define filecache_error_freshpdata 27
#define filecache_error_fresh404 28
#define filecache_error_opencalloc 29
#define filecache_error_readsdata 30
#define filecache_error_readread 31
#define filecache_error_writesdata 32
#define filecache_error_writewriteable 33
#define filecache_error_writeflock1 34
#define filecache_error_writewrite 35
#define filecache_error_writeflock2 36
#define filecache_error_closesdata 37
#define filecache_error_closefd 38
#define filecache_error_closeclose 39
#define filecache_error_etagflock1 40
#define filecache_error_etagfstat 41
#define filecache_error_etagcurl1 42
#define filecache_error_etagcurl2 43
#define filecache_error_etagflock2 44
#define filecache_error_syncsdata 45
#define filecache_error_REUSE 46
#define filecache_error_syncpdata 47
#define filecache_error_synclseek 48
#define filecache_error_truncsdata 49
#define filecache_error_truncflock1 50
#define filecache_error_truncftrunc 51
#define filecache_error_truncflock2 52
#define filecache_error_deleteldb 53
#define filecache_error_movepdata 54
#define filecache_error_orphanopendir 55
#define filecache_error_enhanced_logging 56

#define statcache_error_cachepath 60
#define statcache_error_openldb 61
#define statcache_error_getldb 62
#define statcache_error_childrenldb 63
#define statcache_error_readchildrenldb 64
#define statcache_error_setldb 65
#define statcache_error_deleteldb 66

#define config_error_parse 70
#define config_error_sessioninit 71
#define config_error_cmdline 72
#define config_error_uri 73
#define config_error_load 74

#define props_error_spropfindsession 80
#define props_error_spropfindcurl 81
#define props_error_spropfindstatefailure 82
#define props_error_spropfindxmlparse 83
#define props_error_spropfindunkcode 84

#define signal_error_action1 90
#define signal_error_action2 91
#define signal_error_action3 92

// Make sure it is higher than the highest value above
#define inject_error_count 100
// last slot is no error
#define no_error inject_error_count - 1

#define injecting_errors true
bool inject_error(int edx);

#else

#define injecting_errors false
#define inject_error(edx) false

#endif

#endif

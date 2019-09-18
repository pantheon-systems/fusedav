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

bool write_flag(int flags);
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
#define fusedav_error_statignorefreshnesssaint 4
#define fusedav_error_statstmode 5
#define fusedav_error_cunlinkisdir 6
#define fusedav_error_cunlinksession 7
#define fusedav_error_cunlinkcurl 8
#define fusedav_error_propfindsession 9
#define fusedav_error_propfindhead 10

#define filecache_error_init1 20
#define filecache_error_init2 21
#define filecache_error_init3 22
#define filecache_error_newcachefile 23
#define filecache_error_setpdata 24
#define filecache_error_setldb 25
#define filecache_error_createcalloc 26
#define filecache_error_getldb 27
#define filecache_error_getvallen 28
#define filecache_error_freshopen1 29
#define filecache_error_freshflock1 30
#define filecache_error_freshftrunc 31
#define filecache_error_freshflock2 32
#define filecache_error_freshsession 33
#define filecache_error_freshcurl1 34
#define filecache_error_freshcurl2 35
#define filecache_error_freshopen2 36
#define filecache_error_freshpdata 37
#define filecache_error_fresh400 38
#define filecache_error_opencalloc 39
#define filecache_error_readsdata 40
#define filecache_error_readread 41
#define filecache_error_writesdata 42
#define filecache_error_writewriteable 43
#define filecache_error_writeflock1 44
#define filecache_error_writewrite 45
#define filecache_error_writeflock2 46
#define filecache_error_closesdata 47
#define filecache_error_closefd 48
#define filecache_error_closeclose 49
#define filecache_error_etagflock1 50
#define filecache_error_etagfstat 51
#define filecache_error_etagcurl1 52
#define filecache_error_etagcurl2 53
#define filecache_error_etagflock2 54
#define filecache_error_syncsdata 55
#define filecache_error_REUSE 56
#define filecache_error_syncpdata 57
#define filecache_error_synclseek 58
#define filecache_error_truncsdata 59
#define filecache_error_truncflock1 60
#define filecache_error_truncftrunc 61
#define filecache_error_truncflock2 62
#define filecache_error_deleteldb 63
#define filecache_error_movepdata 64
#define filecache_error_orphanopendir 65
#define filecache_error_enhanced_logging 66

#define statcache_error_cachepath 70
#define statcache_error_openldb 71
#define statcache_error_getldb 72
#define statcache_error_childrenldb 73
#define statcache_error_readchildrenldb 74
#define statcache_error_setldb 75
#define statcache_error_deleteldb 76
#define statcache_error_data_version_get 77
#define statcache_error_data_version_set 78

#define config_error_parse 80
#define config_error_sessioninit 81
#define config_error_cmdline 82
#define config_error_uri 83
#define config_error_load 84

#define props_error_spropfindsession 90
#define props_error_spropfindcurl 91
#define props_error_spropfindstatefailure 92
#define props_error_spropfindxmlparse 93
#define props_error_spropfindunkcode 94

#define signal_error_action1 100
#define signal_error_action2 101
#define signal_error_action3 102

// Make sure it is higher than the highest value above
#define inject_error_count 110
// last slot is no error
#define no_error inject_error_count - 1

#define injecting_errors true
bool inject_error(int edx);

#else

#define injecting_errors false
#define inject_error(edx) false

#endif

#endif

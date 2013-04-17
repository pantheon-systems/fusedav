# This file is part of fusedav.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

bin_PROGRAMS=fusedav

fusedav_SOURCES=fusedav.c fusedav.h \
				statcache.c statcache.h \
				ldb-filecache.c ldb-filecache.h \
				session.c session.h \
				log.c log.h \
				bloom-filter.c bloom-filter.h

fusedav_CFLAGS = $(AM_CFLAGS) $(NEON_CFLAGS) $(FUSE_CFLAGS) $(YAML_CFLAGS) $(LEVELDB_CFLAGS) $(SYSTEMD_CFLAGS) $(ZLIB_CFLAGS) -DFUSE_USE_VERSION=26
fusedav_LDADD = -lpthread -ljemalloc $(NEON_LIBS) $(FUSE_LIBS) $(YAML_LIBS) $(LEVELDB_LIBS) $(SYSTEMD_LIBS) $(ZLIB_LIBS)

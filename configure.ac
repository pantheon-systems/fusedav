# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

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

AC_PREREQ([2.68])

define([gitcommit], esyscmd([sh -c "git rev-parse --short HEAD|tr -d '\n'"]))dnl

AC_DEFINE(GIT_COMMIT, "gitcommit", [Git Commit])
AC_INIT([fusedav],m4_esyscmd([tr -d '\n' < VERSION])-[gitcommit],[david@davidstrauss.net])
AC_CONFIG_SRCDIR([src/fusedav.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall])
AC_REVISION($Id$)

AC_SUBST(PACKAGE_URL, [https://github.com/pantheon-systems/fusedav])

if type -p stow > /dev/null && test -d /usr/local/stow ; then
   AC_MSG_NOTICE([*** Found /usr/local/stow: default install prefix set to /usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION} ***])
   ac_default_prefix="/usr/local/stow/${PACKAGE_NAME}-${PACKAGE_VERSION}"
fi

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

test_gcc_flag() {
    AC_LANG_CONFTEST([AC_LANG_SOURCE([int main() {}])])
    $CC -c conftest.c $CFLAGS $@ > /dev/null 2> /dev/null
    ret=$?
    rm -f conftest.o
    return $ret
}

# If using GCC specify some additional parameters
if test "x$GCC" = "xyes" ; then

    DESIRED_FLAGS="-Wall -W -Wextra -pedantic -pipe -Wformat -Wold-style-definition -Wdeclaration-after-statement -Wfloat-equal -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls -Wmissing-noreturn -Wshadow -Wendif-labels -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align -Wwrite-strings -Winline"

    if test "x$HAVE_NETLINK" = "xyes" ; then
        # Test whether rtnetlink.h can be included when compiled with -std=c99
        # some distributions (e.g. archlinux) have broken headers that dont
        # define __u64 with -std=c99
        AC_MSG_CHECKING([checking whether rtnetlink.h can be included with -std=c99])
        OLDCFLAGS="$CFLAGS"
        CFLAGS="-std=c99"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <linux/rtnetlink.h>]], [[]])],[use_stdc99=yes],[use_stdc99=no])

        if test x"$use_stdc99" = xyes; then
            DESIRED_FLAGS="-std=c99 $DESIRED_FLAGS"
            AC_MSG_RESULT([yes])
        else
            AC_MSG_RESULT([no])
        fi

        CFLAGS="$OLDCFLAGS"
    else
        DESIRED_FLAGS="-std=c99 $DESIRED_FLAGS"
    fi

    for flag in $DESIRED_FLAGS ; do
        AC_MSG_CHECKING([whether $CC accepts $flag])
        if test_gcc_flag $flag ; then
           CFLAGS="$CFLAGS $flag"
           AC_MSG_RESULT([yes])
        else
           AC_MSG_RESULT([no])
        fi
    done
fi

# 64 Bit LFS support
AC_SYS_LARGEFILE

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h malloc.h stdlib.h string.h sys/statfs.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_STRUCT_ST_BLOCKS

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([ftruncate memset strdup strerror strrchr memchr strchr strcspn])

AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([jemalloc], [malloc], [:], [AC_MSG_ERROR(jemalloc not found or functional. Install the jemalloc allocator.)], [])

AC_CHECK_HEADER(expat.h, [], [AC_MSG_ERROR(expat.h not found. Install Expat.)], [])

PKG_CHECK_MODULES(SYSTEMD, [ libsystemd ] )
PKG_CHECK_MODULES(LEVELDB, [ leveldb ])
PKG_CHECK_MODULES(CURL, [ libcurl >= 7.24.0 ])
PKG_CHECK_MODULES(FUSE, [ fuse >= 2.8 ])
PKG_CHECK_MODULES(ZLIB, [ zlib >= 1.2.5 ])
PKG_CHECK_MODULES(GLIB, [ glib-2.0 >= 1.2.10 ])
PKG_CHECK_MODULES(URIPARSER, [ liburiparser >= 0.7.5 ])

AC_CONFIG_FILES([src/Makefile Makefile])
AC_OUTPUT

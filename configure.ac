# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# $Id$

# This file is part of fusedav.
#
# fusedav is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# fusedav is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with fusedav; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.

AC_PREREQ([2.68])
AC_INIT([fusedav],[0.2],[mzshfrqni (at) 0pointer (dot) de])
AC_CONFIG_SRCDIR([src/fusedav.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign 1.9 -Wall])
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
AC_CHECK_LIB([yaml], [yaml_parser_initialize])

PKG_CHECK_MODULES(NEON, [ neon >= 0.27 ])
PKG_CHECK_MODULES(FUSE, [ fuse >= 2.5 ])

# LYNX documentation generation
AC_ARG_ENABLE(lynx,
        AS_HELP_STRING(--disable-lynx,Turn off lynx usage for documentation generation),
[case "${enableval}" in
  yes) lynx=yes ;;
  no)  lynx=no ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --disable-lynx) ;;
esac],[lynx=yes])

if test x$lynx = xyes ; then
   AC_CHECK_PROG(have_lynx, lynx, yes, no)

   if test x$have_lynx = xno ; then
     AC_MSG_ERROR([*** Sorry, you have to install lynx or use --disable-lynx ***])
   fi
fi

AM_CONDITIONAL([USE_LYNX], [test "x$lynx" = xyes])

AC_CONFIG_FILES([src/Makefile Makefile doc/Makefile doc/README.html])
AC_OUTPUT

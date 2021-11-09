dnl Copyright (c) 2006-2009 HADA, Inc. <http://www.hada.com>
dnl This file is part of HADAFS.
dnl
dnl HADAFS is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl HADAFS is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([hadafs],[0.0.4],[hada-users@hada.org])

AM_INIT_AUTOMAKE

AM_CONFIG_HEADER([config.h])

AC_CONFIG_FILES([Makefile
		libhadafs/Makefile 
		libhadafs/src/Makefile
		libhadafsclient/Makefile
		libhadafsclient/src/Makefile
		hadafsd/Makefile
		hadafsd/src/Makefile
		booster/Makefile
		booster/src/Makefile
		xlators/Makefile
		xlators/protocol/Makefile
		xlators/protocol/client/Makefile
		xlators/protocol/client/src/Makefile
		xlators/protocol/server/Makefile
		xlators/protocol/server/src/Makefile
		xlators/performance/Makefile
		xlators/performance/mem-cache/Makefile
		xlators/performance/mem-cache/src/Makefile
		xlators/performance/io-threads/Makefile
		xlators/performance/io-threads/src/Makefile
		xlators/performance/qos_monitor/Makefile
		xlators/performance/qos_monitor/src/Makefile
		xlators/storage/Makefile
		xlators/storage/posix/Makefile
		xlators/storage/posix/src/Makefile
		xlators/cluster/Makefile
		xlators/cluster/unify/Makefile
        xlators/cluster/unify/src/Makefile
		transport/Makefile
		transport/socket/Makefile
		transport/socket/src/Makefile
		transport/ib-verbs/Makefile
		transport/ib-verbs/src/Makefile
		auth/Makefile
		auth/addr/Makefile
		auth/addr/src/Makefile
		auth/login/Makefile
		auth/login/src/Makefile
		doc/Makefile
		doc/examples/Makefile
		doc/hacker-guide/Makefile
		extras/Makefile
		extras/ctltools/Makefile
		extras/ctltools/init.d/Makefile
        extras/ctltools/init.d/hadafs-server.plist
        extras/ctltools/init.d/hadafsd-Debian
        extras/ctltools/init.d/hadafsd-Redhat
        extras/ctltools/init.d/hadafsd-SuSE
        hadafs.spec])

AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_LIBTOOL

AC_ARG_WITH(mountutildir,
            [  --with-mountutildir=DIR mount helper utility in DIR @<:@/sbin@:>@],
            [mountutildir=$withval],
            [mountutildir='/sbin'])
AC_SUBST(mountutildir)

AC_ARG_WITH(initdir,
            [  --with-initdir=DIR init.d scripts in DIR @<:@/etc/init.d@:>@],
            [initdir=$withval],
            [initdir='/etc/init.d'])
AC_SUBST(initdir)

# LEX needs a check
AC_PROG_LEX
if test  "x${LEX}" != "xflex" -a "x${FLEX}" != "xlex"; then
   AC_MSG_ERROR([Flex or lex required to build hadafs.])
fi

# YACC needs a check
AC_PROG_YACC
if test "x${YACC}" = "xbyacc" -o "x${YACC}" = "xyacc" -o "x${YACC}" = "x"; then
   AC_MSG_ERROR([GNU Bison required to build hadafs.])
fi

AC_CHECK_TOOL([LD],[ld])

AC_CHECK_LIB([pthread], [pthread_mutex_init], , AC_MSG_ERROR([Posix threads library is required to build hadafs]))
		 
AC_CHECK_FUNC([dlopen], [has_dlopen=yes], AC_CHECK_LIB([dl], [dlopen], , AC_MSG_ERROR([Dynamic linking library required to build hadafs])))


AC_CHECK_HEADERS([sys/xattr.h])

AC_CHECK_HEADERS([sys/extattr.h])

#HEXB add 201704
AC_CHECK_HEADERS([hiredis/hiredis.h])

dnl Mac OS X does not have spinlocks
#AC_CHECK_FUNC([pthread_spin_init], [have_spinlock=yes])
#if test "x${have_spinlock}" = "xyes"; then
#   AC_DEFINE(HAVE_SPINLOCK, 0, [define if found spinlock])
#fi
AC_SUBST(HAVE_SPINLOCK)

dnl some os may not have GNU defined strnlen function
AC_CHECK_FUNC([strnlen], [have_strnlen=yes])
if test "x${have_strnlen}" = "xyes"; then
   AC_DEFINE(HAVE_STRNLEN, 1, [define if found strnlen])
fi
AC_SUBST(HAVE_STRNLEN)


AC_CHECK_FUNC([setfsuid], [have_setfsuid=yes])
AC_CHECK_FUNC([setfsgid], [have_setfsgid=yes])

if test "x${have_setfsuid}" = "xyes" -a "x${have_setfsgid}" = "xyes"; then
  AC_DEFINE(HAVE_SET_FSID, 1, [define if found setfsuid setfsgid])
fi


# LIBHADAFSCLIENT section
AC_ARG_ENABLE([libhadafsclient],
	      AC_HELP_STRING([--disable-libhadafsclient],
			     [Do not build libhadafsclient]))

BUILD_LIBHADAFSCLIENT="yes"

if test "x$enable_libhadafsclient" != "xno"; then
   LIBHADAFSCLIENT_SUBDIR="libhadafsclient"
   BUILD_LIBHADAFSCLIENT="yes"
fi

AC_SUBST(LIBHADAFSCLIENT_SUBDIR)
# end LIBHADAFSCLIENT section

# EPOLL section
AC_ARG_ENABLE([epoll],
	      AC_HELP_STRING([--disable-epoll],
			     [Use poll instead of epoll.]))

BUILD_EPOLL=no
if test "x$enable_epoll" != "xno"; then
   AC_CHECK_HEADERS([sys/epoll.h],
                    [BUILD_EPOLL=yes],
		    [BUILD_EPOLL=no])
fi
# end EPOLL section


# IBVERBS section
AC_ARG_ENABLE([ibverbs],
	      AC_HELP_STRING([--disable-ibverbs],
			     [Do not build the ibverbs transport]))

if test "x$enable_ibverbs" != "xno"; then
  AC_CHECK_LIB([ibverbs],
               [ibv_get_device_list],
	       [HAVE_LIBIBVERBS="yes"],
	       [HAVE_LIBIBVERBS="no"])
fi

if test "x$enable_ibverbs" = "xyes" -a "x$HAVE_LIBIBVERBS" = "xno"; then
   echo "ibverbs requested but not found."
   exit 1
fi


BUILD_IBVERBS=no
if test "x$enable_ibverbs" != "xno" -a "x$HAVE_LIBIBVERBS" = "xyes"; then
  IBVERBS_SUBDIR=ib-verbs
  BUILD_IBVERBS=yes
fi

AC_SUBST(IBVERBS_SUBDIR)
# end IBVERBS section

# SWNETVERBS section
AC_ARG_ENABLE([swnetverbs],
	      AC_HELP_STRING([--disable-swnetverbs],
			     [Do not build the swnet-verbs transport]))

if test "x$enable_swnetverbs" != "xno"; then
  AC_CHECK_LIB([swverbs],
               [swnet_get_device_list],
	       [HAVE_LIBSWVERBS="yes"],
	       [HAVE_LIBSWVERBS="no"])
fi

if test "x$enable_swnetverbs" = "xyes" -a "x$HAVE_LIBSWVERBS" = "xno"; then
   echo "swnet-verbs requested but not found."
   exit 1
fi


BUILD_SWVERBS=no
if test "x$enable_swnetverbs" != "xno" -a "x$HAVE_LIBSWVERBS" = "xyes"; then
  SWVERBS_SUBDIR=swnet-verbs
  BUILD_SWVERBS=no
fi

AC_SUBST(SWVERBS_SUBDIR)
# end SWNETVERBS section

dnl FreeBSD > 5 has execinfo as a Ported library for giving a workaround
dnl solution to GCC backtrace functionality

AC_CHECK_HEADERS([execinfo.h], [have_backtrace=yes],
               AC_CHECK_LIB([execinfo], [backtrace], [have_backtrace=yes]))
dnl               AC_MSG_ERROR([libexecinfo not found libexecinfo required.])))

if test "x${have_backtrace}" = "xyes"; then
   AC_DEFINE(HAVE_BACKTRACE, 1, [define if found backtrace])
fi
AC_SUBST(HAVE_BACKTRACE)

dnl hadafs prints memory usage to stderr by sending it SIGUSR1
AC_CHECK_FUNC([malloc_stats], [have_malloc_stats=yes])
if test "x${have_malloc_stats}" = "xyes"; then
   AC_DEFINE(HAVE_MALLOC_STATS, 1, [define if found malloc_stats])
fi
AC_SUBST(HAVE_MALLOC_STATS)

dnl Linux, Solaris, Cygwin
AC_CHECK_MEMBERS([struct stat.st_atim.tv_nsec])
dnl FreeBSD, NetBSD
AC_CHECK_MEMBERS([struct stat.st_atimespec.tv_nsec])

dnl Check for argp
AC_CHECK_HEADER([argp.h], AC_DEFINE(HAVE_ARGP, 1, [have argp]))
AC_CONFIG_SUBDIRS(argp-standalone)
BUILD_ARGP_STANDALONE=no
if test "x${ac_cv_header_argp_h}" = "xno"; then 
   BUILD_ARGP_STANDALONE=yes
   ARGP_STANDALONE_CPPFLAGS='-I${top_srcdir}/argp-standalone'
   ARGP_STANDALONE_LDADD='${top_builddir}/argp-standalone/libargp.a'
fi

AC_SUBST(ARGP_STANDALONE_CPPFLAGS)
AC_SUBST(ARGP_STANDALONE_LDADD)

AC_CHECK_HEADER([malloc.h], AC_DEFINE(HAVE_MALLOC_H, 1, [have malloc.h]))

AC_CHECK_FUNC([llistxattr], [have_llistxattr=yes])
if test "x${have_llistxattr}" = "xyes"; then
   AC_DEFINE(HAVE_LLISTXATTR, 1, [define if llistxattr exists])
fi

AC_CHECK_FUNC([fdatasync], [have_fdatasync=yes])
if test "x${have_fdatasync}" = "xyes"; then
   AC_DEFINE(HAVE_FDATASYNC, 1, [define if fdatasync exists])
fi

# Check the distribution where you are compiling hadafs on 

GF_DISTRIBUTION=
AC_CHECK_FILE([/etc/debian_version])
AC_CHECK_FILE([/etc/SuSE-release])
AC_CHECK_FILE([/etc/redhat-release])


if test "x$ac_cv_file__etc_debian_version" = "xyes"; then
   GF_DISTRIBUTION=Debian
fi
if test "x$ac_cv_file__etc_SuSE_release" = "xyes"; then
   GF_DISTRIBUTION=SuSE
fi
if test "x$ac_cv_file__etc_redhat_release" = "xyes"; then
   GF_DISTRIBUTION=Redhat
fi

AC_SUBST(GF_DISTRIBUTION)

GF_HOST_OS=""
GF_LDFLAGS="-rdynamic"

if test "x$BUILD_LIBHADAFSCLIENT" = "xyes"; then
   GF_BOOSTER_SUBDIR="booster"
fi

GF_FUSE_LDADD="-lfuse"
case $host_os in
     linux*)
     dnl	GF_LINUX_HOST_OS=1
        GF_HOST_OS="GF_LINUX_HOST_OS"
	GF_CFLAGS="${ARGP_STANDALONE_CPPFLAGS}"
	GF_HADAFS_CFLAGS="${GF_CFLAGS}"
	GF_LDADD="${ARGP_STANDALONE_LDADD}"
	;;
     solaris*)
        GF_HOST_OS="GF_SOLARIS_HOST_OS"
	GF_CFLAGS="${ARGP_STANDALONE_CPPFLAGS} -D_REENTRANT"
	GF_LDFLAGS=""
	GF_HADAFS_CFLAGS="${GF_CFLAGS}"
	GF_LDADD="${ARGP_STANDALONE_LDADD}"
	GF_HADAFS_LDFLAGS="-lnsl -lresolv -lsocket"
	GF_BOOSTER_SUBDIR=""
	;;
     *bsd*)
        GF_HOST_OS="GF_BSD_HOST_OS"
	GF_CFLAGS="${ARGP_STANDALONE_CPPFLAGS}"
	GF_HADAFS_CFLAGS="${GF_CFLAGS}"
	GF_LDADD="${ARGP_STANDALONE_LDADD}"
	if test "x$ac_cv_header_execinfo_h" = "xyes"; then
	   GF_HADAFS_LDFLAGS="-lexecinfo"
	fi				      
	GF_FUSE_LDADD="-liconv -lfuse"
	BUILD_LIBHADAFSCLIENT=no
	LIBHADAFSCLIENT_SUBDIR=""
	GF_BOOSTER_SUBDIR=""
	;;
     darwin*)
        GF_HOST_OS="GF_DARWIN_HOST_OS"
	LIBTOOL=glibtool
	GF_CFLAGS="${ARGP_STANDALONE_CPPFLAGS} -D__DARWIN_64_BIT_INO_T -bundle -undefined suppress -flat_namespace"
	GF_HADAFS_CFLAGS="${ARGP_STANDALONE_CPPFLAGS} -D__DARWIN_64_BIT_INO_T -undefined suppress -flat_namespace"
	GF_LDADD="${ARGP_STANDALONE_LDADD}"
	GF_FUSE_LDADD="-liconv -lfuse_ino64"
	BUILD_LIBHADAFSCLIENT=no
	LIBHADAFSCLIENT_SUBDIR=""
	GF_BOOSTER_SUBDIR=""
	;;
esac

AC_SUBST(GF_HOST_OS)
AC_SUBST(GF_HADAFS_LDFLAGS)
AC_SUBST(GF_HADAFS_CFLAGS)
AC_SUBST(GF_CFLAGS)
AC_SUBST(GF_LDFLAGS)
AC_SUBST(GF_LDADD)
AC_SUBST(GF_FUSE_LDADD)
AC_SUBST(GF_BOOSTER_SUBDIR)

AM_CONDITIONAL([GF_DARWIN_HOST_OS], test "${GF_HOST_OS}" = "GF_DARWIN_HOST_OS")	

AC_OUTPUT

echo
echo "HADAFS configure summary"
echo "==========================="
echo "Infiniband verbs   : $BUILD_IBVERBS"
echo "swnet verbs   : $BUILD_SWVERBS"
echo "epoll IO multiplex : $BUILD_EPOLL"
echo "libhadafsclient : $BUILD_LIBHADAFSCLIENT"
echo "argp-standalone    : $BUILD_ARGP_STANDALONE"
echo

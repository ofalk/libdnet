dnl aclocal.m4 generated automatically by aclocal 1.4-p6

dnl Copyright (C) 1994, 1995-8, 1999, 2001 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.

dnl
dnl Check for 4.4 BSD sa_len member in sockaddr struct
dnl
dnl usage:	AC_DNET_SOCKADDR_SA_LEN
dnl results:	HAVE_SOCKADDR_SA_LEN (defined)
dnl
AC_DEFUN(AC_DNET_SOCKADDR_SA_LEN,
    [AC_MSG_CHECKING(for sa_len in sockaddr struct)
    AC_CACHE_VAL(ac_cv_dnet_sockaddr_has_sa_len,
        AC_TRY_COMPILE([
#       include <sys/types.h>
#       include <sys/socket.h>],
        [u_int i = sizeof(((struct sockaddr *)0)->sa_len)],
        ac_cv_dnet_sockaddr_has_sa_len=yes,
        ac_cv_dnet_sockaddr_has_sa_len=no))
    AC_MSG_RESULT($ac_cv_dnet_sockaddr_has_sa_len)
    if test $ac_cv_dnet_sockaddr_has_sa_len = yes ; then
            AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
                      [Define if sockaddr struct has sa_len.])
    fi])

dnl
dnl Check for arp_dev member in arpreq struct
dnl
dnl usage:	AC_DNET_ARPREQ_ARP_DEV
dnl results:	HAVE_ARPREQ_ARP_DEV (defined)
dnl
AC_DEFUN(AC_DNET_ARPREQ_ARP_DEV,
    [AC_MSG_CHECKING(for arp_dev in arpreq struct)
    AC_CACHE_VAL(ac_cv_dnet_arpreq_has_arp_dev,
	AC_TRY_COMPILE([
#       include <sys/types.h>
#	include <sys/socket.h>
#	include <net/if_arp.h>],
	[void *p = ((struct arpreq *)0)->arp_dev],
	ac_cv_dnet_arpreq_has_arp_dev=yes,
	ac_cv_dnet_arpreq_has_arp_dev=no))
    AC_MSG_RESULT($ac_cv_dnet_arpreq_has_arp_dev)
    if test $ac_cv_dnet_arpreq_has_arp_dev = yes ; then
	AC_DEFINE(HAVE_ARPREQ_ARP_DEV, 1,
		[Define if arpreq struct has arp_dev.])
    fi])


dnl
dnl Check for rt_msghdr struct in <net/route.h>
dnl
dnl usage:	AC_DNET_ROUTE_RT_MSGHDR
dnl results:	HAVE_ROUTE_RT_MSGHDR
dnl
AC_DEFUN(AC_DNET_ROUTE_RT_MSGHDR,
    [AC_MSG_CHECKING(for rt_msghdr struct in <net/route.h>)
    AC_CACHE_VAL(ac_cv_dnet_route_h_has_rt_msghdr,
        AC_TRY_COMPILE([
#       include <sys/types.h>
#       include <sys/socket.h>
#       include <net/if.h>
#       include <net/route.h>],
        [struct rt_msghdr rtm; rtm.rtm_msglen = 0;],
	ac_cv_dnet_route_h_has_rt_msghdr=yes,
	ac_cv_dnet_route_h_has_rt_msghdr=no))
    AC_MSG_RESULT($ac_cv_dnet_route_h_has_rt_msghdr)
    if test $ac_cv_dnet_route_h_has_rt_msghdr = yes ; then
        AC_DEFINE(HAVE_ROUTE_RT_MSGHDR, 1,
	          [Define if <net/route.h> has rt_msghdr struct.])
    fi])

dnl
dnl Check for the Berkeley Packet Filter
dnl
dnl usage:	AC_DNET_BSD_BPF
dnl results:	HAVE_BSD_BPF
dnl
AC_DEFUN(AC_DNET_BSD_BPF,
    [AC_MSG_CHECKING(for Berkeley Packet Filter)
    AC_CACHE_VAL(ac_cv_dnet_bsd_bpf,
	if test -c /dev/bpf0 ; then
	    ac_cv_dnet_bsd_bpf=yes
	else
	    ac_cv_dnet_bsd_bpf=no
	fi)
    AC_MSG_RESULT($ac_cv_dnet_bsd_bpf)
    if test $ac_cv_dnet_bsd_bpf = yes ; then
	AC_DEFINE(HAVE_BSD_BPF, 1,
		  [Define if you have the Berkeley Packet Filter.])
    fi])

dnl
dnl Check for the Linux /proc filesystem
dnl
dnl usage:	AC_DNET_LINUX_PROCFS
dnl results:	HAVE_LINUX_PROCFS
dnl
AC_DEFUN(AC_DNET_LINUX_PROCFS,
    [AC_MSG_CHECKING(for Linux proc filesystem)
    AC_CACHE_VAL(ac_cv_dnet_linux_procfs,
	if test "x`cat /proc/sys/kernel/ostype 2>&-`" = "xLinux" ; then
	    ac_cv_dnet_linux_procfs=yes
        else
	    ac_cv_dnet_linux_procfs=no
	fi)
    AC_MSG_RESULT($ac_cv_dnet_linux_procfs)
    if test $ac_cv_dnet_linux_procfs = yes ; then
	AC_DEFINE(HAVE_LINUX_PROCFS, 1,
		  [Define if you have the Linux /proc filesystem.])
    fi])

dnl
dnl Check for Linux PF_PACKET sockets
dnl
dnl usage:	AC_DNET_LINUX_PF_PACKET
dnl results:	HAVE_LINUX_PF_PACKET
dnl
AC_DEFUN(AC_DNET_LINUX_PF_PACKET,
    [AC_MSG_CHECKING(for Linux PF_PACKET sockets)
    AC_CACHE_VAL(ac_cv_dnet_linux_pf_packet,
	if test -f /usr/include/netpacket/packet.h ; then
	    ac_cv_dnet_linux_pf_packet=yes
	else
	    ac_cv_dnet_linux_pf_packet=no
	fi)
    AC_MSG_RESULT($ac_cv_dnet_linux_pf_packet)
    if test $ac_cv_dnet_linux_pf_packet = yes ; then
	AC_DEFINE(HAVE_LINUX_PF_PACKET, 1,
		  [Define if you have Linux PF_PACKET sockets.])
    fi])

dnl
dnl Check for SNMP MIB2 STREAMS (Solaris only?)
dnl
dnl usage:      AC_DNET_STREAMS_MIB2
dnl results:    HAVE_STREAMS_MIB2
dnl
AC_DEFUN(AC_DNET_STREAMS_MIB2,
    [AC_MSG_CHECKING(for SNMP MIB2 STREAMS)
    AC_CACHE_VAL(ac_cv_dnet_streams_mib2,
        if test -f /usr/include/inet/mib2.h -a -c /dev/ip ; then
            ac_cv_dnet_streams_mib2=yes
        else
            ac_cv_dnet_streams_mib2=no
        fi)
    AC_MSG_RESULT($ac_cv_dnet_streams_mib2)
    if test $ac_cv_dnet_streams_mib2 = yes ; then
        AC_DEFINE(HAVE_STREAMS_MIB2, 1,
                  [Define if you have SNMP MIB2 STREAMS.])
    fi])

dnl
dnl Check for route(7) STREAMS (UnixWare only?)
dnl
dnl usage:      AC_DNET_STREAMS_ROUTE
dnl results:    HAVE_STREAMS_ROUTE
dnl
AC_DEFUN(AC_DNET_STREAMS_ROUTE,
    [AC_MSG_CHECKING(for route(7) STREAMS)
    AC_CACHE_VAL(ac_cv_dnet_streams_route,
        if grep RTSTR_SEND /usr/include/net/route.h >/dev/null 2>&1 ; then
            ac_cv_dnet_streams_route=yes
        else
            ac_cv_dnet_streams_route=no
        fi)
    AC_MSG_RESULT($ac_cv_dnet_streams_route)
    if test $ac_cv_dnet_streams_route = yes ; then
        AC_DEFINE(HAVE_STREAMS_ROUTE, 1,
                  [Define if you have route(7) STREAMS.])
    fi])

dnl
dnl Check for arp(7) ioctls
dnl
dnl usage:      AC_DNET_IOCTL_ARP
dnl results:    HAVE_IOCTL_ARP
dnl
AC_DEFUN(AC_DNET_IOCTL_ARP,
    [AC_MSG_CHECKING(for arp(7) ioctls)
    AC_CACHE_VAL(ac_cv_dnet_ioctl_arp,
	AC_EGREP_CPP(werd, [
#	include <sys/types.h>
#	define BSD_COMP
#	include <sys/ioctl.h>
#	ifdef SIOCGARP
	werd
#	endif],
	ac_cv_dnet_ioctl_arp=yes,
	ac_cv_dnet_ioctl_arp=no))
    case "$host_os" in
    irix*)
        ac_cv_dnet_ioctl_arp=no ;;
    esac
    AC_MSG_RESULT($ac_cv_dnet_ioctl_arp)
    if test $ac_cv_dnet_ioctl_arp = yes ; then
        AC_DEFINE(HAVE_IOCTL_ARP, 1,
                  [Define if you have arp(7) ioctls.])
    fi])

dnl
dnl Check for raw IP sockets ip_{len,off} host byte ordering
dnl
dnl usage:      AC_DNET_RAWIP_HOST_OFFLEN
dnl results:    HAVE_RAWIP_HOST_OFFLEN
dnl
AC_DEFUN(AC_DNET_RAWIP_HOST_OFFLEN,
    [AC_MSG_CHECKING([for raw IP sockets ip_{len,off} host byte ordering])
    AC_CACHE_VAL(ac_cv_dnet_rawip_host_offlen, [
	case "$host_os" in
	*openbsd*)
	    ac_cv_dnet_rawip_host_offlen=no ;;
	*bsd*|*unixware*)
	    ac_cv_dnet_rawip_host_offlen=yes ;;
	*)
	    ac_cv_dnet_rawip_host_offlen=no ;;
	esac])
    AC_MSG_RESULT($ac_cv_dnet_rawip_host_offlen)
    if test $ac_cv_dnet_rawip_host_offlen = yes ; then
        AC_DEFINE(HAVE_RAWIP_HOST_OFFLEN, 1,
                  [Define if raw IP sockets require host byte ordering for ip_off, ip_len.])
    fi])

dnl
dnl Check for cooked raw IP sockets
dnl
dnl usage:      AC_DNET_RAWIP_COOKED
dnl results:    HAVE_RAWIP_COOKED
dnl
AC_DEFUN(AC_DNET_RAWIP_COOKED,
    [AC_MSG_CHECKING(for cooked raw IP sockets)
    AC_CACHE_VAL(ac_cv_dnet_rawip_cooked, [
	case "$host_os" in
	solaris*|irix*)
	    ac_cv_dnet_rawip_cooked=yes ;;
	*)
	    ac_cv_dnet_rawip_cooked=no ;;
	esac])
    AC_MSG_RESULT($ac_cv_dnet_rawip_cooked)
    if test $ac_cv_dnet_rawip_cooked = yes ; then
        AC_DEFINE(HAVE_RAWIP_COOKED, 1,
                  [Define if you have cooked raw IP sockets.])
    fi])

dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.

dnl It has been argued that this test should be broken up into two
dnl seperate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independantly potentially results in unfortunate ordering
dnl dependancies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    # Most operating systems have gethostbyname() in the default searched
    # libraries (i.e. libc):
    AC_CHECK_FUNC(gethostbyname, ,
        # Some OSes (eg. Solaris) place it in libnsl:
        AC_CHECK_LIB(nsl, gethostbyname, , 
            # Some strange OSes (SINIX) have it in libsocket:
            AC_CHECK_LIB(socket, gethostbyname, ,
                # Unfortunately libsocket sometimes depends on libnsl.
                # AC_CHECK_LIB's API is essentially broken so the
                # following ugliness is necessary:
                AC_CHECK_LIB(socket, gethostbyname,
                    LIBS="-lsocket -lnsl $LIBS",
                    AC_CHECK_LIB(resolv, gethostbyname),
                    -lnsl))))
    AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
        AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", ,
            -lnsl)))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_CHECK_LIB(str, putmsg)
    ])

# Do all the work for Automake.  This macro actually does too much --
# some checks are only needed if your package does certain things.
# But this isn't really a big deal.

# serial 1

dnl Usage:
dnl AM_INIT_AUTOMAKE(package,version, [no-define])

AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
AC_REQUIRE([AC_PROG_INSTALL])
PACKAGE=[$1]
AC_SUBST(PACKAGE)
VERSION=[$2]
AC_SUBST(VERSION)
dnl test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" && test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi
ifelse([$3],,
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package]))
AC_REQUIRE([AM_SANITY_CHECK])
AC_REQUIRE([AC_ARG_PROGRAM])
dnl FIXME This is truly gross.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal-${am__api_version}, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake-${am__api_version}, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_REQUIRE([AC_PROG_MAKE_SET])])

# Copyright 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
AC_DEFUN([AM_AUTOMAKE_VERSION],[am__api_version="1.4"])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION so it can be traced.
# This function is AC_REQUIREd by AC_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
	 [AM_AUTOMAKE_VERSION([1.4-p6])])

#
# Check to make sure that the build environment is sane.
#

AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftestfile
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftestfile 2> /dev/null`
   if test "[$]*" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftestfile`
   fi
   if test "[$]*" != "X $srcdir/configure conftestfile" \
      && test "[$]*" != "X conftestfile $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "[$]2" = conftestfile
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
rm -f conftest*
AC_MSG_RESULT(yes)])

dnl AM_MISSING_PROG(NAME, PROGRAM, DIRECTORY)
dnl The program must properly implement --version.
AC_DEFUN([AM_MISSING_PROG],
[AC_MSG_CHECKING(for working $2)
# Run test in a subshell; some versions of sh will print an error if
# an executable is not found, even if stderr is redirected.
# Redirect stdin to placate older versions of autoconf.  Sigh.
if ($2 --version) < /dev/null > /dev/null 2>&1; then
   $1=$2
   AC_MSG_RESULT(found)
else
   $1="$3/missing $2"
   AC_MSG_RESULT(missing)
fi
AC_SUBST($1)])

# Like AC_CONFIG_HEADER, but automatically create stamp file.

AC_DEFUN([AM_CONFIG_HEADER],
[AC_PREREQ([2.12])
AC_CONFIG_HEADER([$1])
dnl When config.status generates a header, we must update the stamp-h file.
dnl This file resides in the same directory as the config header
dnl that is generated.  We must strip everything past the first ":",
dnl and everything past the last "/".
AC_OUTPUT_COMMANDS(changequote(<<,>>)dnl
ifelse(patsubst(<<$1>>, <<[^ ]>>, <<>>), <<>>,
<<test -z "<<$>>CONFIG_HEADERS" || echo timestamp > patsubst(<<$1>>, <<^\([^:]*/\)?.*>>, <<\1>>)stamp-h<<>>dnl>>,
<<am_indx=1
for am_file in <<$1>>; do
  case " <<$>>CONFIG_HEADERS " in
  *" <<$>>am_file "*<<)>>
    echo timestamp > `echo <<$>>am_file | sed -e 's%:.*%%' -e 's%[^/]*$%%'`stamp-h$am_indx
    ;;
  esac
  am_indx=`expr "<<$>>am_indx" + 1`
done<<>>dnl>>)
changequote([,]))])

# Define a conditional.

AC_DEFUN([AM_CONDITIONAL],
[AC_SUBST($1_TRUE)
AC_SUBST($1_FALSE)
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi])


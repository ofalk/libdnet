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
dnl Check for Solaris /dev/ip device
dnl
dnl usage:      AC_DNET_SOLARIS_DEV_IP
dnl results:    HAVE_SOLARIS_DEV_IP
dnl
AC_DEFUN(AC_DNET_SOLARIS_DEV_IP,
    [AC_MSG_CHECKING(for Solaris /dev/ip device)
    AC_CACHE_VAL(ac_cv_dnet_solaris_dev_ip,
        if test -f /usr/include/inet/mib2.h -a -c /dev/ip ; then
            ac_cv_dnet_solaris_dev_ip=yes
        else
            ac_cv_dnet_solaris_dev_ip=no
        fi)
    AC_MSG_RESULT($ac_cv_dnet_solaris_dev_ip)
    if test $ac_cv_dnet_solaris_dev_ip = yes ; then
        AC_DEFINE(HAVE_SOLARIS_DEV_IP, 1,
                  [Define if you have the Solaris /dev/ip device.])
    fi])

dnl
dnl Improved version of AC_CHECK_LIB
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl     AC_LBL_CHECK_LIB(LIBRARY, FUNCTION [, ACTION-IF-FOUND [,
dnl         ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl
dnl results:
dnl
dnl     LIBS
dnl

define(AC_LBL_CHECK_LIB,
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $1 defining function $2, not
dnl just for library $1.  Separate tests with the same $1 and different $2's
dnl may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
            [$2()],
            eval "ac_cv_lbl_lib_$ac_lib_var=yes",
            eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])

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
        AC_LBL_CHECK_LIB(nsl, gethostbyname, , 
            # Some strange OSes (SINIX) have it in libsocket:
            AC_LBL_CHECK_LIB(socket, gethostbyname, ,
                # Unfortunately libsocket sometimes depends on libnsl.
                # AC_CHECK_LIB's API is essentially broken so the
                # following ugliness is necessary:
                AC_LBL_CHECK_LIB(socket, gethostbyname,
                    LIBS="-lsocket -lnsl $LIBS",
                    AC_CHECK_LIB(resolv, gethostbyname),
                    -lnsl))))
    AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
        AC_LBL_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", ,
            -lnsl)))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_CHECK_LIB(str, putmsg)
    ])

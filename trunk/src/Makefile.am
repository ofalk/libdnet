## $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libdnet.la

libdnet_la_SOURCES = addr-util.c addr.c blob.c ip-util.c ip6.c rand.c

EXTRA_libdnet_la_SOURCES = arp-bsd.c arp-ioctl.c arp-none.c arp-win32.c \
	eth-bsd.c eth-dlpi.c eth-linux.c eth-ndd.c eth-none.c eth-snoop.c \
	eth-win32.c fw-ipchains.c fw-ipf.c fw-ipfw.c fw-none.c fw-pf.c \
	fw-pktfilter.c intf-win32.c intf.c ip-cooked.c ip.c ip-win32.c \
	route-bsd.c route-hpux.c route-linux.c route-none.c route-win32.c \
	tun-bsd.c tun-linux.c tun-none.c tun-solaris.c

libdnet_la_LIBADD = @LTLIBOBJS@

libdnet_la_LDFLAGS = -version-info 1:0:0

## $Id$

include $(top_srcdir)/Makefile.am.common

lib_LIBRARIES = libdnet.a

libdnet_a_SOURCES = addr-util.c addr.c blob.c ip-util.c ip6.c rand.c

EXTRA_libdnet_a_SOURCES = arp-bsd.c arp-ioctl.c arp-none.c arp-win32.c \
	eth-bsd.c eth-dlpi.c eth-linux.c eth-ndd.c eth-none.c eth-snoop.c \
	eth-win32.c fw-ipchains.c fw-ipf.c fw-ipfw.c fw-none.c fw-pf.c \
	intf-win32.c intf.c ip-cooked.c ip.c ip-win32.c route-bsd.c \
	route-hpux.c route-linux.c route-none.c route-win32.c

libdnet_a_LIBADD = @LIBOBJS@

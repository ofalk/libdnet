## $Id$

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = dnet

dnet_SOURCES = dnet-int.h dnet.c addr.c arp.c aton.c eth.c hex.c ip.c icmp.c \
	tcp.c udp.c send.c fw.c intf.c route.c

man_MANS = dnet.8

EXTRA_DIST = $(man_MANS)

LDADD = $(top_srcdir)/src/libdnet.a

## $Id$

include $(top_srcdir)/Makefile.am.common

noinst_PROGRAMS = dnet

dnet_SOURCES = dnet-int.h dnet.c eth.c arp.c ip.c icmp.c tcp.c udp.c

noinst_MANS = dnet.8

EXTRA_DIST = $(noinst_MANS)

LDADD = $(top_srcdir)/src/libdnet.a

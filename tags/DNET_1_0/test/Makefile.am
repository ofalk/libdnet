## $Id$

include $(top_srcdir)/Makefile.am.common

noinst_PROGRAMS = addr arp fw intf route

addr_SOURCES = addr.c
arp_SOURCES = arp.c
fw_SOURCES = fw.c
intf_SOURCES = intf.c
route_SOURCES = route.c

LDADD = $(top_srcdir)/src/libdnet.a

SUBDIRS = dnet

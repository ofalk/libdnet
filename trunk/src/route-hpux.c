/*
 * route-hpux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mib.h>
#include <sys/socket.h>

#include <net/route.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "dnet.h"

struct route_handle {
	int	fd;
};

route_t *
route_open(void)
{
	route_t *r;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		return (NULL);

	if ((r->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		free(r);
		return (NULL);
	}
	return (r);
}

int
route_add(route_t *r, struct addr *dst, struct addr *gw)
{
	struct rtentry rt;
	
	assert(r != NULL && dst != NULL && gw != NULL);

	memset(&rt, 0, sizeof(rt));

	if (addr_ntos(dst, &rt.rt_dst) < 0 ||
	    addr_ntos(gw, &rt.rt_gateway) < 0)
		return (-1);

	if (dst->addr_bits < IP_ADDR_BITS) {
		rt.rt_flags = RTF_UP | RTF_GATEWAY;
		if (addr_btom(dst->addr_bits,
		    (u_int32_t *)&rt.rt_subnetmask) < 0)
			return (-1);
	} else {
		rt.rt_flags = RTF_UP | RTF_HOST | RTF_GATEWAY;
		addr_btom(IP_ADDR_BITS, (u_int32_t *)&rt.rt_subnetmask);
	}
	return (ioctl(r->fd, SIOCADDRT, &rt));
}

int
route_delete(route_t *r, struct addr *dst)
{
	struct rtentry rt;

	assert(r != NULL && dst != NULL);

	memset(&rt, 0, sizeof(rt));

	if (addr_ntos(dst, &rt.rt_dst) < 0)
		return (-1);

	if (dst->addr_bits < IP_ADDR_BITS) {
		rt.rt_flags = RTF_UP;
		if (addr_btom(dst->addr_bits,
		    (u_int32_t *)&rt.rt_subnetmask) < 0)
			return (-1);
	} else {
		rt.rt_flags = RTF_UP | RTF_HOST;
		addr_btom(IP_ADDR_BITS, (u_int32_t *)&rt.rt_subnetmask);
	}
	return (ioctl(r->fd, SIOCDELRT, &rt));
}

int
route_get(route_t *r, struct addr *dst, struct addr *gw)
{
	struct rtreq rtr;

	assert(r != NULL && dst != NULL && gw != NULL);

	memset(&rtr, 0, sizeof(rtr));
	memcpy(&rtr.rtr_destaddr, &dst->addr_ip, IP_ADDR_LEN);
	
	if (dst->addr_bits < IP_ADDR_BITS)
		addr_btom(dst->addr_bits, (u_int32_t *)&rtr.rtr_subnetmask);
	
	if (ioctl(r->fd, SIOCGRTENTRY, &rtr) < 0)
		return (-1);

	if (rtr.rtr_gwayaddr == 0) {
		errno = ESRCH;
		return (-1);
	}
	gw->addr_type = ADDR_TYPE_IP;
	gw->addr_bits = IP_ADDR_BITS;
	memcpy(&gw->addr_ip, &rtr.rtr_gwayaddr, IP_ADDR_LEN);

	return (0);
}

#define MAX_RTENTRIES	256	/* XXX */

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	struct nmparms nm;
	struct addr dst, gw;
	mib_ipRouteEnt rtentries[MAX_RTENTRIES];
	int fd, i, n, ret;
	
	if ((fd = open_mib("/dev/ip", O_RDWR, 0 /* XXX */, 0)) < 0)
		return (-1);
	
	nm.objid = ID_ipRouteTable;
	nm.buffer = rtentries;
	n = sizeof(rtentries);
	nm.len = &n;
	
	if (get_mib_info(fd, &nm) < 0) {
		close_mib(fd);
		return (-1);
	}
	close_mib(fd);

	dst.addr_type = gw.addr_type = ADDR_TYPE_IP;
	dst.addr_bits = gw.addr_bits = IP_ADDR_BITS;
	n /= sizeof(*rtentries);
	ret = 0;
	
	for (i = 0; i < n; i++) {
		if (rtentries[i].Type != NMDIRECT &&
		    rtentries[i].Type != NMREMOTE)
			continue;
		
		dst.addr_ip = rtentries[i].Dest;
		addr_mtob(rtentries[i].Mask, &dst.addr_bits);
		gw.addr_ip = rtentries[i].NextHop;

		if ((ret = callback(&dst, &gw, arg)) != 0)
			break;
	}
	return (ret);
}

int
route_close(route_t *r)
{
	assert(r != NULL);

	if (close(r->fd) < 0)
		return (-1);
	
	free(r);
	return (0);
}

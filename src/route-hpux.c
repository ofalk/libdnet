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
#include <sys/socket.h>

#include <net/route.h>

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
	
	if (r == NULL || dst == NULL || gw == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

	if (r == NULL || dst == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

	if (r == NULL || dst == NULL || gw == NULL) {
		errno = EINVAL;
		return (-1);
	}
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

#define MAX_RTENTRIES	128	/* XXX */

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	struct rtreq *rtr, rtbuf[MAX_RTENTRIES];
	struct rtlist rtl;
	struct addr dst, gw;
	int i, ret;
	
	if (r == NULL || callback == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&rtl, 0, sizeof(rtl));

	rtl.rtl_len = sizeof(rtbuf);
	rtl.rtl_rtreq = (uint32_t)rtbuf;

	if (ioctl(r->fd, SIOCGRTTABLE, &rtl) < 0)
		return (-1);

	dst.addr_type = gw.addr_type = ADDR_TYPE_IP;
	
	for (i = ret = 0; i < rtl.rtl_cnt; i++) {
		rtr = (struct rtreq *)(rtl.rtl_rtreq + i);

		if (rtr->rtr_gwayaddr == 0)
			continue;
		
		memcpy(&dst.addr_ip, &rtr->rtr_destaddr, IP_ADDR_LEN);
		addr_mtob((u_int32_t)rtr->rtr_subnetmask, &dst.addr_bits);
		memcpy(&gw.addr_ip, &rtr->rtr_gwayaddr, IP_ADDR_LEN);

		if ((ret = callback(&dst, &gw, arg)) != 0)
			break;
	}
	return (ret);
}

int
route_close(route_t *r)
{
	if (r == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(r->fd) < 0)
		return (-1);
	
	free(r);
	return (0);
}

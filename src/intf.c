/*
 * intf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <net/if.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct intf_handle {
	int	fd;
};

static int
intf_flags_to_iff(int flags)
{
	int n = 0;
	
	if (flags & INTF_FLAG_UP)
		n |= IFF_UP;
	else
		n &= ~IFF_UP;

	if (flags & INTF_FLAG_LOOPBACK)
		n |= IFF_LOOPBACK;
	else
		n &= ~IFF_LOOPBACK;
	
	if (flags & INTF_FLAG_POINTOPOINT)
		n |= IFF_POINTOPOINT;
	else
		n &= ~IFF_POINTOPOINT;
	
	if (flags & INTF_FLAG_NOARP)
		n |= IFF_NOARP;
	else
		n &= ~IFF_NOARP;

	if (flags & INTF_FLAG_MULTICAST)
		n |= IFF_MULTICAST;
	else
		n &= ~IFF_MULTICAST;
	
	return (n);
}

static int
intf_iff_to_flags(int iff)
{
	int n = 0;

	if (iff & IFF_UP)
		n |= INTF_FLAG_UP;	
	if (iff & IFF_LOOPBACK)
		n |= INTF_FLAG_LOOPBACK;
	if (iff & IFF_POINTOPOINT)
		n |= INTF_FLAG_POINTOPOINT;
	if (iff & IFF_NOARP)
		n |= INTF_FLAG_NOARP;
	if (iff & IFF_MULTICAST)
		n |= INTF_FLAG_MULTICAST;

	return (n);
}

intf_t *
intf_open(void)
{
	intf_t *intf;
	
	if ((intf = calloc(1, sizeof(*intf))) == NULL)
		return (NULL);

	if ((intf->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		free(intf);
		return (NULL);
	}
	return (intf);
}

#ifdef notyet
int
intf_add(intf_t *i, char *device, struct addr *addr)
{
	struct ifaliasreq ifra;

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, device, sizeof(ifra.ifra_name));
	addr_ntos(addr, &ifra.ifra_addr);
	/* XXX - needed? */
	if (addr->mask > 0 && addr->mask < IP_ADDR_BITS)
		addr_mtos(addr->mask, &ifra.ifra_mask);
	/* XXX - broadcast? */
	
	return (ioctl(i->fd, SIOCAIFADDR, (caddr_t)&ifra));
}

int
intf_delete(intf_t *i, char *device, struct addr *addr)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	addr_ntos(addr, &ifr.ifr_addr);
	
	return (ioctl(i->fd, SIOCDIFADDR, (caddr_t)&ifr));
}
#endif

int
intf_set(intf_t *i, char *device, struct intf_info *info)
{
	struct addr bcast;
	struct ifreq ifr;
	
	assert(device != NULL && info != NULL);
	
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if ((info->intf_info & INTF_INFO_ADDR) != 0) {
		if (addr_ntos(&info->intf_addr, &ifr.ifr_addr) < 0)
			return (-1);
		
		if (ioctl(i->fd, SIOCSIFADDR, &ifr) < 0)
			return (-1);
		
		if (addr_btos(info->intf_addr.addr_bits, &ifr.ifr_addr) == 0) {
			if (ioctl(i->fd, SIOCSIFNETMASK, &ifr) < 0)
				return (-1);
		}
		if (addr_bcast(&info->intf_addr, &bcast) == 0) {
			if (addr_ntos(&bcast, &ifr.ifr_broadaddr) == 0) {
				if (ioctl(i->fd, SIOCSIFBRDADDR, &ifr) < 0)
					return (-1);
			}
		}
	}
	if ((info->intf_info & INTF_INFO_FLAGS) != 0) {
		if (ioctl(i->fd, SIOCGIFFLAGS, &ifr) < 0)
			return (-1);
		
		ifr.ifr_flags = intf_flags_to_iff(info->intf_flags);
		
		if (ioctl(i->fd, SIOCSIFFLAGS, &ifr) < 0)
			return (-1);
	}
	if ((info->intf_info & INTF_INFO_MTU) != 0) {
		/* XXX - ifr_mtu missing on Solaris */
		ifr.ifr_metric = info->intf_mtu;
		
		if (ioctl(i->fd, SIOCSIFMTU, &ifr) < 0)
			return (-1);
	}
	return (0);
}

int
intf_get(intf_t *i, char *device, struct intf_info *info)
{
	struct ifreq ifr;

	assert(device != NULL && info != NULL);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	info->intf_info = 0;
	
	if (ioctl(i->fd, SIOCGIFADDR, &ifr) == 0) {
		if (addr_ston(&ifr.ifr_addr, &info->intf_addr) < 0)
			return (-1);
		info->intf_info |= INTF_INFO_ADDR;
	} else if (errno != EADDRNOTAVAIL)
		return (-1);
	
	if (ioctl(i->fd, SIOCGIFNETMASK, &ifr) == 0) {
		if (addr_stob(&ifr.ifr_addr, &info->intf_addr.addr_bits) < 0)
			return (-1);
	} else if (errno != EADDRNOTAVAIL)
		return (-1);
	
	if (ioctl(i->fd, SIOCGIFFLAGS, &ifr) < 0)
		return (-1);
	
	info->intf_flags = intf_iff_to_flags(ifr.ifr_flags);
	info->intf_info |= INTF_INFO_FLAGS;
	
	if (ioctl(i->fd, SIOCGIFMTU, &ifr) < 0)
		return (-1);

	/* XXX - ifr_mtu missing on Solaris */
	info->intf_mtu = ifr.ifr_metric;
	info->intf_info |= INTF_INFO_MTU;
	
	return (0);
}

int
intf_loop(intf_t *i, intf_handler callback, void *arg)
{
	struct intf_info info;
	struct ifreq *ifr;
	struct ifconf ifc;
	u_char *p, *pdev, buf[BUFSIZ];
	int ret;
	
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;

	if (ioctl(i->fd, SIOCGIFCONF, &ifc) < 0)
		return (-1);
	
	if (ifc.ifc_len < sizeof(*ifr)) {
		errno = EINVAL;
		return (-1);
	}
	pdev = "";
	
	for (p = buf; p < buf + ifc.ifc_len; ) {
		ifr = (struct ifreq *)p;
#ifdef HAVE_SOCKADDR_SA_LEN
		p += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
#else
		p += sizeof(*ifr);
#endif
		if (strcmp(ifr->ifr_name, pdev) != 0) {
			if (intf_get(i, ifr->ifr_name, &info) < 0)
				return (-1);

			if ((ret = callback(ifr->ifr_name, &info, arg)) != 0)
				return (ret);
		}
		pdev = ifr->ifr_name;
	}
	return (0);
}

int
intf_close(intf_t *intf)
{
	assert(intf != NULL);

	if (close(intf->fd) < 0)
		return (-1);
	
	free(intf);
	return (0);
}

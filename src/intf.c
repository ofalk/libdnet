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
#if defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_ROUTE_RT_MSGHDR)
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
#endif
#include <net/if.h>
#ifdef SIOCGARP
#include <net/if_arp.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct intf_handle {
	int	fd;
};

int	eth_get_hwaddr(eth_t *e, struct addr *ha);	/* XXX */
int	eth_set_hwaddr(eth_t *e, struct addr *ha);	/* XXX */

static void
intf_flags_to_iff(int flags, short *iff)
{
	short n = *iff;
	
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
	
	*iff = n;
}

static void
intf_iff_to_flags(short iff, int *flags)
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

	*flags = n;
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

#if 0
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
intf_set(intf_t *i, char *device, struct addr *addr, int *flags)
{
	struct ifreq ifr;

	if (device == NULL || (addr == NULL && flags == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	
	if (addr != NULL) {
		if (addr_ntos(addr, &ifr.ifr_addr) < 0)
			return (-1);

		switch (addr->addr_type) {
		case ADDR_TYPE_IP:
			if (ioctl(i->fd, SIOCSIFADDR, &ifr) < 0)
				return (-1);
			
			if (addr->addr_bits < IP_ADDR_BITS &&
			    addr_btos(addr->addr_bits, &ifr.ifr_addr) == 0) {
				return (ioctl(i->fd, SIOCSIFNETMASK, &ifr));
			}
			break;
		case ADDR_TYPE_ETH:
		{
#ifdef SIOCSIFHWADDR
			return (ioctl(i->fd, SIOCSIFHWADDR, &ifr));
			break;
#elif defined(HAVE_SYS_DLPI_H) || defined(HAVE_SYS_DLPIHDR_H) || defined(HAVE_NET_RAW_H)
			eth_t *eth;
			
			if ((eth = eth_open(device)) == NULL)
				return (-1);
			
			if (eth_set_hwaddr(eth, addr) < 0)
				return (-1);
			
			eth_close(eth);
			break;
#else
			/* FALLTHROUGH */
#endif
		}
		default:
			errno = EAFNOSUPPORT;
			return (-1);
		}
	}
	if (flags != NULL) {
		if (ioctl(i->fd, SIOCGIFFLAGS, &ifr) < 0)
			return (-1);
		
		intf_flags_to_iff(*flags, &ifr.ifr_flags);
		
		return (ioctl(i->fd, SIOCSIFFLAGS, &ifr));
	}
	return (0);
}

int
intf_get(intf_t *i, char *device, struct addr *addr, int *flags)
{
	struct ifreq ifr;
	
	if (device == NULL || (addr == NULL && flags == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	
	if (addr != NULL) {
		switch (addr->addr_type) {
		case ADDR_TYPE_IP:
			if (ioctl(i->fd, SIOCGIFADDR, &ifr) < 0)
				return (-1);
			
			if (addr_ston(&ifr.ifr_addr, addr) < 0)
				return (-1);
			
			if (ioctl(i->fd, SIOCGIFNETMASK, &ifr) == 0) {
				if (addr_stob(&ifr.ifr_addr,
				    &addr->addr_bits) < 0)
					return (-1);
			}
			break;
		case ADDR_TYPE_ETH:
		{
#ifdef SIOCGIFHWADDR
			if (ioctl(i->fd, SIOCGIFHWADDR, &ifr) < 0)
				return (-1);
			if (addr_ston(&ifr.ifr_hwaddr, addr) < 0)
				return (-1);
			break;
#elif defined(HAVE_SYS_DLPI_H) || defined(HAVE_SYS_DLPIHDR_H) || defined(HAVE_NET_RAW_H) || defined(HAVE_NET_PFILT_H)
			eth_t *eth;
			
			if ((eth = eth_open(device)) == NULL)
				return (-1);
			if (eth_get_hwaddr(eth, addr) < 0)
				return (-1);
			eth_close(eth);
			break;
#elif defined(SIOCGARP)
			struct arpreq ar;
			
			ar.arp_pa = ifr.ifr_addr;
			if (ioctl(i->fd, SIOCGARP, &ar) < 0)
				return (-1);
			if (addr_ston(&ar.arp_ha, addr) < 0)
				return (-1);
			break;
#elif defined(HAVE_SYS_SYSCTL_H) && defined(HAVE_ROUTE_RT_MSGHDR)
			struct if_msghdr *ifm;
			struct sockaddr_dl *sdl;
			u_char *p, *buf;
			size_t len;
			int mib[] = { CTL_NET, AF_ROUTE, 0, AF_LINK,
				      NET_RT_IFLIST, 0 };
			
			if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
				return (-1);
			if ((buf = malloc(len)) == NULL)
				return (-1);
			if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
				free(buf);
				return (-1);
			}
			for (p = buf; p < buf + len; p += ifm->ifm_msglen) {
				ifm = (struct if_msghdr *)p;
				sdl = (struct sockaddr_dl *)(ifm + 1);
				
				if (ifm->ifm_type != RTM_IFINFO ||
				    (ifm->ifm_addrs & RTA_IFP) == 0)
					continue;

				if (sdl->sdl_family != AF_LINK ||
				    sdl->sdl_nlen == 0 ||
				    memcmp(sdl->sdl_data, device,
					sdl->sdl_nlen) != 0)
					continue;
				
				if (!addr_ston((struct sockaddr *)sdl, addr))
					break;
			}
			free(buf);
			
			if (p >= buf + len) {
				errno = ESRCH;
				return (-1);
			}
			break;
#else
			/* FALLTHROUGH */
#endif
		}
		default:
			errno = EAFNOSUPPORT;
			return (-1);
		}
	}
	if (flags != NULL) {
		if (ioctl(i->fd, SIOCGIFFLAGS, &ifr) < 0)
			return (-1);
		
		intf_iff_to_flags(ifr.ifr_flags, flags);
	}
	return (0);
}

int
intf_loop(intf_t *i, intf_handler callback, void *arg)
{
	struct ifreq *ifr, iftmp;
	struct ifconf ifc;
	struct addr addr;
	u_char *p, buf[BUFSIZ];
	int flags, ret;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;

	if (ioctl(i->fd, SIOCGIFCONF, &ifc) < 0)
		return (-1);
	
	if (ifc.ifc_len < sizeof(*ifr)) {
		errno = EINVAL;
		return (-1);
	}
	for (p = buf; p < buf + ifc.ifc_len; ) {
		ifr = (struct ifreq *)p;
#ifdef HAVE_SOCKADDR_SA_LEN
		p += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
#else
		p += sizeof(*ifr);
#endif
		if (ifr->ifr_addr.sa_family != AF_INET ||
		    addr_ston(&ifr->ifr_addr, &addr) < 0)
			continue;

		iftmp = *ifr;
		if (ioctl(i->fd, SIOCGIFFLAGS, &iftmp) < 0)
			continue;
		
		if ((iftmp.ifr_flags & IFF_UP) == 0)
			continue;

		intf_iff_to_flags(iftmp.ifr_flags, &flags);

		iftmp = *ifr;
		if (ioctl(i->fd, SIOCGIFNETMASK, &iftmp) == 0) {
			if (addr_stob(&iftmp.ifr_addr, &addr.addr_bits) < 0)
				continue;
		}
		if ((ret = callback(ifr->ifr_name, &addr, flags, arg)) != 0)
			return (ret);
	}
	return (0);
}

int
intf_close(intf_t *intf)
{
	if (intf == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(intf->fd) < 0)
		return (-1);
	
	free(intf);
	return (0);
}

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

/* XXX - Tru64 */
#if defined(SIOCRIPMTU) && defined(SIOCSIPMTU)
# define SIOCGIFMTU	SIOCRIPMTU
# define SIOCSIFMTU	SIOCSIPMTU
#endif

/* XXX - HP-UX */
#if defined(SIOCADDIFADDR) && defined(SIOCDELIFADDR)
# define SIOCAIFADDR	SIOCADDIFADDR
# define SIOCDIFADDR	SIOCDELIFADDR
#endif

/* XXX - HP-UX, Solaris */
#if !defined(ifr_mtu) && defined(ifr_metric)
# define ifr_mtu	ifr_metric
#endif

/* XXX - superset of ifreq, for portable SIOC{A,D}IFADDR */
struct dnet_ifaliasreq {
	char		ifra_name[IFNAMSIZ];
	struct sockaddr ifra_addr;
	struct sockaddr ifra_brdaddr;
	struct sockaddr ifra_mask;
};

struct intf_handle {
	int	fd;
};

static int
intf_flags_to_iff(u_short flags, int iff)
{
	if (flags & INTF_FLAG_UP)
		iff |= IFF_UP;
	else
		iff &= ~IFF_UP;
	if (flags & INTF_FLAG_NOARP)
		iff |= IFF_NOARP;
	else
		iff &= ~IFF_NOARP;
	
	return (iff);
}

static u_int
intf_iff_to_flags(int iff)
{
	u_int n = 0;

	if (iff & IFF_UP)
		n |= INTF_FLAG_UP;	
	if (iff & IFF_LOOPBACK)
		n |= INTF_FLAG_LOOPBACK;
	if (iff & IFF_POINTOPOINT)
		n |= INTF_FLAG_POINTOPOINT;
	if (iff & IFF_NOARP)
		n |= INTF_FLAG_NOARP;
	if (iff & IFF_BROADCAST)
		n |= INTF_FLAG_BROADCAST;
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

	if ((intf->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (intf_close(intf));
	
	return (intf);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
#ifdef SIOCAIFADDR
	struct dnet_ifaliasreq ifra;
#endif
	struct ifreq ifr;
	struct addr bcast;
	struct intf_entry *orig;
	u_char buf[4096];
	int i;
	
	orig = (struct intf_entry *)buf;
	orig->intf_len = sizeof(buf);
	strcpy(orig->intf_name, entry->intf_name);
	
	if (intf_get(intf, orig) < 0)
		return (-1);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, entry->intf_name, sizeof(ifr.ifr_name));

	if (entry->intf_mtu != 0) {
		ifr.ifr_mtu = entry->intf_mtu;
		if (ioctl(intf->fd, SIOCSIFMTU, &ifr) < 0)
			return (-1);
	}
	if (entry->intf_addr != NULL) {
		if (addr_btos(entry->intf_addr->addr_bits,
		    &ifr.ifr_addr) == 0) {
			if (ioctl(intf->fd, SIOCSIFNETMASK, &ifr) < 0)
				return (-1);
		}
		if (addr_ntos(entry->intf_addr, &ifr.ifr_addr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFADDR, &ifr) < 0 && errno != EEXIST)
			return (-1);
		
		if (addr_bcast(entry->intf_addr, &bcast) == 0) {
			if (addr_ntos(&bcast, &ifr.ifr_broadaddr) == 0) {
				/* XXX - ignore error from non-broadcast ifs */
				ioctl(intf->fd, SIOCSIFBRDADDR, &ifr);
			}
		}
	}
#ifdef SIOCDIFADDR
	else if (orig->intf_addr != NULL) {
		addr_ntos(orig->intf_addr, &ifr.ifr_addr);
		if (ioctl(intf->fd, SIOCDIFADDR, &ifr) < 0)
			return (-1);
	}
#endif
	if (entry->intf_link_addr != NULL) {
#if defined(SIOCSIFHWADDR)
		if (addr_ntos(entry->intf_link_addr, &ifr.ifr_hwaddr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFHWADDR, &ifr) < 0)
			return (-1);
#elif defined (SIOCSIFLLADDR)
		memcpy(ifr.ifr_addr.sa_data, &entry->intf_link_addr->addr_eth,
		    ETH_ADDR_LEN);
		ifr.ifr_addr.sa_len = ETH_ADDR_LEN;
		if (ioctl(intf->fd, SIOCSIFLLADDR, &ifr) < 0)
			return (-1);
#else
		eth_t *eth;

		if ((eth = eth_open(entry->intf_name)) == NULL)
			return (-1);
		if (eth_set(eth, &entry->intf_link_addr->addr_eth) < 0) {
			eth_close(eth);
			return (-1);
		}
		eth_close(eth);
#endif
	}
	if (entry->intf_dst_addr != NULL) {
		if (addr_ntos(entry->intf_dst_addr, &ifr.ifr_dstaddr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFDSTADDR, &ifr) < 0 &&
		    errno != EEXIST)
			return (-1);
	}
#ifdef SIOCAIFADDR
	strlcpy(ifra.ifra_name, entry->intf_name, sizeof(ifra.ifra_name));
#endif
	for (i = 0; i < orig->intf_alias_num; i++) {
#ifdef SIOCAIFADDR	/* XXX - Linux has SIOCDIFADDR we want to skip */
		addr_ntos(&orig->intf_alias_addr[i], &ifra.ifra_addr);
		ioctl(intf->fd, SIOCDIFADDR, &ifra);
#else
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d",
		    entry->intf_name, i);
# ifdef SIOCLIFREMOVEIF
		/* XXX - overloading lifreq with ifreq */
		ioctl(intf->fd, SIOCLIFREMOVEIF, &ifr);
# else
		ifr.ifr_flags = 0;
		ioctl(intf->fd, SIOCSIFFLAGS, &ifr);
# endif /* SIOCLIFREMOVEIF */
#endif
	}
	for (i = 0; i < entry->intf_alias_num; i++) {
#ifdef SIOCAIFADDR
		if (addr_ntos(&entry->intf_alias_addr[i], &ifra.ifra_addr) < 0)
			return (-1);
		
		addr_bcast(&entry->intf_alias_addr[i], &bcast);
		addr_ntos(&bcast, &ifra.ifra_brdaddr);
		addr_btos(IP_ADDR_BITS, &ifra.ifra_mask);
		
		if (ioctl(intf->fd, SIOCAIFADDR, &ifra) < 0)
			return (-1);
#else
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s:%d",
		    entry->intf_name, i);
# ifdef SIOCLIFADDIF
		if (ioctl(intf->fd, SIOCLIFADDIF, &ifr) < 0)
			return (-1);
# endif
		if (addr_ntos(&entry->intf_alias_addr[i], &ifr.ifr_addr) < 0)
			return (-1);
		if (ioctl(intf->fd, SIOCSIFADDR, &ifr) < 0)
			return (-1);
#endif /* SIOCAIFADDR */
	}
	if (ioctl(intf->fd, SIOCGIFFLAGS, &ifr) < 0)
		return (-1);
	
	ifr.ifr_flags = intf_flags_to_iff(entry->intf_flags, ifr.ifr_flags);
	
	if (ioctl(intf->fd, SIOCSIFFLAGS, &ifr) < 0)
		return (-1);
	
	return (0);
}

static int
_intf_get_entry(const struct intf_entry *entry, void *arg)
{
	struct intf_entry *e = (struct intf_entry *)arg;
	off_t off;
	
	if (strcmp(e->intf_name, entry->intf_name) == 0) {
		if (e->intf_len < entry->intf_len) {
			errno = EINVAL;
			return (-1);
		}
		memcpy(e, entry, entry->intf_len);
		off = (u_char *)e - (u_char *)entry;

#define ADDROFF(a, o)	((struct addr *)((u_char *)a + o))
		if (e->intf_addr != NULL)
			e->intf_addr = ADDROFF(e->intf_addr, off);
		if (e->intf_link_addr != NULL)
			e->intf_link_addr = ADDROFF(e->intf_link_addr, off);
		if (e->intf_dst_addr != NULL)
			e->intf_dst_addr = ADDROFF(e->intf_dst_addr, off);
		if (e->intf_alias_addr != NULL)
			e->intf_alias_addr = ADDROFF(e->intf_alias_addr, off);

		return (1);
	}
	return (0);
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	errno = ENXIO;
	
	if (intf_loop(intf, _intf_get_entry, entry) != 1)
		return (-1);
	
	return (0);
}

/* XXX - this is total crap. how to do this without walking ifnet? */
static void
_intf_set_type(struct intf_entry *entry)
{
	if ((entry->intf_flags & INTF_FLAG_BROADCAST) != 0)
		entry->intf_type = INTF_TYPE_ETH;
	else if ((entry->intf_flags & INTF_FLAG_POINTOPOINT) != 0)
		entry->intf_type = INTF_TYPE_TUN;
	else if ((entry->intf_flags & INTF_FLAG_LOOPBACK) != 0)
		entry->intf_type = INTF_TYPE_LOOPBACK;
	else
		entry->intf_type = INTF_TYPE_OTHER;
}

#ifdef HAVE_SOCKADDR_SA_LEN
# define NEXTIFR(i)	((struct ifreq *)((u_char *)&i->ifr_addr + \
				i->ifr_addr.sa_len))
#else
# define NEXTIFR(i)	(i + 1)
#endif

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	struct ifconf ifc;
	struct ifreq *ifr, *lifr, iftmp;
	struct addr *ap, *lap;
	char *p, ebuf[4096], ibuf[8192];
	int ret;
	
	ifc.ifc_buf = ibuf;
	ifc.ifc_len = sizeof(ibuf);
	
	if (ioctl(intf->fd, SIOCGIFCONF, &ifc) < 0) {
		return (-1);
	} else if (ifc.ifc_len < sizeof(*ifr)) {
		errno = EINVAL;
		return (-1);
	}
	lifr = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];
	entry = (struct intf_entry *)ebuf;
	lap = (struct addr *)(ebuf + sizeof(ebuf));
	
	/*
	 * XXX - this code assumes SIOCGIFCONF returns all
	 * configured addresses for an interface in a row.
	 */
	for (ifr = ifc.ifc_req; ifr < lifr; ) {
		memset(entry, 0, sizeof(*entry));
		
		strcpy(iftmp.ifr_name, ifr->ifr_name);
		strlcpy(entry->intf_name, ifr->ifr_name,
		    sizeof(entry->intf_name));

		/* Get addresses for this interface. */
		for (ap = entry->intf_addr_data; ifr < lifr && ap < lap;
		    ifr = NEXTIFR(ifr)) {
			/* XXX - Linux, Solaris ifaliases */
			if ((p = strchr(ifr->ifr_name, ':')) != NULL)
				*p = '\0';
			
			if (strcmp(ifr->ifr_name, entry->intf_name) != 0)
				break;
			if (addr_ston(&ifr->ifr_addr, ap) < 0)
				continue;
			
			if (ap->addr_type == ADDR_TYPE_ETH) {
				entry->intf_link_addr = ap;
			} else {
				if (entry->intf_addr == NULL) {
					entry->intf_addr = ap;
				} else {
					if (entry->intf_alias_addr == NULL)
						entry->intf_alias_addr = ap;
					entry->intf_alias_num++;
				}
			}
			ap++;
		}
		if (entry->intf_addr != NULL) {
			if (ioctl(intf->fd, SIOCGIFNETMASK, &iftmp) < 0)
				return (-1);
			addr_stob(&iftmp.ifr_addr,
			    &entry->intf_addr->addr_bits);
		}
		/* Get interface flags. */
		if (ioctl(intf->fd, SIOCGIFFLAGS, &iftmp) < 0)
			return (-1);
		
		entry->intf_flags = intf_iff_to_flags(iftmp.ifr_flags);
		
		_intf_set_type(entry);

		/* Get other addresses. */
		if (entry->intf_type == INTF_TYPE_TUN && ap < lap) {
			if (ioctl(intf->fd, SIOCGIFDSTADDR, &iftmp) == 0) {
				if (addr_ston(&iftmp.ifr_addr, ap) < 0)
					return (-1);
				if (ap->addr_type == ADDR_TYPE_IP)
					entry->intf_dst_addr = ap++;
			}
		} else if (entry->intf_type == INTF_TYPE_ETH &&
		    entry->intf_link_addr == NULL && ap < lap) {
#if defined(SIOCGIFHWADDR)
			if (ioctl(intf->fd, SIOCGIFHWADDR, &iftmp) < 0)
				return (-1);
			if (addr_ston(&iftmp.ifr_addr, ap) < 0)
				return (-1);
#elif defined(SIOCGENADDR)
			if (ioctl(intf->fd, SIOCGENADDR, &iftmp) < 0)
				return (-1);
			ap->addr_type = ADDR_TYPE_ETH;
			ap->addr_bits = ETH_ADDR_BITS;
			memcpy(&ap->addr_eth, iftmp.ifr_enaddr, ETH_ADDR_LEN);
#else
			eth_t *eth;

			if ((eth = eth_open(entry->intf_name)) != NULL) {
				ap->addr_type = ADDR_TYPE_ETH;
				ap->addr_bits = ETH_ADDR_BITS;
				if (eth_get(eth, &ap->addr_eth) < 0) {
					/* XXX - hrr */
					memcpy(&ap->addr_eth,
					    ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
				}
				eth_close(eth);
			}
#endif
			entry->intf_link_addr = ap++;
		}
		/* Get interface MTU. */
		if (ioctl(intf->fd, SIOCGIFMTU, &iftmp) < 0)
			return (-1);
		entry->intf_mtu = iftmp.ifr_mtu;
		
		entry->intf_len = (u_char *)ap - (u_char *)entry;
		
		if ((ret = (*callback)(entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

intf_t *
intf_close(intf_t *intf)
{
	assert(intf != NULL);

	if (intf->fd > 0)
		close(intf->fd);
	free(intf);
	return (NULL);
}

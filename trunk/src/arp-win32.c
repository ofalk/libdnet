/*
 * arp-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <ws2tcpip.h>
#include <Iphlpapi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

struct arp_handle {
	intf_t			*intf;
	const struct addr	*pa;
	struct addr		*ha;
};

arp_t *
arp_open(void)
{
	arp_t *arp;

	if ((arp = calloc(1, sizeof(*arp))) == NULL)
		return (NULL);

	if ((arp->intf = intf_open()) == NULL) {
		free(arp);
		return (NULL);
	}
	return (arp);
}

int
arp_add(arp_t *arp, const struct addr *pa, const struct addr *ha)
{
	MIB_IPFORWARDROW ipfrow;
	MIB_IPNETROW iprow;
	
	if (GetBestRoute(pa->addr_ip, IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	iprow.dwIndex = ipfrow.dwForwardIfIndex;
	iprow.dwPhysAddrLen = ETH_ADDR_LEN;
	memcpy(iprow.bPhysAddr, &ha->addr_eth, ETH_ADDR_LEN);
	iprow.dwAddr = pa->addr_ip;
	iprow.dwType = 4; /* static */

	if (CreateIpNetEntry(&iprow) != NO_ERROR)
		return (-1);

	return (0);
}

int
arp_delete(arp_t *arp, const struct addr *pa)
{
	MIB_IPFORWARDROW ipfrow;
	MIB_IPNETROW iprow;

	if (GetBestRoute(pa->addr_ip, IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	memset(&iprow, 0, sizeof(iprow));
	iprow.dwIndex = ipfrow.dwForwardIfIndex;
	iprow.dwAddr = pa->addr_ip;

	if (DeleteIpNetEntry(&iprow) != NO_ERROR)
		return (-1);

	return (0);
}

static int
_arp_get(const struct addr *pa, const struct addr *ha, void *arg)
{
	arp_t *arp = (arp_t *)arg;
	
	if (addr_cmp(pa, arp->pa) == 0) {
		memcpy(arp->ha, ha, sizeof(*ha));
		return (1);
	}
	return (0);
}

int
arp_get(arp_t *arp, const struct addr *pa, struct addr *ha)
{
	int ret;
	
	arp->pa = pa;
	arp->ha = ha;

	ret = arp_loop(arp, _arp_get, arp);

	if (ret == 0) {
		errno = ENXIO;
		return (-1);
	} else if (ret == 1)
		return (0);

	return (ret);
}

int
arp_loop(arp_t *arp, arp_handler callback, void *arg)
{
	MIB_IPNETTABLE *iptable;
	ULONG len;
	struct addr pa, ha;
	u_char buf[2048];
	int i, ret;
	
	iptable = (MIB_IPNETTABLE *)buf;
	len = sizeof(buf);
	
	if (GetIpNetTable(iptable, &len, FALSE) != NO_ERROR)
		return (-1);

	pa.addr_type = ADDR_TYPE_IP;
	pa.addr_bits = IP_ADDR_BITS;
	
	ha.addr_type = ADDR_TYPE_ETH;
	ha.addr_bits = ETH_ADDR_BITS;
	
	for (i = 0; i < iptable->dwNumEntries; i++) {
		if (iptable->table[i].dwPhysAddrLen != ETH_ADDR_LEN)
			continue;
		pa.addr_ip = iptable->table[i].dwAddr;
		memcpy(&ha.addr_eth, iptable->table[i].bPhysAddr,
		    ETH_ADDR_LEN);

		if ((ret = (*callback)(&pa, &ha, arg)) != 0)
			return (ret);
	}
	return (0);
}

int
arp_close(arp_t *arp)
{
	if (arp->intf != NULL)
		intf_close(arp->intf);
	free(arp);
	return (0);
}

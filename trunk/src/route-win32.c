/*
 * route-win32.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

struct route_handle {
	int	dummy;
};

route_t *
route_open(void)
{
	return ((route_t *)calloc(1, sizeof(route_t)));
}

int
route_add(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;

	memset(&ipfrow, 0, sizeof(ipfrow));

	if (GetBestInterface(entry->route_gw.addr_ip,
	    &ipfrow.dwForwardIfIndex) != NO_ERROR)
		return (-1);
	
	ipfrow.dwForwardDest = entry->route_dst.addr_ip;
	addr_btom(entry->route_dst.addr_bits,
	    &ipfrow.dwForwardMask, IP_ADDR_LEN);
	ipfrow.dwForwardNextHop = entry->route_gw.addr_ip;
	ipfrow.dwForwardType = 4;	/* XXX - next hop != final dest */
	ipfrow.dwForwardProto = 3;	/* XXX - MIB_PROTO_NETMGMT */
	
	if (CreateIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_delete(route_t *route, const struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;
	
	if (GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	if (ipfrow.dwForwardDest != entry->route_dst.addr_ip ||
	    ipfrow.dwForwardMask != mask) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	if (DeleteIpForwardEntry(&ipfrow) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
route_get(route_t *route, struct route_entry *entry)
{
	MIB_IPFORWARDROW ipfrow;
	DWORD mask;

	if (GetBestRoute(entry->route_dst.addr_ip,
	    IP_ADDR_ANY, &ipfrow) != NO_ERROR)
		return (-1);

	if (ipfrow.dwForwardProto == 2 &&	/* XXX - MIB_IPPROTO_LOCAL */
	    (ipfrow.dwForwardNextHop|IP_CLASSA_NET) !=
	    (IP_ADDR_LOOPBACK|IP_CLASSA_NET) &&
	    !IP_LOCAL_GROUP(ipfrow.dwForwardNextHop)) { 
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	addr_btom(entry->route_dst.addr_bits, &mask, IP_ADDR_LEN);
	
	entry->route_gw.addr_type = ADDR_TYPE_IP;
	entry->route_gw.addr_bits = IP_ADDR_BITS;
	entry->route_gw.addr_ip = ipfrow.dwForwardNextHop;
	
	return (0);
}

int
route_loop(route_t *route, route_handler callback, void *arg)
{
	MIB_IPFORWARDTABLE *ipftable;
	ULONG len;
	struct route_entry entry;
	u_char buf[4096];
	u_long i;
	int ret;
	
	ipftable = (MIB_IPFORWARDTABLE *)buf;
	len = sizeof(buf);
	
	if (GetIpForwardTable(ipftable, &len, FALSE) != NO_ERROR)
		return (-1);

	entry.route_dst.addr_type = ADDR_TYPE_IP;
	entry.route_dst.addr_bits = IP_ADDR_BITS;
	
	entry.route_gw.addr_type = ADDR_TYPE_IP;
	entry.route_gw.addr_bits = IP_ADDR_BITS;
	
	for (i = 0; i < ipftable->dwNumEntries; i++) {
		entry.route_dst.addr_ip = ipftable->table[i].dwForwardDest;
		addr_mtob(&ipftable->table[i].dwForwardMask, IP_ADDR_LEN,
		    &entry.route_dst.addr_bits);
		entry.route_gw.addr_ip = ipftable->table[i].dwForwardNextHop;

		if ((ret = (*callback)(&entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

route_t *
route_close(route_t *route)
{
	free(route);
	return (NULL);
}

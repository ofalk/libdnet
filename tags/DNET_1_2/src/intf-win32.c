/*
 * intf-win32.c
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

struct intf_handle {
	int	fd;
};

intf_t *
intf_open(void)
{
	return ((intf_t *)calloc(1, sizeof(intf_t)));
}

static int
_intf_get_entry(const struct intf_entry *entry, void *arg)
{
	struct intf_entry *e = (struct intf_entry *)arg;
	
	if (strcmp(e->intf_name, entry->intf_name) == 0) {
		if (e->intf_len < entry->intf_len) {
			errno = EINVAL;
			return (-1);
		}
		memcpy(e, entry, entry->intf_len);
		return (1);
	}
	return (0);
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	if (intf_loop(intf, _intf_get_entry, entry) != 1) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	return (0);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	/*
	 * XXX - could set interface down via SetIfEntry(),
	 * but what about the rest of the configuration? :-(
	 */
	errno = ENOSYS;
	SetLastError(ERROR_NOT_SUPPORTED);
	return (-1);
}

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	MIB_IPADDRTABLE *iptable;
	MIB_IFTABLE *iftable;
	ULONG len;
	struct intf_entry *entry;
	struct addr *ap;
	u_char ebuf[1024], ifbuf[4192], ipbuf[1024];
	int i, j, ret;

	iftable = (MIB_IFTABLE *)ifbuf;
	len = sizeof(ifbuf);

	if (GetIfTable(iftable, &len, FALSE) != NO_ERROR)
		return (-1);

	iptable = (MIB_IPADDRTABLE *)ipbuf;
	len = sizeof(ipbuf);

	if (GetIpAddrTable(iptable, &len, FALSE) != NO_ERROR)
		return (-1);

	entry = (struct intf_entry *)ebuf;
	
	for (i = 0; i < iftable->dwNumEntries; i++) {
		memset(entry, 0, sizeof(*entry));
		
		strlcpy(entry->intf_name, iftable->table[i].bDescr,
		    sizeof(entry->intf_name));
		
		/* XXX - dwType matches MIB-II ifType. */
		switch (iftable->table[i].dwType) {
		case MIB_IF_TYPE_ETHERNET:
		case MIB_IF_TYPE_LOOPBACK:
			entry->intf_type = iftable->table[i].dwType;
			break;
		default:
			entry->intf_type = INTF_TYPE_OTHER;
			break;
		}
		/* Get interface flags. */
		entry->intf_flags = 0;
		
		if (iftable->table[i].dwAdminStatus == MIB_IF_ADMIN_STATUS_UP)
			entry->intf_flags |= INTF_FLAG_UP;
		if (iftable->table[i].dwType == MIB_IF_TYPE_LOOPBACK)
			entry->intf_flags |= INTF_FLAG_LOOPBACK;
		else
			entry->intf_flags |= INTF_FLAG_MULTICAST;

		/* Get interface MTU. */
		entry->intf_mtu = iftable->table[i].dwMtu;

		/* Get hardware address. */
		if (iftable->table[i].dwType == MIB_IF_TYPE_ETHERNET &&
		    iftable->table[i].dwPhysAddrLen == ETH_ADDR_LEN) {
			entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
			entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
			memcpy(&entry->intf_link_addr.addr_eth,
			    iftable->table[i].bPhysAddr, ETH_ADDR_LEN);
		}
		/* Get addresses. */
		ap = entry->intf_alias_addrs;
		for (j = 0; j < iptable->dwNumEntries; j++) {
			if (iptable->table[j].dwIndex !=
			    iftable->table[i].dwIndex)
				continue;

			if (entry->intf_addr.addr_type != ADDR_TYPE_IP) {
				entry->intf_addr.addr_type = ADDR_TYPE_IP;
				entry->intf_addr.addr_ip =
				    iptable->table[j].dwAddr;
				addr_mtob(&iptable->table[j].dwMask,
				    IP_ADDR_LEN, &entry->intf_addr.addr_bits);
			} else {
				ap->addr_type = ADDR_TYPE_IP;
				ap->addr_ip = iptable->table[j].dwAddr;
				addr_mtob(&iptable->table[j].dwMask,
				    IP_ADDR_LEN, &ap->addr_bits);
				ap++, entry->intf_alias_num++;
			}
		}
		entry->intf_len = (u_char *)ap - (u_char *)entry;
		
		if ((ret = (*callback)(entry, arg)) != 0)
			return (ret);
	}
	return (0);
}

intf_t *
intf_close(intf_t *intf)
{
	free(intf);
	return (NULL);
}

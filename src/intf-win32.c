/*
 * intf-win32.c
 *
 * Copyright (c) 2023-2024 Oliver Falk <oliver@linux-kernel.at>
 *
 */

#include "config.h"

#include <iphlpapi.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

/* XXX - ipifcons.h incomplete, use IANA ifTypes MIB */
#define MIB_IF_TYPE_TUNNEL	131
#define MIB_IF_TYPE_MAX		259 /* According to ipifcons.h */

struct intf_handle {
	MIB_IFTABLE	*iftable;
	MIB_IPADDRTABLE	*iptable;
};

static char *
_ifcombo_name(int type)
{
	char *name = "eth";	/* XXX */
	
	if (type == MIB_IF_TYPE_TOKENRING) {
		name = "tr";
	} else if (type == MIB_IF_TYPE_FDDI) {
		name = "fddi";
	} else if (type == MIB_IF_TYPE_PPP) {
		name = "ppp";
	} else if (type == MIB_IF_TYPE_LOOPBACK) {
		name = "lo";
	} else if (type == MIB_IF_TYPE_SLIP) {
		name = "sl";
	} else if (type == MIB_IF_TYPE_TUNNEL) {
		name = "tun";
	}
	return (name);
}

static void
_ifrow_to_entry(intf_t *intf, MIB_IFROW *ifrow, struct intf_entry *entry)
{
	struct addr *ap, *lap;
	int i;
	
	/* The total length of the entry may be passed in inside entry.
	   Remember it and clear the entry. */
	u_int intf_len = entry->intf_len;
	memset(entry, 0, sizeof(*entry));
	/* Restore the length. */
	entry->intf_len = intf_len;

	/* XXX - dwType matches MIB-II ifType. */
	snprintf(entry->intf_name, sizeof(entry->intf_name), "%s%lu",
	    _ifcombo_name(ifrow->dwType), (unsigned long)ifrow->dwIndex);
	entry->intf_type = (uint16_t)ifrow->dwType;
	
	/* Get interface flags. */
	entry->intf_flags = 0;
	if (ifrow->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP &&
	    (ifrow->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL ||
	     ifrow->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED))
		entry->intf_flags |= INTF_FLAG_UP;
	if (ifrow->dwType == MIB_IF_TYPE_LOOPBACK)
		entry->intf_flags |= INTF_FLAG_LOOPBACK;
	else
		entry->intf_flags |= INTF_FLAG_MULTICAST;
	
	/* Get interface MTU. */
	entry->intf_mtu = ifrow->dwMtu;
	
	/* Get hardware address. */
	if (ifrow->dwPhysAddrLen == ETH_ADDR_LEN) {
		entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
		entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
		memcpy(&entry->intf_link_addr.addr_eth, ifrow->bPhysAddr,
		    ETH_ADDR_LEN);
	}
	/* Get addresses. */
	ap = entry->intf_alias_addrs;
	lap = ap + ((entry->intf_len - sizeof(*entry)) /
	    sizeof(entry->intf_alias_addrs[0]));
	for (i = 0; i < (int)intf->iptable->dwNumEntries; i++) {
		if (intf->iptable->table[i].dwIndex == ifrow->dwIndex &&
		    intf->iptable->table[i].dwAddr != 0) {
			if (entry->intf_addr.addr_type == ADDR_TYPE_NONE) {
				/* Set primary address if unset. */
				entry->intf_addr.addr_type = ADDR_TYPE_IP;
				entry->intf_addr.addr_ip =
				    intf->iptable->table[i].dwAddr;
				addr_mtob(&intf->iptable->table[i].dwMask,
				    IP_ADDR_LEN, &entry->intf_addr.addr_bits);
			} else if (ap < lap) {
				/* Set aliases. */
				ap->addr_type = ADDR_TYPE_IP;
				ap->addr_ip = intf->iptable->table[i].dwAddr;
				addr_mtob(&intf->iptable->table[i].dwMask,
				    IP_ADDR_LEN, &ap->addr_bits);
				ap++, entry->intf_alias_num++;
			}
		}
	}
	entry->intf_len = (u_char *)ap - (u_char *)entry;
}

static int
_refresh_tables(intf_t *intf)
{
	MIB_IFROW *ifrow;
	ULONG len;
	u_int i, ret;

	/* Get interface table. */
	for (len = sizeof(intf->iftable[0]); ; ) {
		if (intf->iftable)
			free(intf->iftable);
		intf->iftable = malloc(len);
		ret = GetIfTable(intf->iftable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}
	/* Get IP address table. */
	for (len = sizeof(intf->iptable[0]); ; ) {
		if (intf->iptable)
			free(intf->iptable);
		intf->iptable = malloc(len);
		ret = GetIpAddrTable(intf->iptable, &len, FALSE);
		if (ret == NO_ERROR)
			break;
		else if (ret != ERROR_INSUFFICIENT_BUFFER)
			return (-1);
	}
	return (0);
}

static DWORD
_find_ifindex(intf_t *intf, const char *device)
{
	char *p = (char *)device;
	int n;
	
	while (isalpha((int) (unsigned char) *p)) p++;
	n = atoi(p);

	return (DWORD)n;
}

intf_t *
intf_open(void)
{
	return (calloc(1, sizeof(intf_t)));
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	MIB_IFROW ifrow;
	
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	ifrow.dwIndex = _find_ifindex(intf, entry->intf_name);
	
	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (-1);

	_ifrow_to_entry(intf, &ifrow, entry);
	
	return (0);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	MIB_IFROW ifrow;
	MIB_IPADDRROW *iprow;
	int i;

	if (src->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	for (i = 0; i < (int)intf->iptable->dwNumEntries; i++) {
		iprow = &intf->iptable->table[i];
		if (iprow->dwAddr == src->addr_ip) {
			ifrow.dwIndex = iprow->dwIndex;
			if (GetIfEntry(&ifrow) != NO_ERROR)
				return (-1);
			_ifrow_to_entry(intf, &ifrow, entry);
			return (0);
		}
	}
	errno = ENXIO;
	return (-1);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	MIB_IFROW ifrow;
	
	if (dst->addr_type != ADDR_TYPE_IP) {
		errno = EINVAL;
		return (-1);
	}
	if (GetBestInterface(dst->addr_ip, &ifrow.dwIndex) != NO_ERROR)
		return (-1);

	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (-1);
	
	if (_refresh_tables(intf) < 0)
		return (-1);
	
	_ifrow_to_entry(intf, &ifrow, entry);
	
	return (0);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	/*
	 * XXX - could set interface up/down via SetIfEntry(),
	 * but what about the rest of the configuration? :-(
	 * {Add,Delete}IPAddress for 2000/XP only
	 */
#if 0
	/* Set interface address. XXX - 2000/XP only? */
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
		ULONG ctx = 0, inst = 0;
		UINT ip, mask;

		memcpy(&ip, &entry->intf_addr.addr_ip, IP_ADDR_LEN);
		addr_btom(entry->intf_addr.addr_bits, &mask, IP_ADDR_LEN);
		
		if (AddIPAddress(ip, mask,
			_find_ifindex(intf, entry->intf_name),
			&ctx, &inst) != NO_ERROR) {
			return (-1);
		}
		return (0);
	}
#endif
	errno = ENOSYS;
	SetLastError(ERROR_NOT_SUPPORTED);
	return (-1);
}

int
intf_loop(intf_t *intf, intf_handler callback, void *arg)
{
	struct intf_entry *entry;
	u_char ebuf[1024];
	int i, ret = 0;

	if (_refresh_tables(intf) < 0)
		return (-1);
	
	entry = (struct intf_entry *)ebuf;
	
	for (i = 0; i < (int)intf->iftable->dwNumEntries; i++) {
		entry->intf_len = sizeof(ebuf);
		_ifrow_to_entry(intf, &intf->iftable->table[i], entry);
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}
	return (ret);
}

intf_t *
intf_close(intf_t *intf)
{
	if (intf != NULL) {
		if (intf->iftable)
			free(intf->iftable);
		if (intf->iptable)
			free(intf->iptable);
		free(intf);
	}
	return (NULL);
}

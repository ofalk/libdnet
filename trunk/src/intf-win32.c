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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

/* XXX - wonky */
#define ETHIDXSZ	 24
#define LOOPIDXSZ	 8
#define IFTABLESZ	 4096
#define IPTABLESZ	 1024

struct intf_handle {
	DWORD		 eth_idx[ETHIDXSZ];
	int		 eth_cnt;
	DWORD		 loop_idx[LOOPIDXSZ];
	int		 loop_cnt;
	MIB_IFTABLE	*iftable;
	MIB_IPADDRTABLE	*iptable;
};

intf_t *
intf_open(void)
{
	intf_t *intf;

	if ((intf = calloc(1, sizeof(*intf) + IFTABLESZ + IPTABLESZ)) != NULL){
		intf->iftable = (MIB_IFTABLE *)((u_char *)intf +
		    sizeof(*intf));
		intf->iptable = (MIB_IPADDRTABLE *)((u_char *)intf->iftable +
		    IFTABLESZ);
	}
	return (intf);
}

static int
_match_intf_name(const struct intf_entry *entry, void *arg)
{
	struct intf_entry *e = (struct intf_entry *)arg;
	
	if (strcmp(e->intf_name, entry->intf_name) == 0) {
		/* XXX - truncated result if entry is too small. */
		memcpy(e, entry, e->intf_len);
		return (1);
	}
	return (0);
}

int
intf_get(intf_t *intf, struct intf_entry *entry)
{
	if (intf_loop(intf, _match_intf_name, entry) != 1) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	}
	return (0);
}

static int
_match_intf_src(const struct intf_entry *entry, void *arg)
{
	struct intf_entry *save = (struct intf_entry *)arg;
	
	if (entry->intf_addr.addr_type == ADDR_TYPE_IP &&
	    entry->intf_addr.addr_ip == save->intf_addr.addr_ip) {
		/* XXX - truncated result if entry is too small. */
		memcpy(save, entry, save->intf_len);
		return (1);
	}
	return (0);
}

int
intf_get_src(intf_t *intf, struct intf_entry *entry, struct addr *src)
{
	memcpy(&entry->intf_addr, src, sizeof(*src));
	
	if (intf_loop(intf, _match_intf_src, entry) != 1) {
		errno = ENXIO;
		return (-1);
	}
	return (0);
}

static void
_ifrow_to_entry(intf_t *intf, MIB_IFROW *ifrow, struct intf_entry *entry)
{
	struct addr *ap;
	int i;
	
	memset(entry, 0, sizeof(*entry));

	/* XXX - dwType matches MIB-II ifType. */
	if (ifrow->dwType == MIB_IF_TYPE_ETHERNET) {
		for (i = 0; i < intf->eth_cnt; i++) {
			if (intf->eth_idx[i] == ifrow->dwIndex)
				break;
		}
		sprintf(entry->intf_name, "eth%d", i);
		entry->intf_type = ifrow->dwType;
	} else if (ifrow->dwType == MIB_IF_TYPE_LOOPBACK) {
		for (i = 0; i < intf->loop_cnt; i++) {
			if (intf->loop_idx[i] == ifrow->dwIndex)
				break;
		}
		sprintf(entry->intf_name, "lo%d", i);
		entry->intf_type = ifrow->dwType;
	} else {
		/* XXX */
		sprintf(entry->intf_name, "nic%lu", ifrow->dwIndex);
		entry->intf_type = INTF_TYPE_OTHER;
	}
	/* Get interface flags. */
	entry->intf_flags = 0;
	
	if (ifrow->dwAdminStatus == MIB_IF_ADMIN_STATUS_UP)
		entry->intf_flags |= INTF_FLAG_UP;
	if (ifrow->dwType == MIB_IF_TYPE_LOOPBACK)
		entry->intf_flags |= INTF_FLAG_LOOPBACK;
	else
		entry->intf_flags |= INTF_FLAG_MULTICAST;
	
	/* Get interface MTU. */
	entry->intf_mtu = ifrow->dwMtu;
	
	/* Get hardware address. */
	if (ifrow->dwType == MIB_IF_TYPE_ETHERNET &&
	    ifrow->dwPhysAddrLen == ETH_ADDR_LEN) {
		entry->intf_link_addr.addr_type = ADDR_TYPE_ETH;
		entry->intf_link_addr.addr_bits = ETH_ADDR_BITS;
		memcpy(&entry->intf_link_addr.addr_eth, ifrow->bPhysAddr,
		    ETH_ADDR_LEN);
	}
	/* Get addresses. */
	ap = entry->intf_alias_addrs;
	for (i = 0; i < intf->iptable->dwNumEntries; i++) {
		if (intf->iptable->table[i].dwIndex == ifrow->dwIndex) {
			if (entry->intf_addr.addr_type != ADDR_TYPE_IP) {
				entry->intf_addr.addr_type = ADDR_TYPE_IP;
				entry->intf_addr.addr_ip =
				    intf->iptable->table[i].dwAddr;
				addr_mtob(&intf->iptable->table[i].dwMask,
				    IP_ADDR_LEN, &entry->intf_addr.addr_bits);
			} else {
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
	ULONG len;
	int i;
	
        len = IFTABLESZ;
	if (GetIfTable(intf->iftable, &len, FALSE) != NO_ERROR)
		return (-1);

	/* Map "unfriendly" win32 interface indices to ours. */
	intf->eth_cnt = intf->loop_cnt = 0;
	
	for (i = 0; i < intf->iftable->dwNumEntries; i++) {
		if (intf->iftable->table[i].dwType == MIB_IF_TYPE_ETHERNET &&
		    intf->eth_cnt < ETHIDXSZ) {
			intf->eth_idx[intf->eth_cnt++] =
			    intf->iftable->table[i].dwIndex;
		} else if (intf->iftable->table[i].dwType ==
		    MIB_IF_TYPE_LOOPBACK && intf->loop_cnt < LOOPIDXSZ) {
			intf->loop_idx[intf->loop_cnt++] =
			    intf->iftable->table[i].dwIndex;
		} else
			return (-1);
	}
	len = IPTABLESZ;
	if (GetIpAddrTable(intf->iptable, &len, FALSE) != NO_ERROR)
		return (-1);
	
	return (0);
}

int
intf_get_dst(intf_t *intf, struct intf_entry *entry, struct addr *dst)
{
	MIB_IFROW ifrow;
	
	if (dst->addr_type != ADDR_TYPE_IP) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
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

const char *
intf_get_desc(intf_t *intf, const char *name)
{
	static char desc[MAXLEN_IFDESCR + 1];
	MIB_IFROW ifrow;
	u_int i;

	if (_refresh_tables(intf) < 0)
		return (NULL);
	
	if (strncmp(name, "eth", 3) == 0 &&
	    (i = atoi(name + 3)) < ETHIDXSZ) {
		ifrow.dwIndex = intf->eth_idx[i];
	} else if (strncmp(name, "lo", 2) == 0 &&
	    (i = atoi(name + 2)) < LOOPIDXSZ) {
		ifrow.dwIndex = intf->loop_idx[i];
	} else
		return (NULL);

	if (GetIfEntry(&ifrow) != NO_ERROR)
		return (NULL);

	strlcpy(desc, ifrow.bDescr, sizeof(desc));
	
	return (desc);
}

int
intf_set(intf_t *intf, const struct intf_entry *entry)
{
	/*
	 * XXX - could set interface down via SetIfEntry(),
	 * but what about the rest of the configuration? :-(
	 * {Add,Delete}IPAddress for 2000/XP only
	 */
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
	
	for (i = 0; i < intf->iftable->dwNumEntries; i++) {
		_ifrow_to_entry(intf, &intf->iftable->table[i], entry);
		
		if ((ret = (*callback)(entry, arg)) != 0)
			break;
	}
	return (ret);
}

intf_t *
intf_close(intf_t *intf)
{
	free(intf);
	return (NULL);
}

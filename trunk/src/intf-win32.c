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
	const char		*device;
	struct intf_info	*info;
};

intf_t *
intf_open(void)
{
	return ((intf_t *)calloc(1, sizeof(intf_t)));
}

static int
_intf_get(const char *device, const struct intf_info *info, void *arg)
{
	intf_t *intf = (intf_t *)arg;

	if (strcmp(device, intf->device) == 0) {
		memcpy(intf->info, info, sizeof(*info));
		return (1);
	}
	return (0);
}

int
intf_get(intf_t *intf, const char *device, struct intf_info *info)
{
	int ret;

	intf->device = device;
	intf->info = info;

	ret = intf_loop(intf, _intf_get, intf);

	if (ret == 0) {
		errno = ENXIO;
		SetLastError(ERROR_NO_DATA);
		return (-1);
	} else if (ret == 1)
		return (0);
	
	return (ret);
}

int
intf_set(intf_t *intf, const char *device, const struct intf_info *info)
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
	struct intf_info info;
	u_char ifbuf[2048], ipbuf[1024];
	int i, j, ret;

	iftable = (MIB_IFTABLE *)ifbuf;
	len = sizeof(ifbuf);

	if (GetIfTable(iftable, &len, FALSE) != NO_ERROR)
		return (-1);

	iptable = (MIB_IPADDRTABLE *)ipbuf;
	len = sizeof(ipbuf);

	if (GetIpAddrTable(iptable, &len, FALSE) != NO_ERROR)
		return (-1);
	
	for (i = 0; i < iftable->dwNumEntries; i++) {
		for (j = 0; j < iptable->dwNumEntries; j++) {
			if (iptable->table[i].dwIndex == 
			    iftable->table[i].dwIndex)
				break;
		}
		info.intf_info = INTF_INFO_FLAGS|INTF_INFO_MTU;

		info.intf_flags = 0;
		if (iftable->table[i].dwAdminStatus == MIB_IF_ADMIN_STATUS_UP)
			info.intf_flags |= INTF_FLAG_UP;
		if (iftable->table[i].dwType == MIB_IF_TYPE_LOOPBACK)
			info.intf_flags |= INTF_FLAG_LOOPBACK;
		else
			info.intf_flags |= INTF_FLAG_MULTICAST;

		info.intf_mtu = iftable->table[i].dwMtu;

		if (j != iptable->dwNumEntries) {
			info.intf_addr.addr_type = ADDR_TYPE_IP;
			info.intf_addr.addr_ip = iptable->table[j].dwAddr;
			addr_mtob(&iptable->table[j].dwMask, IP_ADDR_LEN,
			    &info.intf_addr.addr_bits);
			info.intf_info |= INTF_INFO_ADDR;
		}
		if ((ret = (*callback)(iftable->table[i].bDescr,
		    &info, arg)) != 0)
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

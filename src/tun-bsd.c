/*
 * tun-bsd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct tun {
	int               fd;
	intf_t           *intf;
	struct intf_entry save;
};

#define MAX_DEVS	16	/* XXX - max number of tunnel devices */

tun_t *
tun_open(struct addr *src, struct addr *dst, int mtu)
{
	struct intf_entry ifent;
	tun_t *tun;
	char dev[128];
	int i;

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		return (NULL);

	if ((tun->intf = intf_open()) == NULL)
		return (tun_close(tun));

	memset(&ifent, 0, sizeof(ifent));
	ifent.intf_len = sizeof(ifent);
	
	for (i = 0; i < MAX_DEVS; i++) {
		snprintf(dev, sizeof(dev), "/dev/tun%d", i);
		strlcpy(ifent.intf_name, dev + 5, sizeof(ifent.intf_name));
		tun->save = ifent;
		
		if ((tun->fd = open(dev, O_RDWR, 0)) != -1 &&
		    intf_get(tun->intf, &tun->save) == 0) {
			ifent.intf_flags = INTF_FLAG_UP|INTF_FLAG_POINTOPOINT;
			ifent.intf_addr = *src;
			ifent.intf_dst_addr = *dst;	
			ifent.intf_mtu = mtu;
			
			if (intf_set(tun->intf, &ifent) < 0)
				tun = tun_close(tun);
			break;
		}
	}
	if (i == MAX_DEVS)
		tun = tun_close(tun);
	return (tun);
}

const char *
tun_name(tun_t *tun)
{
	return (tun->save.intf_name);
}

int
tun_fileno(tun_t *tun)
{
	return (tun->fd);
}

size_t
tun_send(tun_t *tun, const void *buf, size_t size)
{
	return (write(tun->fd, buf, size));
}

size_t
tun_recv(tun_t *tun, void *buf, size_t size)
{
	return (read(tun->fd, buf, size));
}

tun_t *
tun_close(tun_t *tun)
{
	if (tun->fd > 0)
		close(tun->fd);
	if (tun->intf != NULL) {
		intf_set(tun->intf, &tun->save);
		intf_close(tun->intf);
	}
	free(tun);
	return (NULL);
}

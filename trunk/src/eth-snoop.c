/*
 * eth-snoop.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/raw.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnet.h"

struct eth_handle {
	int	fd;
	char	device[16];
};

int	eth_get_hwaddr(eth_t *e, struct addr *ha);

eth_t *
eth_open(char *device)
{
	struct sockaddr_raw sr;
	eth_t *e;
	int n;
	
	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);

	if ((e->fd = socket(PF_RAW, SOCK_RAW, RAWPROTO_SNOOP)) < 0) {
		free(e);
		return (NULL);
	}
	memset(&sr, 0, sizeof(sr));
	sr.sr_family = AF_RAW;
	strlcpy(sr.sr_ifname, device, sizeof(sr.sr_ifname));

	if (bind(e->fd, (struct sockaddr *)&sr, sizeof(sr)) < 0) {
		eth_close(e);
		return (NULL);
	}
	n = 60000;
	if (setsockopt(e->fd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0) {
		eth_close(e);
		return (NULL);
	}
	strlcpy(e->device, device, sizeof(e->device));
	
	return (e);
}

int
eth_get_hwaddr(eth_t *e, struct addr *ha)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, e->device, sizeof(ifr.ifr_name));

	if (ioctl(e->fd, SIOCGIFADDR, &ifr) < 0)
		return (-1);

	if (addr_ston(&ifr.ifr_addr, ha) < 0)
		return (-1);

	if (ha->addr_type != ADDR_TYPE_ETH)
		return (-1);

	return (0);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	return (write(e->fd, buf, len));
}

int
eth_close(eth_t *e)
{
	if (e == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(e->fd) < 0)
		return (-1);
	
	free(e);
	return (0);
}

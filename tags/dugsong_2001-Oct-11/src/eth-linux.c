/*
 * eth-linux.c
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
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif /* __GLIBC__ */
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int			fd;
	struct sockaddr_ll	sll;
};

eth_t *
eth_open(char *device)
{
	struct ifreq ifr;
	eth_t *e;
	int n;
	
	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);
	
	if ((e->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		free(e);
		return (NULL);
	}
#ifdef SO_BROADCAST
	n = 1;
	if (setsockopt(e->fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) < 0) {
		eth_close(e);
		return (NULL);
	}
#endif
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	
	if (ioctl(e->fd, SIOCGIFINDEX, &ifr) < 0) {
		eth_close(e);
		return (NULL);
	}
	e->sll.sll_family = AF_PACKET;
	e->sll.sll_ifindex = ifr.ifr_ifindex;
	
	return (e);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	struct eth_hdr *eth = (struct eth_hdr *)buf;
	
	e->sll.sll_protocol = eth->eth_type;

	return (sendto(e->fd, buf, len, 0, (struct sockaddr *)&e->sll,
	    sizeof(e->sll)));
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

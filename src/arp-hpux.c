/*
 * arp-hpux.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if_arp.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct arp_handle {
	int	 fd;
};

arp_t *
arp_open(void)
{
	arp_t *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);

	if ((a->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		free(a);
		return (NULL);
	}
	return (a);
}

int
arp_add(arp_t *a, struct addr *pa, struct addr *ha)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));

	if (addr_ntos(pa, &ar.arp_pa) < 0 ||
	    addr_ntos(ha, &ar.arp_ha) < 0)
		return (-1);
	
	ar.arp_flags = ATF_PERM | ATF_COM;
	
	if (ioctl(a->fd, SIOCSARP, &ar) < 0)
		return (-1);

	return (0);
}

int
arp_delete(arp_t *a, struct addr *pa)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(pa, &ar.arp_pa) < 0)
		return (-1);
	
	if (ioctl(a->fd, SIOCDARP, &ar) < 0)
		return (-1);
	
	return (0);
}

int
arp_get(arp_t *a, struct addr *pa, struct addr *ha)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(pa, &ar.arp_pa) < 0)
		return (-1);
	
	if (ioctl(a->fd, SIOCGARP, &ar) < 0)
		return (-1);
	
	if ((ar.arp_flags & ATF_COM) == 0) {
		errno = ESRCH;
		return (-1);
	}
	if (addr_ston(&ar.arp_ha, ha) < 0)
		return (-1);
	
	return (0);
}	

int
arp_loop(arp_t *a, arp_handler callback, void *arg)
{
	errno = EOPNOTSUPP;
	return (-1);
}

int
arp_close(arp_t *a)
{
	if (a == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(a->fd) < 0)
		return (-1);

	return (0);
}

/*
 * arp-linux.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if_arp.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

#define PROC_ARP_FILE	"/proc/net/arp"

struct arp_handle {
	intf_t	*intf;
	int	 fd;
};

arp_t *
arp_open(void)
{
	arp_t *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);

	if ((a->intf = intf_open()) == NULL) {
		free(a);
		return (NULL);
	}
	if ((a->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		arp_close(a);
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

	strlcpy(ar.arp_dev, "eth0", sizeof(ar.arp_dev));	/* XXX */
	
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

	strlcpy(ar.arp_dev, "eth0", sizeof(ar.arp_dev));	/* XXX */
	
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
	FILE *fp;
	struct addr pa, ha;
	char buf[BUFSIZ], ipbuf[100], macbuf[100], maskbuf[100], devbuf[100];
	int i, type, flags, ret;

	if ((fp = fopen(PROC_ARP_FILE, "r")) == NULL)
		return (-1);

	ret = 0;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		i = sscanf(buf, "%s 0x%x 0x%x %100s %100s %100s\n",
		    ipbuf, &type, &flags, macbuf, maskbuf, devbuf);
		
		if (i < 4 || (flags & ATF_COM) == 0)
			continue;
		
		if (addr_aton(ipbuf, &pa) == 0 &&
		    addr_aton(macbuf, &ha) == 0) {
			if ((ret = callback(&pa, &ha, arg)) != 0)
				break;
		}
	}
	if (ferror(fp)) {
		fclose(fp);
		return (-1);
	}
	fclose(fp);
	
	return (ret);
}

int
arp_close(arp_t *a)
{
	if (a == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (intf_close(a->intf) < 0 || close(a->fd) < 0)
		return (-1);

	return (0);
}

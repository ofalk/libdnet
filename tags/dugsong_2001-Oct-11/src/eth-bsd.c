/*
 * eth-bsd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/bpf.h>
#include <net/if.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int	fd;
};

eth_t *
eth_open(char *device)
{
	struct ifreq ifr;
	char file[32];
	eth_t *e;
	int i, fd = -1;

	for (i = 0; i < 32; i++) {
		snprintf(file, sizeof(file), "/dev/bpf%d", i);
		fd = open(file, O_WRONLY);
		if (fd != -1 || errno != EBUSY)
			break;
	}
	if (fd < 0)
		return (NULL);
	
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	
	if (ioctl(fd, BIOCSETIF, (char *)&ifr) < 0) {
		close(fd);
		return (NULL);
	}
#ifdef BIOCSHDRCMPLT
	i = 1;
	if (ioctl(fd, BIOCSHDRCMPLT, &i) < 0) {
		close(fd);
		return (NULL);
	}
#endif
	if ((e = malloc(sizeof(*e))) == NULL) {
		close(fd);
		return (NULL);
	}
	e->fd = fd;
	
	return (e);
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

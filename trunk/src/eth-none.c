/*
 * eth-none.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "dnet.h"

eth_t *
eth_open(char *device)
{
	errno = ENOSYS;
	return (NULL);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
	errno = ENOSYS;
	return (-1);
}

int
eth_close(eth_t *e)
{
	errno = ENOSYS;
	return (-1);
}

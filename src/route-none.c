/*
 * route-none.c
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

route_t *
route_open(void)
{
	errno = ENOSYS;
	return (NULL);
}

int
route_add(route_t *r, const struct addr *dst, const struct addr *gw)
{
	errno = ENOSYS;
	return (-1);
}

int
route_delete(route_t *r, const struct addr *dst)
{
	errno = ENOSYS;
	return (-1);
}

int
route_get(route_t *r, const struct addr *dst, struct addr *gw)
{
	errno = ENOSYS;
	return (-1);
}

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	errno = ENOSYS;
	return (-1);
}

int
route_close(route_t *r)
{
	errno = ENOSYS;
	return (-1);
}

/*
 * route.c
 *
 * Kernel route table operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_ROUTE_H
#define DNET_ROUTE_H

#ifdef __cplusplus
extern "C" {
#endif
	
typedef struct route_handle route_t;

typedef int (*route_handler)(struct addr *dst, struct addr *gw, void *arg);

route_t	*route_open(void);
int	 route_add(route_t *r, struct addr *dst, struct addr *gw);
int	 route_delete(route_t *r, struct addr *dst);
int	 route_get(route_t *r, struct addr *dst, struct addr *gw);
int	 route_loop(route_t *r, route_handler callback, void *arg);
int	 route_close(route_t *r);

#ifdef __cplusplus
}
#endif

#endif /* DNET_ROUTE_H */

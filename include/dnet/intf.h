/*
 * intf.c
 *
 * Network interface operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_INTF_H
#define DNET_INTF_H

#ifdef __cplusplus
extern "C" {
#endif
	
#define INTF_FLAG_UP		0x01	/* interface is up */
#define INTF_FLAG_LOOPBACK	0x02	/* is a loopback net (r/o) */
#define INTF_FLAG_POINTOPOINT	0x04	/* point-to-point link (r/o) */
#define INTF_FLAG_NOARP		0x08	/* no address resolution protocol */
#define INTF_FLAG_MULTICAST	0x10	/* supports multicast (r/o) */

typedef struct intf_handle intf_t;

typedef int (*intf_handler)(char *device, struct addr *addr,
			int flags, void *arg);

intf_t	*intf_open(void);
#ifdef notyet
/* XXX - need to figure out interface aliases on !BSD */
int	 intf_add(intf_t *i, char *device, struct addr *addr);
int	 intf_delete(intf_t *i, char *device, struct addr *addr);
#endif
int	 intf_set(intf_t *i, char *device, struct addr *addr, int *flags);
int	 intf_get(intf_t *i, char *device, struct addr *addr, int *flags);
int	 intf_loop(intf_t *i, intf_handler callback, void *arg); 
int	 intf_close(intf_t *i);

#ifdef __cplusplus
}
#endif

#endif /* DNET_INTF_H */

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

/*
 * Interface information
 */
#define INTF_INFO_ADDR	0x01		/* intf_addr is set */
#define INTF_INFO_FLAGS	0x02		/* intf_flags is set */
#define INTF_INFO_MTU	0x04		/* intf_mtu is set */

struct intf_info {
	uint32_t	intf_info;	/* bitmask of fields set */
	struct addr	intf_addr;	/* interface IP address */
	uint32_t	intf_flags;	/* interface flags */
	uint32_t	intf_mtu;	/* interface MTU */
};

#define INTF_FLAG_UP		0x01	/* enable interface */
#define INTF_FLAG_LOOPBACK	0x02	/* is a loopback net (r/o) */
#define INTF_FLAG_POINTOPOINT	0x04	/* point-to-point link (r/o) */
#define INTF_FLAG_NOARP		0x08	/* disable ARP */
#define INTF_FLAG_MULTICAST	0x10	/* supports multicast (r/o) */

typedef struct intf_handle intf_t;

typedef int (*intf_handler)(const char *device,
	    const struct intf_info *info, void *arg);

__BEGIN_DECLS
intf_t	*intf_open(void);
int	 intf_get(intf_t *i, const char *device, struct intf_info *info);
int	 intf_set(intf_t *i, const char *device, const struct intf_info *info);
int	 intf_loop(intf_t *i, intf_handler callback, void *arg);
intf_t	*intf_close(intf_t *i);
__END_DECLS

#endif /* DNET_INTF_H */

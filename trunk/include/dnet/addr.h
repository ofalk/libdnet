/*
 * addr.h
 *
 * Network address operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_ADDR_H
#define DNET_ADDR_H

#define	ADDR_TYPE_ETH		1	/* Ethernet */
#define	ADDR_TYPE_IP		2	/* Internet Protocol v4 */

struct addr {
	uint16_t		addr_type;
	uint16_t		addr_bits;
	union {
		eth_addr_t	__eth;
		ip_addr_t	__ip;
		
		uint8_t		__data8[20];
		uint16_t	__data16[10];
		uint32_t	__data32[5];
	} __addr_u;
};
#define addr_eth	__addr_u.__eth
#define addr_ip		__addr_u.__ip
#define addr_data8	__addr_u.__data8
#define addr_data16	__addr_u.__data16
#define addr_data32	__addr_u.__data32

__BEGIN_DECLS
int	 addr_cmp(struct addr *a, struct addr *b);
int	 addr_bcast(struct addr *a, struct addr *b);

int	 addr_ntop(struct addr *src, char *dst, size_t size);
int	 addr_pton(char *src, struct addr *dst);

char	*addr_ntoa(struct addr *a);
#define	 addr_aton	addr_pton

int	 addr_ntos(struct addr *a, struct sockaddr *sa);
int	 addr_ston(struct sockaddr *sa, struct addr *a);

int	 addr_btos(uint16_t bits, struct sockaddr *sa);
int	 addr_stob(struct sockaddr *sa, uint16_t *bits);

int	 addr_btom(uint16_t bits, void *mask, size_t size);
int	 addr_mtob(void *mask, size_t size, uint16_t *bits);

#define addr_fill(addr, type, bits, data, len) do {	\
	(addr)->addr_type = type;			\
	(addr)->addr_bits = bits;			\
	memmove((addr)->addr_data8, (char *)data, len);	\
} while (0)
__END_DECLS

#endif /* DNET_ADDR_H */
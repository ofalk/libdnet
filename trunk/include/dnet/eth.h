/*
 * eth.h
 *
 * Ethernet.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_ETH_H
#define DNET_ETH_H

#define ETH_ADDR_LEN	6
#define ETH_ADDR_BITS	48
#define ETH_TYPE_LEN	2
#define ETH_CRC_LEN	4
#define ETH_HDR_LEN	14

#define ETH_LEN_MIN	64		/* minimum frame length with CRC */
#define ETH_LEN_MAX	1518		/* maximum frame length with CRC */

#define ETH_MTU		(ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
#define ETH_MIN		(ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

typedef struct eth_addr {
	u_char		data[ETH_ADDR_LEN];
} eth_addr_t;

struct eth_hdr {
	eth_addr_t	eth_dst;	/* destination address */
	eth_addr_t	eth_src;	/* source address */
	u_short		eth_type;	/* payload type */
};

/*
 * Ethernet payload types
 */
#define ETH_TYPE_PUP	0x0200		/* PUP protocol */
#define ETH_TYPE_IP	0x0800		/* IP protocol */
#define ETH_TYPE_ARP	0x0806		/* address resolution protocol */
#define ETH_TYPE_REVARP	0x8035		/* reverse addr resolution protocol */
#define ETH_TYPE_8021Q	0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETH_TYPE_IPV6	0x86DD		/* IPv6 protocol */
#define ETH_TYPE_PPPOEDISC	0x8863	/* PPP Over Ethernet Discovery Stage */
#define ETH_TYPE_PPPOE	0x8864		/* PPP Over Ethernet Session Stage */
#define ETH_TYPE_LOOPBACK	0x9000	/* used to test interfaces */

#define ETH_IS_MULTICAST(ea)	(*(ea) & 0x01) /* is address mcast/bcast? */

#define ETH_ADDR_BROADCAST	"\xff\xff\xff\xff\xff\xff"

typedef struct eth_handle eth_t;

eth_t	*eth_open(char *device);
ssize_t	 eth_send(eth_t *e, const void *buf, size_t len);
int	 eth_close(eth_t *e);

#define eth_fill(h, dst, src, type) do {			\
	struct eth_hdr *eth_fill_p = (struct eth_hdr *)(h);	\
	memcpy(&eth_fill_p->eth_dst, &(dst), ETH_ADDR_LEN);	\
	memcpy(&eth_fill_p->eth_src, &(src), ETH_ADDR_LEN);	\
	eth_fill_p->eth_type = htons(type);			\
} while (0)

#endif /* DNET_ETH_H */

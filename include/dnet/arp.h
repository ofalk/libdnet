/*
 * arp.h
 * 
 * Address Resolution Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_ARP_H
#define DNET_ARP_H

/*
 * See RFC 826 for protocol description. ARP packets are variable in
 * size; the arp_hdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */

#define ARP_HDR_LEN	8
#define ARP_ETHIP_LEN	20

struct arp_hdr {
	u_short		ar_hrd;	/* format of hardware address */
	u_short		ar_pro;	/* format of protocol address */
	u_char		ar_hln;	/* length of hardware address (ETH_ADDR_LEN) */
	u_char		ar_pln;	/* length of protocol address (IP_ADDR_LEN) */
	u_short		ar_op;	/* operation */
};

/* Hardware address format */
#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */
#define ARP_HRD_FRELAY 	0x000F	/* frame relay hardware */

/* Protocol address format */
#define ARP_PRO_IP	0x0800	/* IP protocol */

/* ARP operation */
#define	ARP_OP_REQUEST	1	/* request to resolve address */
#define	ARP_OP_REPLY	2	/* response to previous request */
#define	ARP_OP_REVREQUEST 3	/* request protocol address given hardware */
#define	ARP_OP_REVREPLY	4	/* response giving protocol address */
#define	ARP_OP_INVREQUEST 8 	/* request to identify peer */
#define	ARP_OP_INVREPLY	9	/* response identifying peer */

struct arp_ethip {
	u_char		ar_sha[ETH_ADDR_LEN];	/* sender hardware address */
	u_char		ar_spa[IP_ADDR_LEN];	/* sender protocol address */
	u_char		ar_tha[ETH_ADDR_LEN];	/* target hardware address */
	u_char		ar_tpa[IP_ADDR_LEN];	/* target protocol address */
};

typedef struct arp_handle arp_t;

typedef int (*arp_handler)(struct addr *pa, struct addr *ha, void *arg);

arp_t	*arp_open(void);
int	 arp_add(arp_t *a, struct addr *pa, struct addr *ha);
int	 arp_delete(arp_t *a, struct addr *pa);
int	 arp_get(arp_t *a, struct addr *pa, struct addr *ha);
int	 arp_loop(arp_t *a, arp_handler callback, void *arg);
int	 arp_close(arp_t *a);

#define arp_ethip_fill(h, op, sha, spa, tha, tpa) do {		\
	struct arp_hdr *fill_arp_p = (struct arp_hdr *)(h);	\
	struct arp_ethip *fill_ethip_p =			\
		(struct arp_ethip *)((char *)(h) + ARP_HDR_LEN);\
	fill_arp_p->ar_hrd = htons(ARP_HRD_ETH);		\
	fill_arp_p->ar_pro = htons(ARP_PRO_IP);			\
	fill_arp_p->ar_hln = ETH_ADDR_LEN;			\
	fill_arp_p->ar_pln = IP_ADDR_LEN;			\
	fill_arp_p->ar_op = htons(op);				\
	memcpy(fill_ethip_p->ar_sha, &(sha), ETH_ADDR_LEN);	\
	memcpy(fill_ethip_p->ar_spa, &(spa), IP_ADDR_LEN);	\
	memcpy(fill_ethip_p->ar_tha, &(tha), ETH_ADDR_LEN);	\
	memcpy(fill_ethip_p->ar_tpa, &(tpa), IP_ADDR_LEN);	\
} while (0)

#endif /* DNET_ARP_H */

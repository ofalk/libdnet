/*
 * ip.h
 *
 * Internet Protocol (RFC 791).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_IP_H
#define DNET_IP_H

#define IP_ADDR_LEN	4
#define IP_ADDR_BITS	32

#define IP_HDR_LEN	20
#define IP_OPT_LEN	2
#define IP_OPT_LEN_MAX	40
#define IP_HDR_LEN_MAX	(IP_HDR_LEN + IP_OPT_LEN_MAX)

#define IP_LEN_MAX	65535
#define IP_LEN_MIN	IP_HDR_LEN

typedef uint32_t	ip_addr_t;

/*
 * IP header
 */
struct ip_hdr {
#if DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		ip_hl:4,	/* header length */
			ip_v:4;		/* version */
#elif DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		ip_v:4,		/* version */
			ip_hl:4;	/* header length */
#endif
	uint8_t		ip_tos;		/* type of service */
	uint16_t	ip_len;		/* total length (including header) */
	uint16_t	ip_id;		/* identification */
	uint16_t	ip_off;		/* fragment offset and flags */
	uint8_t		ip_ttl;		/* time to live */
	uint8_t		ip_p;		/* protocol */
	uint16_t	ip_sum;		/* checksum */
	ip_addr_t	ip_src;		/* source address */
	ip_addr_t	ip_dst;		/* destination address */
};

/*
 * Fragmentation flags
 */
#define IP_RF		0x8000		/* reserved fragment flag */
#define IP_DF		0x4000		/* dont fragment flag */
#define IP_MF		0x2000		/* more fragments flag */
#define IP_OFFMASK	0x1fff		/* mask for fragmenting bits */

/*
 * Type of service
 */
#define IP_TOS_LOWDELAY		0x10
#define IP_TOS_THROUGHPUT	0x08
#define IP_TOS_RELIABILITY	0x04
#define IP_TOS_ECT		0x02
#define IP_TOS_CE		0x01

/*
 * IP precedence
 */
#define IP_TOS_PREC_NETCONTROL		0xe0
#define IP_TOS_PREC_INTERNETCONTROL	0xc0
#define IP_TOS_PREC_CRITIC_ECP		0xa0
#define IP_TOS_PREC_FLASHOVERRIDE	0x80
#define IP_TOS_PREC_FLASH		0x60
#define IP_TOS_PREC_IMMEDIATE		0x40
#define IP_TOS_PREC_PRIORITY		0x20
#define IP_TOS_PREC_ROUTINE		0x00

#define IP_TTL_MAX		255

/*
 * Protocols
 */
#define	IP_PROTO_IP		0		/* Dummy for IP */
#define IP_PROTO_HOPOPTS	IP_PROTO_IP	/* IPv6 hop-by-hop options */
#define	IP_PROTO_ICMP		1		/* ICMP */
#define	IP_PROTO_IGMP		2		/* IGMP */
#define	IP_PROTO_IPIP		4		/* IP in IP */
#define	IP_PROTO_TCP		6		/* TCP */
#define	IP_PROTO_EGP		8		/* Exterior gateway protocol */
#define	IP_PROTO_PUP		12		/* PUP */
#define	IP_PROTO_UDP		17		/* UDP */
#define	IP_PROTO_IDP		22		/* XNS IDP */
#define	IP_PROTO_TP		29 		/* SO TP class 4 */
#define IP_PROTO_IPV6		41		/* IPv6 */
#define IP_PROTO_ROUTING	43		/* IPv6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#define IP_PROTO_RSVP		46		/* Reservation protocol */
#define	IP_PROTO_GRE		47		/* GRE encap, RFCs 1701/1702 */
#define	IP_PROTO_ESP		50		/* Encap. security payload */
#define	IP_PROTO_AH		51		/* Authentication header */
#define	IP_PROTO_MOBILE		55		/* IP Mobility, RFC 2004 */
#define IP_PROTO_ICMPV6		58		/* ICMP for IPv6 */
#define IP_PROTO_NONE		59		/* IPv6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IPv6 destination options */
#define	IP_PROTO_EON		80		/* ISO CNLP */
#define IP_PROTO_ETHERIP	97		/* Ethernet in IPv4 */
#define	IP_PROTO_ENCAP		98		/* Encapsulation header */
#define IP_PROTO_PIM		103		/* Protocol indep. multicast */
#define IP_PROTO_IPCOMP		108		/* Compression header proto */
#define	IP_PROTO_RAW		255		/* Raw IP packets */
#define	IP_PROTO_MAX		256

/*
 * Options
 */
#define IP_OPT_COPIED(o)	((o) & 0x80)
#define IP_OPT_CLASS(o)		((o) & 0x60)
#define IP_OPT_NUMBER(o)	((o) & 0x1f)

#define IP_OPT_CONTROL		0x00
#define IP_OPT_RESERVED1	0x20
#define IP_OPT_DEBMEAS		0x40
#define IP_OPT_RESERVED2	0x60

#define IP_OPT_EOL		0		/* end of options */
#define IP_OPT_NOP		1		/* no operation */
#define IP_OPT_RR		7		/* record route */
#define IP_OPT_TS		68		/* timestamp */
#define IP_OPT_SECURITY		130		/* provide s,c,h,tcc */
#define IP_OPT_LSRR		131		/* loose source route */
#define IP_OPT_SATID		136		/* satnet id */
#define IP_OPT_SSRR		137		/* strict source route */

#define IP_OPT_TYPEONLY(type)	((type) == IP_OPT_EOL || (type) == IP_OPT_NOP)

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

struct ip_opt_data_security {
	uint16_t	s;
	uint16_t	c;
	uint16_t	h;
	uint8_t		tcc[3];
} __attribute__((__packed__));

#define IP_OPT_SECUR_UNCLASS	0x0000
#define IP_OPT_SECUR_CONFID	0xf135
#define IP_OPT_SECUR_EFTO	0x789a
#define IP_OPT_SECUR_MMMM	0xbc4d
#define IP_OPT_SECUR_RESTR	0xaf13
#define IP_OPT_SECUR_SECRET	0xd788
#define IP_OPT_SECUR_TOPSECRET	0x6bc5

struct ip_opt_data_route {
	uint8_t		ptr;		/* from start of option, >= 4 */
	uint32_t	iplist __flexarr; /* list of IP addresses */
} __attribute__((__packed__));

struct ip_opt_data_ts {
	uint8_t		ptr;		/* from start of option, >= 5 */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		oflw:4,
			flg:4;
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		flg:4,
			oflw:4;
#endif
	uint32_t	ipts __flexarr;	/* IP address [ / timestamp] pairs */
} __attribute__((__packed__));

#define IP_OPT_TS_TSONLY	0	/* timestamps only */
#define IP_OPT_TS_TSADDR	1	/* IP address / timestamp pairs */
#define IP_OPT_TS_PRESPEC	3	/* IP address / zero timestamp pairs */

struct ip_opt {
	uint8_t		opt_type;
	uint8_t		opt_len;	/* length of entire option */
	union ip_opt_data {
		struct ip_opt_data_security	security;
		struct ip_opt_data_route	route;
		struct ip_opt_data_ts		timestamp;
		uint16_t			satid;
		uint8_t				data8[IP_OPT_LEN_MAX - IP_OPT_LEN];
	} opt_data;
} __attribute__((__packed__));

#ifndef __GNUC__
#pragma pack()
#endif

/*
 * Classful addressing
 */
#define	IP_CLASSA(i)		(((uint32_t)(i) & htonl(0x80000000)) == \
				 htonl(0x00000000))
#define	IP_CLASSA_NET		(htonl(0xff000000))
#define	IP_CLASSA_NSHIFT	24
#define	IP_CLASSA_HOST		(htonl(0x00ffffff))
#define	IP_CLASSA_MAX		128

#define	IP_CLASSB(i)		(((uint32_t)(i) & htonl(0xc0000000)) == \
				 htonl(0x80000000))
#define	IP_CLASSB_NET		(htonl(0xffff0000))
#define	IP_CLASSB_NSHIFT	16
#define	IP_CLASSB_HOST		(htonl(0x0000ffff))
#define	IP_CLASSB_MAX		65536

#define	IP_CLASSC(i)		(((uint32_t)(i) & htonl(0xe0000000)) == \
				 htonl(0xc0000000))
#define	IP_CLASSC_NET		(htonl(0xffffff00))
#define	IP_CLASSC_NSHIFT	8
#define	IP_CLASSC_HOST		(htonl(0x000000ff))

#define	IP_CLASSD(i)		(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xe0000000))
/* These ones aren't really net and host fields, but routing needn't know. */
#define	IP_CLASSD_NET		(htonl(0xf0000000))
#define	IP_CLASSD_NSHIFT	28
#define	IP_CLASSD_HOST		(htonl(0x0fffffff))
#define	IP_MULTICAST(i)		IP_CLASSD(i)

#define	IP_EXPERIMENTAL(i)	(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_BADCLASS(i)		(((uint32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_LOCAL_GROUP(i)	(((uint32_t)(i) & htonl(0xffffff00)) == \
				 htonl(0xe0000000))
/*
 * Reserved addresses
 */
#define IP_ADDR_ANY		(htonl(0x00000000))	/* 0.0.0.0 */
#define IP_ADDR_BROADCAST	(htonl(0xffffffff))	/* 255.255.255.255 */
#define IP_ADDR_LOOPBACK	(htonl(0x7f000001))	/* 127.0.0.1 */
#define IP_ADDR_MCAST_ALL	(htonl(0xe0000001))	/* 224.0.0.1 */
#define IP_ADDR_MCAST_LOCAL	(htonl(0xe00000ff))	/* 224.0.0.225 */

typedef struct ip_handle ip_t;

__BEGIN_DECLS
ip_t	*ip_open(void);
size_t	 ip_send(ip_t *i, const void *buf, size_t len);
int	 ip_close(ip_t *i);

char	*ip_ntoa(ip_addr_t *ip);
int	 ip_aton(char *src, ip_addr_t *dst);

size_t	 ip_add_option(void *buf, size_t len,
	    int proto, const void *optbuf, size_t optlen);
void	 ip_checksum(void *buf, size_t len);

int	 ip_cksum_add(const void *buf, size_t len, int cksum);
#define	 ip_cksum_carry(x) \
	    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

#define ip_fill_hdr(hdr, tos, len, id, off, ttl, p, src, dst) do {	\
	struct ip_hdr *ip_fill_p = (struct ip_hdr *)(hdr);		\
	ip_fill_p->ip_v = 4; ip_fill_p->ip_hl = 5;			\
	ip_fill_p->ip_tos = tos; ip_fill_p->ip_len = htons(len);	\
 	ip_fill_p->ip_id = htons(id); ip_fill_p->ip_off = htons(off);	\
	ip_fill_p->ip_ttl = ttl; ip_fill_p->ip_p = p;			\
	ip_fill_p->ip_src = src; ip_fill_p->ip_dst = dst;		\
} while (0)
__END_DECLS

#endif /* DNET_IP_H */

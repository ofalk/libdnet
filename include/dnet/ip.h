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

#ifdef __cplusplus
extern "C" {
#endif

#define IP_ADDR_LEN	4
#define IP_ADDR_BITS	32

#define IP_HDR_LEN	20
#define IP_OPT_LEN	2
#define IP_OPT_LEN_MAX	40
#define IP_HDR_LEN_MAX	(IP_HDR_LEN + IP_OPT_LEN_MAX)

#define IP_LEN_MAX	65535
#define IP_LEN_MIN	IP_HDR_LEN

typedef u_int32_t	ip_addr_t;

/*
 * IP header
 */
struct ip_hdr {
#if DNET_BYTESEX == DNET_LIL_ENDIAN
	u_char		ip_hl:4,	/* header length */
			ip_v:4;		/* version */
#elif DNET_BYTESEX == DNET_BIG_ENDIAN
	u_char		ip_v:4,		/* version */
			ip_hl:4;	/* header length */
#endif
	u_char		ip_tos;		/* type of service */
	u_short		ip_len;		/* total length (including header) */
	u_short		ip_id;		/* identification */
	u_short		ip_off;		/* fragment offset and flags */
	u_char		ip_ttl;		/* time to live */
	u_char		ip_p;		/* protocol */
	u_short		ip_sum;		/* checksum */
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

struct ip_opt_data_security {
	u_short		s;
	u_short		c;
	u_short		h;
	u_char		tcc[3];
	u_char		nop;		/* XXX - pad with NOP for alignment */
};
#define IP_OPT_SECUR_UNCLASS	0x0000
#define IP_OPT_SECUR_CONFID	0xf135
#define IP_OPT_SECUR_EFTO	0x789a
#define IP_OPT_SECUR_MMMM	0xbc4d
#define IP_OPT_SECUR_RESTR	0xaf13
#define IP_OPT_SECUR_SECRET	0xd788
#define IP_OPT_SECUR_TOPSECRET	0x6bc5

struct ip_opt_data_route {
	u_char		ptr;		/* from start of option, >= 4 */
	u_char		iplist[0];	/* list of IP addresses */
};

struct ip_opt_data_ts {
	u_char		ptr;		/* from start of option, >= 5 */
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	u_char		oflw:4,
			flg:4;
#elif DNET_BYTESEX == DNET_LIL_ENDIAN
	u_char		flg:4,
			oflw:4;
#endif
	u_int32_t	ipts[0];	/* IP address [ / timestamp] pairs */
};
#define IP_OPT_TS_TSONLY	0	/* timestamps only */
#define IP_OPT_TS_TSADDR	1	/* IP address / timestamp pairs */
#define IP_OPT_TS_PRESPEC	3	/* IP address / zero timestamp pairs */

struct ip_opt {
	u_char		__opt_void[2];	/* XXX - word-align union */
	u_char		opt_type;
	u_char		opt_len;	/* length of entire option */
	union ip_opt_data {
		struct ip_opt_data_security	security;
		struct ip_opt_data_route	route;
		struct ip_opt_data_ts		timestamp;
		u_short				satid;
		u_char				data8[0];
	} opt_data;
};

/*
 * Classful addressing
 */
#define	IP_CLASSA(i)		(((u_int32_t)(i) & htonl(0x80000000)) == \
				 htonl(0x00000000))
#define	IP_CLASSA_NET		(htonl(0xff000000))
#define	IP_CLASSA_NSHIFT	24
#define	IP_CLASSA_HOST		(htonl(0x00ffffff))
#define	IP_CLASSA_MAX		128

#define	IP_CLASSB(i)		(((u_int32_t)(i) & htonl(0xc0000000)) == \
				 htonl(0x80000000))
#define	IP_CLASSB_NET		(htonl(0xffff0000))
#define	IP_CLASSB_NSHIFT	16
#define	IP_CLASSB_HOST		(htonl(0x0000ffff))
#define	IP_CLASSB_MAX		65536

#define	IP_CLASSC(i)		(((u_int32_t)(i) & htonl(0xe0000000)) == \
				 htonl(0xc0000000))
#define	IP_CLASSC_NET		(htonl(0xffffff00))
#define	IP_CLASSC_NSHIFT	8
#define	IP_CLASSC_HOST		(htonl(0x000000ff))

#define	IP_CLASSD(i)		(((u_int32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xe0000000))
/* These ones aren't really net and host fields, but routing needn't know. */
#define	IP_CLASSD_NET		(htonl(0xf0000000))
#define	IP_CLASSD_NSHIFT	28
#define	IP_CLASSD_HOST		(htonl(0x0fffffff))
#define	IP_MULTICAST(i)		IP_CLASSD(i)

#define	IP_EXPERIMENTAL(i)	(((u_int32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_BADCLASS(i)		(((u_int32_t)(i) & htonl(0xf0000000)) == \
				 htonl(0xf0000000))
#define	IP_LOCAL_GROUP(i)	(((u_int32_t)(i) & htonl(0xffffff00)) == \
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

ip_t	*ip_open(void);
ssize_t	 ip_send(ip_t *i, const void *buf, size_t len);
int	 ip_close(ip_t *i);

size_t	 ip_add_opt(void *buf, size_t len, const void *optbuf, size_t optlen);
void	 ip_checksum(void *buf, size_t len);

int	 ip_cksum_add(void *buf, size_t len, int cksum);
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

#ifdef __cplusplus
}
#endif

#endif /* DNET_IP_H */

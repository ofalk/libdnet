/*
 * tcp.h
 *
 * Transmission Control Protocol (RFC 793).
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_TCP_H
#define DNET_TCP_H

#define TCP_HDR_LEN	20
#define TCP_OPT_LEN	2
#define TCP_OPT_LEN_MAX	44
#define TCP_HDR_LEN_MAX	(TCP_HDR_LEN + TCP_OPT_LEN_MAX)

/*
 * TCP header
 */
struct tcp_hdr {
	u_short		th_sport;	/* source port */
	u_short		th_dport;	/* destination port */
	u_int32_t	th_seq;		/* sequence number */
	u_int32_t	th_ack;		/* acknowledgement number */
#if DNET_BYTESEX == DNET_LIL_ENDIAN
	u_char		th_x2:4,	/* (unused) */
			th_off:4;	/* data offset */
#elif DNET_BYTESEX == DNET_BIG_ENDIAN
	u_char		th_off:4,	/* data offset */
			th_x2:4;	/* (unused) */
#endif
	u_char		th_flags;
	u_short		th_win;		/* window */
	u_short		th_sum;		/* checksum */
	u_short		th_urp;		/* urgent pointer */
};

/*
 * TCP control flags
 */
#define TH_FIN		0x01
#define TH_SYN		0x02
#define TH_RST		0x04
#define TH_PUSH		0x08
#define TH_ACK		0x10
#define TH_URG		0x20
#define TH_ECE		0x40		/* RFC 3168 */
#define TH_CWR		0x80

#define TCP_PORT_MAX	65535
#define TCP_WIN_MAX	65535		/* maximum (unscaled) window */

/*
 * Options
 */

#define TCP_OPT_EOL		0
#define TCP_OPT_NOP		1
#define TCP_OPT_MSS		2
#define TCP_OPT_WSCALE		3
#define TCP_OPT_SACKOK		4
#define TCP_OPT_SACK		5
#define TCP_OPT_CC		11
#define TCP_OPT_CCNEW		12
#define TCP_OPT_CCECHO		13
#define TCP_OPT_MD5		19

#define TCP_OPT_TYPEONLY(type)	\
	((type) == TCP_OPT_EOL || (type) == TCP_OPT_NOP)

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

struct tcp_opt {
	u_char		opt_type;
	u_char		opt_len;		/* length of entire option */
	union tcp_opt_data {
		u_short		mss;
		u_char		wscale[2];	/* XXX - scale + NOP */
		u_short		sack __flexarr;	/* origin / size pairs */
		u_int32_t	cc;
		u_char		md5[16];
		u_char		data8[TCP_OPT_LEN_MAX - TCP_OPT_LEN];
	} opt_data;
} __attribute__((__packed__));

#ifndef __GNUC__
# pragma pack()
#endif

#define tcp_fill_hdr(hdr, sport, dport, seq, ack, flags, win, urp) do {	\
	struct tcp_hdr *tcp_fill_p = (struct tcp_hdr *)(hdr);		\
	tcp_fill_p->th_sport = htons(sport);				\
	tcp_fill_p->th_dport = htons(dport);				\
	tcp_fill_p->th_seq = htonl(seq);				\
	tcp_fill_p->th_ack = htonl(ack);				\
	tcp_fill_p->th_x2 = 0; tcp_fill_p->th_off = 5;			\
	tcp_fill_p->th_flags = flags;					\
	tcp_fill_p->th_win = htons(win);				\
	tcp_fill_p->th_urp = htons(urp);				\
} while (0)

__BEGIN_DECLS
size_t	tcp_add_opt(void *buf, size_t len, const void *optbuf, size_t optlen);
__END_DECLS

#endif /* DNET_TCP_H */

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
#define TCP_OPT_LEN_MAX	40
#define TCP_HDR_LEN_MAX	(TCP_HDR_LEN + TCP_OPT_LEN_MAX)

/*
 * TCP header
 */
struct tcp_hdr {
	uint16_t	th_sport;	/* source port */
	uint16_t	th_dport;	/* destination port */
	uint32_t	th_seq;		/* sequence number */
	uint32_t	th_ack;		/* acknowledgement number */
#if DNET_BYTESEX == DNET_LIL_ENDIAN
	uint8_t		th_x2:4,	/* (unused) */
			th_off:4;	/* data offset */
#elif DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t		th_off:4,	/* data offset */
			th_x2:4;	/* (unused) */
#endif
	uint8_t		th_flags;
	uint16_t	th_win;		/* window */
	uint16_t	th_sum;		/* checksum */
	uint16_t	th_urp;		/* urgent pointer */
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
#define TCP_OPT_WSCALE		3	/* RFC 1072 */
#define TCP_OPT_SACKOK		4	/* RFC 2018 */
#define TCP_OPT_SACK		5	/* RFC 2018 */
#define TCP_OPT_ECHO		6	/* RFC 1072 */
#define TCP_OPT_ECHOREPLY	7	/* RFC 1072 */
#define TCP_OPT_TIMESTAMP	8	/* RFC 1323 */
#define TCP_OPT_CC		11	/* RFC 1644 */
#define TCP_OPT_CCNEW		12	/* RFC 1644 */
#define TCP_OPT_CCECHO		13	/* RFC 1644 */
#define TCP_OPT_MD5		19

#define TCP_OPT_TYPEONLY(type)	\
	((type) == TCP_OPT_EOL || (type) == TCP_OPT_NOP)

#ifndef __GNUC__
# define __attribute__(x)
# pragma pack(1)
#endif

struct tcp_opt {
	uint8_t		opt_type;
	uint8_t		opt_len;		/* length of entire option */
	union tcp_opt_data {
		uint16_t	mss;
		uint8_t		wscale[2];	/* XXX - scale + NOP */
		uint16_t	sack[19];	/* XXX - origin / size pairs */
		uint32_t	cc;
		uint8_t		md5[16];
		uint8_t		data8[TCP_OPT_LEN_MAX - TCP_OPT_LEN];
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

#endif /* DNET_TCP_H */

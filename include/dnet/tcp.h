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

/* TCP flags */
#define TH_FIN		0x01
#define TH_SYN		0x02
#define TH_RST		0x04
#define TH_PUSH		0x08
#define TH_ACK		0x10
#define TH_URG		0x20

#define TCP_PORT_MAX	65535
#define TCP_WIN_MAX	65535		/* maximum (unscaled) window */

#define tcp_fill_hdr(h, sport, dport, seq, ack, flags, win, urp) do {	\
	struct tcp_hdr *tcp_fill_p = (struct tcp_hdr *)(h);		\
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

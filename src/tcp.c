/*
 * tcp.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dnet.h"

size_t
tcp_add_opt(void *buf, size_t len, const void *optbuf, size_t optlen)
{
	struct ip_hdr *ip;
	struct tcp_hdr *tcp;
	struct tcp_opt *opt;
	u_char *p;
	int padlen, datalen;

	ip = (struct ip_hdr *)buf;
	tcp = (struct tcp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
	p = (u_char *)tcp + (tcp->th_off << 2);
	datalen = ntohs(ip->ip_len) - (p - (u_char *)buf);
	
	if ((padlen = 4 - (optlen % 4)) == 4)
		padlen = 0;

	assert(ntohs(ip->ip_len) + optlen + padlen < len);
	assert((tcp->th_off << 2) + optlen + padlen < TCP_HDR_LEN_MAX);
	
	opt = (struct tcp_opt *)optbuf;
	if (TCP_OPT_TYPEONLY(opt->opt_type))
		optlen = 1;
	else
		assert(opt->opt_len == optlen);

	/* XXX - shift any existing TCP data. */
	if (datalen) {
		memmove(p + optlen + padlen, p, datalen);
	}
	memmove(p, &opt->opt_type, optlen);
	p += optlen;
	
	/* XXX - pad with NOPs to word boundary. */
	if (padlen) {
		memset(p, TCP_OPT_NOP, padlen);
		p += padlen;
		optlen += padlen;
	}
	tcp->th_off = (p - (u_char *)tcp) >> 2;
	ip->ip_len = htons(ntohs(ip->ip_len) + optlen);
	
	return (optlen);
}

/*
 * ip-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

char *
ip_ntoa(const ip_addr_t *ip)
{
	struct addr addr;

	addr.addr_type = ADDR_TYPE_IP;
	addr.addr_bits = IP_ADDR_BITS;
	addr.addr_ip = *ip;

	return (addr_ntoa(&addr));
}

int
ip_aton(const char *src, ip_addr_t *ip)
{
	struct addr addr;

	if (addr_aton(src, &addr) < 0)
		return (-1);

	if (addr.addr_type != ADDR_TYPE_IP)
		return (-1);
	
	*ip = addr.addr_ip;
	
	return (0);
}

size_t
ip_add_option(void *buf, size_t len, int proto,
    const void *optbuf, size_t optlen)
{
	struct ip_hdr *ip;
	struct tcp_hdr *tcp = NULL;
	u_char *p;
	int hl, datalen, padlen;
	
	if (proto != IP_PROTO_IP && proto != IP_PROTO_TCP) {
		errno = EINVAL;
		return (-1);
	}
	ip = (struct ip_hdr *)buf;
	hl = ip->ip_hl << 2;
	p = (u_char *)buf + hl;
	
	if (proto == IP_PROTO_TCP) {
		tcp = (struct tcp_hdr *)p;
		hl = tcp->th_off << 2;
		p = (u_char *)tcp + hl;
	}
	datalen = ntohs(ip->ip_len) - (p - (u_char *)buf);
	
	/* Compute padding to next word boundary. */
	if ((padlen = 4 - (optlen % 4)) == 4)
		padlen = 0;

	/* XXX - IP_HDR_LEN_MAX == TCP_HDR_LEN_MAX */
	if (hl + optlen + padlen > IP_HDR_LEN_MAX ||
	    ntohs(ip->ip_len) + optlen + padlen > len) {
		errno = EINVAL;
		return (-1);
	}
	/* XXX - IP_OPT_TYPEONLY() == TCP_OPT_TYPEONLY */
	if (IP_OPT_TYPEONLY(((struct ip_opt *)optbuf)->opt_type))
		optlen = 1;
	
	/* Shift any existing data. */
	if (datalen) {
		memmove(p + optlen + padlen, p, datalen);
	}
	memmove(p, optbuf, optlen);
	p += optlen;
	
	/* XXX - IP_OPT_NOP == TCP_OPT_NOP */
	if (padlen) {
		memset(p, IP_OPT_NOP, padlen);
		p += padlen;
		optlen += padlen;
	}
	if (proto == IP_PROTO_IP)
		ip->ip_hl = (p - (u_char *)ip) >> 2;
	else if (proto == IP_PROTO_TCP)
		tcp->th_off = (p - (u_char *)tcp) >> 2;

	ip->ip_len = htons(ntohs(ip->ip_len) + optlen);
	
	return (optlen);
}

void
ip_checksum(void *buf, size_t len)
{
	struct ip_hdr *ip;
	int hl, sum;

	ip = (struct ip_hdr *)buf;
	hl = ip->ip_hl << 2;
	
	len = ntohs(ip->ip_len) - hl;
	
	ip->ip_sum = 0;
	sum = ip_cksum_add(ip, hl, 0);
	ip->ip_sum = ip_cksum_carry(sum);

	if ((ip->ip_off & IP_OFFMASK) != 0)
		return;
	
	if (ip->ip_p == IP_PROTO_TCP && len >= TCP_HDR_LEN) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)((u_char *)ip + hl);
		
		tcp->th_sum = 0;
		sum = ip_cksum_add(tcp, len, 0) + htons(ip->ip_p + len);
		sum = ip_cksum_add(&ip->ip_src, 8, sum);
		tcp->th_sum = ip_cksum_carry(sum);
	} else if (ip->ip_p == IP_PROTO_UDP && len >= UDP_HDR_LEN) {
		struct udp_hdr *udp = (struct udp_hdr *)((u_char *)ip + hl);

		udp->uh_sum = 0;
		sum = ip_cksum_add(udp, len, 0) + htons(ip->ip_p + len);
		sum = ip_cksum_add(&ip->ip_src, 8, sum);
		udp->uh_sum = ip_cksum_carry(sum);
	} else if ((ip->ip_p == IP_PROTO_ICMP || ip->ip_p == IP_PROTO_IGMP) &&
	    len >= ICMP_HDR_LEN) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)((u_char *)ip + hl);
		
		icmp->icmp_cksum = 0;
		sum = ip_cksum_add(icmp, len, 0);
		icmp->icmp_cksum = ip_cksum_carry(sum);
	}
}

int
ip_cksum_add(const void *buf, size_t len, int cksum)
{
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;
	
	sn = len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}

/*
 * ip.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct ip_handle {
	int	fd;
#ifdef HAVE_RAWIP_COOKED
	eth_t		*eth;
	intf_t		*intf;
	arp_t		*arp;
	route_t		*route;
	struct addr	 ip_src, ip_dst;
	struct addr	 eth_src, eth_dst;
#endif
};

#ifdef HAVE_RAWIP_COOKED
ip_t *
ip_open(void)
{
	ip_t *i;

	if ((i = calloc(1, sizeof(*i))) == NULL)
		return (NULL);
	
	if ((i->fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		free(i);
		return (NULL);
	}
	i->ip_src.addr_type = i->ip_dst.addr_type = ADDR_TYPE_IP;
	i->ip_src.addr_bits = i->ip_dst.addr_bits = IP_ADDR_BITS;
	
	i->eth_src.addr_type = i->eth_dst.addr_type = ADDR_TYPE_ETH;
	i->eth_src.addr_bits = i->eth_dst.addr_bits = ETH_ADDR_BITS;
	
	if ((i->intf = intf_open()) == NULL ||
	    (i->arp = arp_open()) == NULL ||
	    (i->route = route_open()) == NULL) {
		ip_close(i);
		free(i);
		return (NULL);
	}
	return (i);
}
#else /* !HAVE_RAWIP_COOKED */
ip_t *
ip_open(void)
{
	ip_t *i;
	int n, fd, len;

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return (NULL);

	n = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) {
		close(fd);
		return (NULL);
	}
#ifdef SO_SNDBUF
	len = sizeof(n);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) < 0) {
		close(fd);
		return (NULL);
	}
	for (n += 128; n < 1048576; n += 128) {
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0) {
			if (errno == ENOBUFS)
				break;
			close(fd);
			return (NULL);
		}
	}
#endif
#ifdef SO_BROADCAST
	n = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) < 0) {
		close(fd);
		return (NULL);
	}
#endif
	if ((i = malloc(sizeof(*i))) == NULL) {
		close(fd);
		return (NULL);
	}
	i->fd = fd;
	return (i);
}
#endif /* !HAVE_RAWIP_COOKED */

#ifdef HAVE_RAWIP_COOKED
static int
ip_match_intf(char *device, struct intf_info *info, void *arg)
{
	ip_t *i = (ip_t *)arg;
	
	if (info->intf_addr.addr_ip == i->ip_src.addr_ip ||
	    i->ip_src.addr_ip == IP_ADDR_ANY) {
		if (i->eth != NULL)
			eth_close(i->eth);
		if ((i->eth = eth_open(device)) == NULL)
			return (-1);
		if (eth_get(i->eth, &i->eth_src) < 0) {
			eth_close(i->eth);
			i->eth = NULL;
			return (-1);
		}
		return (1);
	}
	return (0);
}

static int
ip_lookup(ip_t *i, ip_addr_t dst)
{
	struct sockaddr_in sin;
	struct addr gw;
	int n;
	
	i->ip_dst.addr_ip = dst;

	addr_ntos(&i->ip_dst, (struct sockaddr *)&sin);
	sin.sin_port = htons(666);

	/* XXX - Force the kernel to ARP for our destination. */
	if (connect(i->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		return (-1);	/* XXX */

	/* Lookup our source address. */
	n = sizeof(sin);
	if (getsockname(i->fd, (struct sockaddr *)&sin, &n) < 0)
		return (-1);	/* XXX */

	addr_ston((struct sockaddr *)&sin, &i->ip_src);
	
	if (intf_loop(i->intf, ip_match_intf, i) != 1) {
		i->ip_src.addr_ip = IP_ADDR_ANY;
		if (intf_loop(i->intf, ip_match_intf, i) != 1)
			return (-1);
	}
	/* Lookup our destination address. */
	if (arp_get(i->arp, &i->ip_dst, &i->eth_dst) == 0)
		return (0);
	
	if (route_get(i->route, &i->ip_dst, &gw) == 0) {
		if (gw.addr_ip != i->ip_src.addr_ip &&
		    arp_get(i->arp, &gw, &i->eth_dst) == 0)
			return (0);
	}
	memcpy(&i->eth_dst.addr_eth, ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
	
	return (0);
}

ssize_t
ip_send(ip_t *i, const void *buf, size_t len)
{
	struct ip_hdr *ip;
	struct eth_hdr *eth;
	u_char frame[ETH_LEN_MAX];
	
	ip = (struct ip_hdr *)buf;
	
	if (ip->ip_dst != i->ip_dst.addr_ip) {
		if (ip_lookup(i, ip->ip_dst) < 0)
			return (-1);
	}
	eth = (struct eth_hdr *)frame;
	memcpy(&eth->eth_src, &i->eth_src.addr_eth, ETH_ADDR_LEN);
	memcpy(&eth->eth_dst, &i->eth_dst.addr_eth, ETH_ADDR_LEN);
	eth->eth_type = htons(ETH_TYPE_IP);

	if (len > ETH_MTU) {
		u_char *p, *start, *end, *ip_data;
		int ip_hl, fraglen;

		ip_hl = ip->ip_hl << 2;
		fraglen = ETH_MTU - ip_hl;
		
		ip = (struct ip_hdr *)(frame + ETH_HDR_LEN);
		memcpy(ip, buf, ip_hl);
		ip_data = (u_char *)ip + ip_hl;

		start = (u_char *)buf + ip_hl;
		end = (u_char *)buf + len;
		
		for (p = start; p < end; ) {
			memcpy(ip_data, p, fraglen);
			
			ip->ip_len = htons(ip_hl + fraglen);
			ip->ip_off = htons(((p + fraglen < end) ? IP_MF : 0) |
			    ((p - start) >> 3));
			
			ip_checksum(ip, ip_hl + fraglen);
			
			if (eth_send(i->eth, frame,
			    ETH_HDR_LEN + ip_hl + fraglen) < 0)
				return (-1);
			
			p += fraglen;
			if (end - p < fraglen)
				fraglen = end - p;
		}
		return (len);
	}
	memcpy(frame + ETH_HDR_LEN, buf, len);
	
	if (eth_send(i->eth, frame, ETH_HDR_LEN + len) != ETH_HDR_LEN + len)
		return (-1);

	return (len);
}
#else /* !HAVE_RAWIP_COOKED */
ssize_t
ip_send(ip_t *i, const void *buf, size_t len)
{
	struct ip_hdr *ip;
	struct sockaddr_in sin;

	ip = (struct ip_hdr *)buf;

	memset(&sin, 0, sizeof(sin));
#ifdef HAVE_SOCKADDR_SA_LEN       
	sin.sin_len = sizeof(sin);
#endif
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip->ip_dst;
	
#ifdef HAVE_RAWIP_HOST_OFFLEN
	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_off = ntohs(ip->ip_off);

	len = sendto(i->fd, buf, len, 0,
	    (struct sockaddr *)&sin, sizeof(sin));
	
	ip->ip_len = htons(ip->ip_len);
	ip->ip_off = htons(ip->ip_off);

	return (len);
#else
	return (sendto(i->fd, buf, len, 0,
	    (struct sockaddr *)&sin, sizeof(sin)));
#endif
}
#endif /* !HAVE_RAWIP_COOKED */

int
ip_close(ip_t *i)
{
	assert(i != NULL);

	if (close(i->fd) < 0)
		return (-1);
#ifdef HAVE_RAWIP_COOKED	
	if (i->intf != NULL)
		intf_close(i->intf);

	if (i->arp != NULL)
		arp_close(i->arp);

	if (i->route != NULL)
		route_close(i->route);
#endif
	free(i);
	return (0);
}

size_t
ip_add_option(void *buf, size_t len,
    int proto, const void *optbuf, size_t optlen)
{
	struct ip_hdr *ip;
	struct tcp_hdr *tcp = NULL;
	u_char *p;
	int hl, datalen, padlen;
	
	if (proto != IP_PROTO_IP && proto != IP_PROTO_TCP) {
		errno = EPROTONOSUPPORT;
		return (-1);
	}
	ip = (struct ip_hdr *)buf;
	hl = ip->ip_hl << 2;
	p = buf + hl;
	
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
	
	assert(hl <= IP_HDR_LEN_MAX);
	assert(ntohs(ip->ip_len) <= len);
	
	len = ntohs(ip->ip_len) - hl;
	
	ip->ip_sum = 0;
	sum = ip_cksum_add(ip, hl, 0);
	ip->ip_sum = ip_cksum_carry(sum);
	
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
ip_cksum_add(void *buf, size_t len, int cksum)
{
	u_short *sp = (u_short *)buf;
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

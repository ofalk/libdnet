/*
 * addr.c
 *
 * Network address operations.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>

#ifdef HAVE_NET_IF_H
# include <sys/socket.h>
# include <net/if.h>
#endif
#ifdef HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#ifdef HAVE_NET_RAW_H
# include <net/raw.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	256
#endif

int
addr_cmp(const struct addr *a, const struct addr *b)
{
	int i, j, k;
	
	if ((i = a->addr_bits - b->addr_bits) != 0)
		return (i);
	
	if ((i = a->addr_type - b->addr_type) != 0)
		return (i);

	j = b->addr_bits / 8;

	for (i = 0; i < j; i++) {
		if ((k = a->addr_data8[i] - b->addr_data8[i]) != 0)
			return (k);
	}
	if ((k = b->addr_bits % 8) == 0)
		return (0);

	k = ~0 << (8 - k);
	i = b->addr_data8[j] & k;
	j = a->addr_data8[j] & k;
	
	return (j - i);
}

int
addr_bcast(const struct addr *a, struct addr *b)
{
	struct addr mask;
	
	if (a->addr_type == ADDR_TYPE_IP) {
		addr_btom(a->addr_bits, &mask.addr_ip, IP_ADDR_LEN);
		b->addr_type = ADDR_TYPE_IP;
		b->addr_bits = IP_ADDR_BITS;
		b->addr_ip = (a->addr_ip & mask.addr_ip) |
		    (~0L & ~mask.addr_ip);
	} else if (a->addr_type == ADDR_TYPE_ETH) {
		b->addr_type = ADDR_TYPE_ETH;
		b->addr_bits = ETH_ADDR_BITS;
		memcpy(&b->addr_eth, ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
	} else {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

char *
addr_ntop(const struct addr *src, char *dst, size_t size)
{
	if (src->addr_type == ADDR_TYPE_IP && size >= 20) {
		if (ip_ntop(&src->addr_ip, dst, size) != NULL) {
			if (src->addr_bits != IP_ADDR_BITS)
				sprintf(dst + strlen(dst), "/%d",
				    src->addr_bits);
			return (dst);
		}
	} else if (src->addr_type == ADDR_TYPE_IP6 && size >= 42) {
		if (ip6_ntop(&src->addr_ip6, dst, size) != NULL) {
			if (src->addr_bits != IP6_ADDR_BITS)
				sprintf(dst + strlen(dst), "/%d",
				    src->addr_bits);
			return (dst);
		}
	} else if (src->addr_type == ADDR_TYPE_ETH && size >= 18) {
		if (src->addr_bits == ETH_ADDR_BITS)
			return (eth_ntop(&src->addr_eth, dst, size));
	}
	errno = EINVAL;
	return (NULL);
}

int
addr_pton(const char *src, struct addr *dst)
{
	struct hostent *hp;
	char *ep, tmp[300];
	long bits = 0;
	int i;
	
	for (i = 0; i < sizeof(tmp) - 1; i++) {
		if (src[i] == '/') {
			tmp[i] = '\0';
			bits = strtol(&src[i + 1], &ep, 10);
			if (ep == src || *ep != '\0' || bits < 0) {
				errno = EINVAL;
				return (-1);
			}
			break;
		} else if ((tmp[i] = src[i]) == '\0')
			break;
	}
	if (ip_pton(tmp, &dst->addr_ip) == 0) {
		dst->addr_type = ADDR_TYPE_IP;
		dst->addr_bits = IP_ADDR_BITS;
	} else if (eth_pton(tmp, &dst->addr_eth) == 0) {
		dst->addr_type = ADDR_TYPE_ETH;
		dst->addr_bits = ETH_ADDR_BITS;
	} else if (ip6_pton(tmp, &dst->addr_ip6) == 0) {
		dst->addr_type = ADDR_TYPE_IP6;
		dst->addr_bits = IP6_ADDR_BITS;
	} else if ((hp = gethostbyname(tmp)) != NULL) {
		memcpy(&dst->addr_ip, hp->h_addr, IP_ADDR_LEN);
		dst->addr_type = ADDR_TYPE_IP;
		dst->addr_bits = IP_ADDR_BITS;
	} else {
		errno = EINVAL;
		return (-1);
	}
	if (bits > 0) {
		if (bits > dst->addr_bits) {
			errno = EINVAL;
			return (-1);
		}
		dst->addr_bits = (uint16_t)bits;
	}
	return (0);
}

char *
addr_ntoa(const struct addr *a)
{
	static char *p, buf[BUFSIZ];
	char *q = NULL;
	
	if (p == NULL || p > buf + sizeof(buf) - 64 /* XXX */)
		p = buf;
	
	if (addr_ntop(a, p, (buf + sizeof(buf)) - p) != NULL) {
		q = p;
		p += strlen(p) + 1;
	}
	return (q);
}

int
addr_ntos(const struct addr *a, struct sockaddr *sa)
{
	switch (a->addr_type) {
	case ADDR_TYPE_ETH:
	{
#ifdef HAVE_NET_IF_DL_H
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

		memset(sa, 0, sizeof(*sa));
#ifdef HAVE_SOCKADDR_SA_LEN
		sdl->sdl_len = sizeof(*sdl);
#endif
		sdl->sdl_family = AF_LINK;
		sdl->sdl_alen = ETH_ADDR_LEN;
		memcpy(LLADDR(sdl), &a->addr_eth, ETH_ADDR_LEN);
#else
		memset(sa, 0, sizeof(*sa));
		sa->sa_family = AF_UNSPEC;
		memcpy(sa->sa_data, &a->addr_eth, ETH_ADDR_LEN);
#endif
		break;
	}
	case ADDR_TYPE_IP:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SOCKADDR_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = a->addr_ip;
		break;
	}
	default:
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_ston(const struct sockaddr *sa, struct addr *a)
{
	memset(a, 0, sizeof(*a));
	
	switch (sa->sa_family) {
#ifdef HAVE_NET_IF_DL_H
	case AF_LINK:
	{
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

		if (sdl->sdl_alen != ETH_ADDR_LEN) {
			errno = EINVAL;
			return (-1);
		}
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, LLADDR(sdl), ETH_ADDR_LEN);
		break;
	}
#endif
	case AF_UNSPEC:
	case ARP_HRD_ETH:	/* XXX- Linux arp(7) */
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, sa->sa_data, ETH_ADDR_LEN);
		break;
		
#ifdef AF_RAW
	case AF_RAW:		/* XXX - IRIX raw(7f) */
		a->addr_type = ADDR_TYPE_ETH;
		a->addr_bits = ETH_ADDR_BITS;
		memcpy(&a->addr_eth, ((struct sockaddr_raw *)sa)->sr_addr,
		    ETH_ADDR_LEN);
		break;
#endif
	case AF_INET:
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		a->addr_type = ADDR_TYPE_IP;
		a->addr_bits = IP_ADDR_BITS;
		a->addr_ip = sin->sin_addr.s_addr;
		break;
	}
	default:
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_btos(uint16_t bits, struct sockaddr *sa)
{
	struct sockaddr_in *sin;
	
	sin = (struct sockaddr_in *)sa;
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	if (addr_btom(bits, &sin->sin_addr.s_addr, IP_ADDR_LEN) < 0)
		return (-1);
#ifdef HAVE_SOCKADDR_SA_LEN
	sin->sin_len = IP_ADDR_LEN + (bits / 8) + (bits % 8);
#endif
	return (0);
}

int
addr_stob(const struct sockaddr *sa, uint16_t *bits)
{
	struct sockaddr_in *sin;
	int i, j, len;
	uint16_t n;
	u_char *p;
	
	sin = (struct sockaddr_in *)sa;
#ifdef HAVE_SOCKADDR_SA_LEN
	if ((len = sa->sa_len - IP_ADDR_LEN) > IP_ADDR_LEN)
#endif
	len = IP_ADDR_LEN;
	
	p = (u_char *)&sin->sin_addr.s_addr;

	for (n = i = 0; i < len; i++, n += 8) {
		if (p[i] != 0xff)
			break;
	}
	if (i != len && p[i]) {
		for (j = 7; j > 0; j--, n++) {
			if ((p[i] & (1 << j)) == 0)
				break;
		}
	}
	*bits = n;
	
	return (0);
}
	
int
addr_btom(uint16_t bits, void *mask, size_t size)
{
	int net, host;
	u_char *p;

	if (size == IP_ADDR_LEN) {
		if (bits > IP_ADDR_BITS) {
			errno = EINVAL;
			return (-1);
		}
		*(uint32_t *)mask = bits ?
		    htonl(~0 << (IP_ADDR_BITS - bits)) : 0;
	} else {
		if (size * 8 < bits) {
			errno = EINVAL;
			return (-1);
		}
		p = (u_char *)mask;
		
		if ((net = bits / 8) > 0)
			memset(p, 0xff, net);
		
		if ((host = bits % 8) > 0) {
			p[net] = 0xff << (8 - host);
			memset(&p[net + 1], 0, size - net - 1);
		} else
			memset(&p[net], 0, size - net);
	}
	return (0);
}

int
addr_mtob(const void *mask, size_t size, uint16_t *bits)
{
	uint16_t n;
	u_char *p;
	int i, j;

	p = (u_char *)mask;
	
	for (n = i = 0; i < size; i++, n += 8) {
		if (p[i] != 0xff)
			break;
	}
	if (i != size && p[i]) {
		for (j = 7; j > 0; j--, n++) {
			if ((p[i] & (1 << j)) == 0)
				break;
		}
	}
	*bits = n;

	return (0);
}

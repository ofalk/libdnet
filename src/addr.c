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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN	256
#endif

static const char *octet2dec[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
	"13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23",
	"24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34",
	"35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45",
	"46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56",
	"57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67",
	"68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78",
	"79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
	"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100",
	"101", "102", "103", "104", "105", "106", "107", "108", "109",
	"110", "111", "112", "113", "114", "115", "116", "117", "118",
	"119", "120", "121", "122", "123", "124", "125", "126", "127",
	"128", "129", "130", "131", "132", "133", "134", "135", "136",
	"137", "138", "139", "140", "141", "142", "143", "144", "145",
	"146", "147", "148", "149", "150", "151", "152", "153", "154",
	"155", "156", "157", "158", "159", "160", "161", "162", "163",
	"164", "165", "166", "167", "168", "169", "170", "171", "172",
	"173", "174", "175", "176", "177", "178", "179", "180", "181",
	"182", "183", "184", "185", "186", "187", "188", "189", "190",
	"191", "192", "193", "194", "195", "196", "197", "198", "199",
	"200", "201", "202", "203", "204", "205", "206", "207", "208",
	"209", "210", "211", "212", "213", "214", "215", "216", "217",
	"218", "219", "220", "221", "222", "223", "224", "225", "226",
	"227", "228", "229", "230", "231", "232", "233", "234", "235",
	"236", "237", "238", "239", "240", "241", "242", "243", "244",
	"245", "246", "247", "248", "249", "250", "251", "252", "253",
	"254", "255"
};

static const char *octet2hex[] = {
	"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a",
	"0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15",
	"16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20",
	"21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b",
	"2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36",
	"37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41",
	"42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c",
	"4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57",
	"58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62",
	"63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d",
	"6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78",
	"79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83",
	"84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e",
	"8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
	"9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4",
	"a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
	"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba",
	"bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5",
	"c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0",
	"d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db",
	"dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6",
	"e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1",
	"f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc",
	"fd", "fe", "ff"
};

int
addr_cmp(const struct addr *a, const struct addr *b)
{
	int i, j, k;
	
	if ((i = b->addr_bits - a->addr_bits) != 0)
		return (i);
	
	if ((i = b->addr_type - a->addr_type) != 0)
		return (i);

	j = a->addr_bits / 8;

	for (i = 0; i < j; i++) {
		if ((k = b->addr_data8[i] - a->addr_data8[i]) != 0)
			return (k);
	}
	if ((k = a->addr_bits % 8) == 0)
		return (0);

	k = ~(~0 << (8 - k));
	i = a->addr_data8[j] & k;
	j = b->addr_data8[j] & k;
	
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

int
addr_ntop(const struct addr *src, char *dst, size_t size)
{
	const char *p;
	const u_char *u;
	
	u = src->addr_data8;
	
	if (src->addr_type == ADDR_TYPE_IP && size >= 20) {
		for (p = octet2dec[u[0]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = '.';
		for (p = octet2dec[u[1]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = '.';
		for (p = octet2dec[u[2]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = '.';
		for (p = octet2dec[u[3]]; (*dst = *p++) != '\0'; ) dst++;
		
		if (src->addr_bits < IP_ADDR_BITS) {
			*dst++ = '/';
			p = octet2dec[src->addr_bits];
			while ((*dst = *p++) != '\0')
				dst++;
		}
		return (0);
	} else if (src->addr_type == ADDR_TYPE_ETH && size >= 18) {
		for (p = octet2hex[u[0]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = ':';
		for (p = octet2hex[u[1]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = ':';
		for (p = octet2hex[u[2]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = ':';
		for (p = octet2hex[u[3]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = ':';
		for (p = octet2hex[u[4]]; (*dst = *p++) != '\0'; ) dst++;
		*dst++ = ':';
		for (p = octet2hex[u[5]]; (*dst = *p++) != '\0'; ) dst++;

		return (0);
	}
	errno = EINVAL;
	
	return (-1);
}

int
addr_pton(const char *src, struct addr *dst)
{
	char *p, tmp[MAXHOSTNAMELEN];
	long l;
	int i;
	
	assert(src != NULL);
	
	if (strchr(src, ':') != NULL) {
		dst->addr_type = ADDR_TYPE_ETH;
		dst->addr_bits = ETH_ADDR_BITS;
		
		for (i = 0; i < ETH_ADDR_LEN; i++) {
			l = strtol(src, &p, 16);
			if (p == src || l < 0 || l > 0xff) {
				errno = EINVAL;
				return (-1);
			}
			if (i < 5 && *p != ':') {
				errno = EINVAL;
				return (-1);
			}
			dst->addr_data8[i] = (u_char)l;
			src = p + 1;
		}
		if (*p != '\0') {
			errno = EINVAL;
			return (-1);
		}
	} else {
		dst->addr_type = ADDR_TYPE_IP;
		
		if ((p = strchr(src, '/')) != NULL) {
			if (++p - src > sizeof(tmp)) {
				errno = EINVAL;
				return (-1);
			}
			strlcpy(tmp, src, p - src);
			src = p;
			l = strtol(src, &p, 10);
			if (p == src || l < 0 || l > IP_ADDR_BITS) {
				errno = EINVAL;
				return (-1);
			}
			dst->addr_bits = l;
		} else {
			strlcpy(tmp, src, sizeof(tmp));
			dst->addr_bits = IP_ADDR_BITS;
		}
		if (inet_pton(AF_INET, tmp, &dst->addr_ip) != 1) {
			struct hostent *hp = gethostbyname(tmp);
			
			if (hp == NULL) {
				errno = EINVAL;
				return (-1);
			}
			memcpy(&dst->addr_ip, hp->h_addr, IP_ADDR_LEN);
		}
	}
	return (0);
}

char *
addr_ntoa(const struct addr *a)
{
	static char *p, buf[BUFSIZ];
	char *q;
	
	if (p == NULL || p > buf + sizeof(buf))
		p = buf;
	
	if (addr_ntop(a, p, (buf + sizeof(buf)) - p) < 0)
		return (NULL);

	q = p;
	p += strlen(p) + 1;
	
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
		assert(bits <= IP_ADDR_BITS);
		*(uint32_t *)mask = bits ?
		    htonl(~0 << (IP_ADDR_BITS - bits)) : 0;
	} else {
		assert(size * 8 >= bits);
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

/*
 * ip.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dnet.h"
#include "dnet-int.h"

void
ip_usage(int die)
{
	fprintf(stderr, "Usage: dnet ip [tos|id|off|ttl|proto|src|dst value] "
	    "... [send]\n");
	if (die)
		exit(1);
}

static int
proto_aton(char *string, uint8_t *proto)
{
	struct protoent *pp;
	long l;
	char *p;
	
	if ((pp = getprotobyname(string)) != NULL)
		*proto = pp->p_proto;
	else {
		l = strtol(string, &p, 10);
		if (*string == '\0' || *p != '\0' || l > 0xffff)
			return (-1);
		*proto = l & 0xff;
	}
	return (0);
}

static int
off_aton(char *string, uint16_t *off)
{
	int i;
	char *p;

	if (strncmp(string, "0x", 2) == 0) {
		if (sscanf(string, "%i", &i) != 1 || i > IP_OFFMASK)
			return (-1);
		*off = htons(i);
	} else {
		i = strtol(string, &p, 10);
		if (*string == '\0' || (*p != '\0' && *p != '+') ||
		    i > IP_OFFMASK)
			return (-1);
		*off = htons(((*p == '+') ? IP_MF : 0) | (i >> 3));
	}
	return (0);
}

int
ip_main(int argc, char *argv[])
{
	struct ip_hdr *ip;
	struct addr addr;
	u_char *p, buf[IP_LEN_MAX];	/* XXX */
	char *name, *value;
	int c, len;
	ip_t *i = NULL;

	srand(time(NULL));

	ip = (struct ip_hdr *)buf;
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_tos = 0;
	ip->ip_id = rand() & 0xffff;
	ip->ip_off = 0;
	ip->ip_ttl = IP_TTL_MAX;
	ip->ip_p = IP_PROTO_IP;
	ip->ip_sum = 0;
	ip->ip_src = rand();
	ip->ip_dst = rand();

	for (c = 0; c + 1 < argc; c += 2) {
		name = argv[c];
		value = argv[c + 1];
		
		if (strcmp(name, "tos") == 0)
			ip->ip_tos = atoi(value);
		else if (strcmp(name, "id") == 0)
			ip->ip_id = ntohs(atoi(value));
		else if (strcmp(name, "off") == 0) {
			if (off_aton(value, &ip->ip_off) < 0)
				ip_usage(1);
		} else if (strcmp(name, "ttl") == 0)
			ip->ip_ttl = atoi(value);
		else if (strcmp(name, "proto") == 0) {
			if (proto_aton(value, &ip->ip_p) < 0)
				ip_usage(1);
		} else if (strcmp(name, "src") == 0) {
			if (addr_aton(value, &addr) < 0)
				ip_usage(1);
			ip->ip_src = addr.addr_ip;
		} else if (strcmp(name, "dst") == 0) {
			if (addr_aton(value, &addr) < 0)
				ip_usage(1);
			ip->ip_dst = addr.addr_ip;
		} else
			ip_usage(1);
	}
	argc -= c;
	argv += c;
	
	if (argc == 1) {
		if (strcmp(argv[0], "send") != 0)
			ip_usage(1);
		if ((i = ip_open()) == NULL)
			err(1, "ip_open");
	} else if (argc != 0)
		ip_usage(1);
	
	p = buf + IP_HDR_LEN;
	
	if (!isatty(STDIN_FILENO)) {
		len = sizeof(buf) - (p - buf);
		while ((c = read(STDIN_FILENO, p, len)) > 0) {
			p += c;
			len -= c;
		}
	}
	len = p - buf;

	ip->ip_len = htons(len);

	ip_checksum(buf, len);
	
	if (i != NULL) {
		if (ip_send(i, buf, len) != len)
			err(1, "ip_send");
		
		ip_close(i);
	} else {
		if (write(STDOUT_FILENO, buf, len) != len)
			err(1, "write");
	}
	return (0);
}

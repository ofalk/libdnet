/*
 * arp.c
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
arp_usage(int die)
{
	fprintf(stderr, "Usage: dnet arp [op|sha|spa|tha|tpa value] ...\n");
	if (die)
		exit(1);
}

static int
op_aton(char *string, uint16_t *op)
{
	long l;
	char *p;

	if (strncasecmp(string, "req", 3) == 0)
		*op = htons(ARP_OP_REQUEST);
	else if (strncasecmp(string, "rep", 3) == 0)
		*op = htons(ARP_OP_REPLY);
	else if (strncasecmp(string, "revreq", 6) == 0)
		*op = htons(ARP_OP_REVREQUEST);
	else if (strncasecmp(string, "revrep", 6) == 0)
		*op = htons(ARP_OP_REVREPLY);
	else if (strncasecmp(string, "invreq", 6) == 0)
		*op = htons(ARP_OP_INVREQUEST);
	else if (strncasecmp(string, "invrep", 6) == 0)
		*op = htons(ARP_OP_INVREPLY);
	else {
		l = strtol(string, &p, 10);
		if (*string == '\0' || *p != '\0' || l > 0xffff)
			return (-1);
		*op = htons(l & 0xffff);
	}
	return (0);
}

int
arp_main(int argc, char *argv[])
{
	struct arp_hdr *arp;
	struct arp_ethip *ethip;
	struct addr addr;
	u_char *p, buf[ETH_MTU];	/* XXX */
	char *name, *value;
	int c, len;

	srand(time(NULL));

	arp = (struct arp_hdr *)buf;
	arp->ar_hrd = htons(ARP_HRD_ETH);
	arp->ar_pro = htons(ARP_PRO_IP);
	arp->ar_hln = ETH_ADDR_LEN;
	arp->ar_pln = IP_ADDR_LEN;
	arp->ar_op = ARP_OP_REQUEST;

	ethip = (struct arp_ethip *)(buf + ARP_HDR_LEN);
	memset(ethip, 0, sizeof(*ethip));

	for (c = 0; c + 1 < argc; c += 2) {
		name = argv[c];
		value = argv[c + 1];
		
		if (strcmp(name, "op") == 0) {
			if (op_aton(value, &arp->ar_op) < 0)
				arp_usage(1);
		} else if (strcmp(name, "sha") == 0) {
			if (addr_aton(value, &addr) < 0)
				arp_usage(1);
			memcpy(ethip->ar_sha, &addr.addr_eth, ETH_ADDR_LEN);
		} else if (strcmp(name, "spa") == 0) {			
			if (addr_aton(value, &addr) < 0)
				arp_usage(1);
			memcpy(ethip->ar_spa, &addr.addr_eth, IP_ADDR_LEN);
		} else if (strcmp(name, "tha") == 0) {
			if (addr_aton(value, &addr) < 0)
				arp_usage(1);
			memcpy(ethip->ar_tha, &addr.addr_eth, ETH_ADDR_LEN);
		} else if (strcmp(name, "tpa") == 0) {
			if (addr_aton(value, &addr) < 0)
				arp_usage(1);
			memcpy(ethip->ar_tpa, &addr.addr_eth, IP_ADDR_LEN);
		}
		else
			arp_usage(1);
	}
	argc -= c;
	argv += c;

	if (argc != 0)
		arp_usage(1);

	p = buf + ARP_HDR_LEN + ARP_ETHIP_LEN;
	
	if (!isatty(STDIN_FILENO)) {
		len = sizeof(buf) - (p - buf);
		while ((c = read(STDIN_FILENO, p, len)) > 0) {
			p += c;
			len -= c;
		}
	}
	len = p - buf;
	
	if (write(STDOUT_FILENO, buf, len) != len)
		err(1, "write");

	return (0);
}

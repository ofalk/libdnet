/*
 * eth.c
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
#include <unistd.h>

#include "dnet.h"
#include "dnet-int.h"

void
eth_usage(int die)
{
	fprintf(stderr, "Usage: dnet eth [type|src|dst value] ... "
	    "[send dev]\n");
	if (die)
		exit(1);
}

static int
type_aton(char *string, u_short *type)
{
	long l;
	char *p;

	if (strcmp(string, "ip") == 0)
		*type = htons(ETH_TYPE_IP);
	else if (strcmp(string, "arp") == 0)
		*type = htons(ETH_TYPE_ARP);
	else {
		l = strtol(string, &p, 10);
		if (*string == '\0' || *p != '\0' || l > 0xffff)
			return (-1);
		*type = htons(l & 0xffff);
	}
	return (0);
}

int
eth_main(int argc, char *argv[])
{
	struct eth_hdr *eth;
	struct addr addr;
	u_char *p, buf[ETH_LEN_MAX];	/* XXX */
	char *name, *value;
	int c, len;
	eth_t *e = NULL;

	eth = (struct eth_hdr *)buf;
	memset(eth, 0, sizeof(*eth));
	eth->eth_type = htons(ETH_TYPE_IP);

	for (c = 0; c + 1 < argc; c += 2) {
		name = argv[c];
		value = argv[c + 1];

		if (strcmp(name, "type") == 0) {
			if (type_aton(value, &eth->eth_type) < 0)
				eth_usage(1);
		} else if (strcmp(name, "src") == 0) {
			if (addr_aton(value, &addr) < 0)
				eth_usage(1);
			memcpy(&eth->eth_src, &addr.addr_eth, ETH_ADDR_LEN);
		} else if (strcmp(name, "dst") == 0) {
			if (addr_aton(value, &addr) < 0)
				eth_usage(1);
			memcpy(&eth->eth_dst, &addr.addr_eth, ETH_ADDR_LEN);
		} else if (strcmp(name, "send") == 0) {
			if ((e = eth_open(value)) == NULL)
				err(1, "eth_open");
		} else
			eth_usage(1);
	}
	argc -= c;
	argv += c;

	if (argc != 0)
		eth_usage(1);
	
	p = buf + ETH_HDR_LEN;
	
	if (!isatty(STDIN_FILENO)) {
		len = sizeof(buf) - (p - buf);
		while ((c = read(STDIN_FILENO, p, len)) > 0) {
			p += c;
			len -= c;
		}
	}
	len = p - buf;

	if (e != NULL) {
		if (eth_send(e, buf, len) != len)
			err(1, "eth_send");
		eth_close(e);
	} else {
		if (write(STDOUT_FILENO, buf, len) != len)
			err(1, "write");
	}
	return (0);
}

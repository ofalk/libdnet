/*
 * addr.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

#include "dnet.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: addr address\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr sa;
	struct addr addr;
	u_int32_t mask;
	char buf[128];

	if (argc != 2)
		usage();

	if (addr_pton(argv[1], &addr) < 0)
		err(1, "addr_pton");

	printf("addr_pton: %s -> %s\n", argv[1], addr_ntoa(&addr));

	if (addr_ntop(&addr, buf, sizeof(buf)) < 0)
		err(1, "addr_ntop");

	printf("addr_ntop: %s -> %s\n", addr_ntoa(&addr), buf);

	if (addr_ntos(&addr, &sa) < 0)
		err(1, "addr_ntos");

	if (addr_ston(&sa, &addr) < 0)
		err(1, "addr_ston");

	printf("addr_ntos -> addr_ston: %s\n", addr_ntoa(&addr));
	
	if (addr.addr_type == ADDR_TYPE_IP) {
		if (addr_btom(addr.addr_bits, &mask) < 0)
			err(1, "addr_btom");
		
		printf("addr_btom: %d -> 0x%08x\n",
		    addr.addr_bits, ntohl(mask));
		
		if (addr_mtob(mask, &addr.addr_bits) < 0)
			err(1, "addr_mtob");

		printf("addr_mtob: 0x%08x -> %d\n",
		    ntohl(mask), addr.addr_bits);
	}
	exit(0);
}

/*
 * intf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */
 
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

static intf_t	*intf;

static void
usage(void)
{
	fprintf(stderr, "Usage: intf show\n"
	                "Usage: intf any\n"
			"Usage: intf get device [ip|eth]\n"
			"Usage: intf set device addr "
	    "[[up|down|arp|noarp] ...]\n");
	exit(1);
}

static char *
flags2string(int flags)
{
	static char buf[256];

	buf[0] = '\0';
	
	if (flags & INTF_FLAG_UP)
		strlcat(buf, ",UP", sizeof(buf));
	if (flags & INTF_FLAG_LOOPBACK)
		strlcat(buf, ",LOOP", sizeof(buf));
	if (flags & INTF_FLAG_POINTOPOINT)
		strlcat(buf, ",P2P", sizeof(buf));
	if (flags & INTF_FLAG_NOARP)
		strlcat(buf, ",NOARP", sizeof(buf));
	if (flags & INTF_FLAG_MULTICAST)
		strlcat(buf, ",MCAST", sizeof(buf));
	
	if (buf[0] != '\0')
		return (buf + 1);

	return (buf);
}

static int
print_intf(char *device, struct addr *addr, int flags, void *arg)
{
	printf("%s: flags=%x<%s>\n", device, flags, flags2string(flags));

	if (addr != NULL) {
		if (addr->addr_type == ADDR_TYPE_IP)
			printf("\tinet %s\n", addr_ntoa(addr));
		else if (addr->addr_type == ADDR_TYPE_ETH)
			printf("\teth %s\n", addr_ntoa(addr));
	}
	return (0);
}

static int
lookup_intf(char *device, struct addr *addr, int flags, void *arg)
{
	struct addr ea;
	
	ea.addr_type = ADDR_TYPE_ETH;
	
	if (intf_get(intf, device, &ea, NULL) == 0) {
		print_intf(device, &ea, flags, NULL);
		return (1);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	struct addr addr;
	char *cmd, *device;
	int i, flags;

	if (argc < 2)
		usage();

	cmd = argv[1];

	if ((intf = intf_open()) == NULL)
		err(1, "intf_open");

	if (strcmp(cmd, "show") == 0) {
		if (intf_loop(intf, print_intf, NULL) < 0)
			err(1, "intf_loop");
	} else if (strcmp(cmd, "any") == 0) {
		if (intf_loop(intf, lookup_intf, &device) < 0)
			err(1, "intf_loop");
	} else if (strcmp(cmd, "get") == 0) {
		device = argv[2];
		    
		if (argc > 3) {
			if (strcmp(argv[3], "ip") == 0)
				addr.addr_type = ADDR_TYPE_IP;
			else if (strcmp(argv[3], "eth") == 0)
				addr.addr_type = ADDR_TYPE_ETH;
			else
				usage();
		} else
			addr.addr_type = ADDR_TYPE_IP;
		
		if (intf_get(intf, device, &addr, &flags) < 0) {
			if (errno == EADDRNOTAVAIL)
				print_intf(device, NULL, flags, NULL);
			else
				err(1, "intf_get");
		} else
			print_intf(device, &addr, flags, NULL);
	} else if (strcmp(cmd, "set") == 0) {
		device = argv[2];
		
		if (intf_get(intf, device, NULL, &flags) < 0)
			err(1, "intf_get");

		if (addr_pton(argv[3], &addr) < 0)
			err(1, "addr_pton");

		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "up") == 0)
				flags |= INTF_FLAG_UP;
			else if (strcmp(argv[i], "down") == 0)
				flags &= ~INTF_FLAG_UP;
			else if (strcmp(argv[i], "arp") == 0)
				flags &= ~INTF_FLAG_NOARP;
			else if (strcmp(argv[i], "noarp") == 0)
				flags |= INTF_FLAG_NOARP;
		}
		if (intf_set(intf, device, &addr, &flags) < 0)
			err(1, "intf_set");
	} else
		usage();
	
	intf_close(intf);

	exit(0);
}

/*
 * intf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

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
			"Usage: intf get device\n"
			"Usage: intf set device addr "
	    "[[up|down|arp|noarp] ...]\n");
	exit(1);
}

static char *
flags2string(u_int flags)
{
	static char buf[256];

	buf[0] = '\0';
	
	if (flags & INTF_FLAG_UP)
		strlcat(buf, ",UP", sizeof(buf));
	if (flags & INTF_FLAG_LOOPBACK)
		strlcat(buf, ",LOOP", sizeof(buf));
	if (flags & INTF_FLAG_POINTOPOINT)
		strlcat(buf, ",POINTOPOINT", sizeof(buf));
	if (flags & INTF_FLAG_NOARP)
		strlcat(buf, ",NOARP", sizeof(buf));
	if (flags & INTF_FLAG_BROADCAST)
		strlcat(buf, ",BROADCAST", sizeof(buf));
	if (flags & INTF_FLAG_MULTICAST)
		strlcat(buf, ",MULTICAST", sizeof(buf));
	
	if (buf[0] != '\0')
		return (buf + 1);

	return (buf);
}

static int
print_intf(const char *device, const struct intf_info *info, void *arg)
{
	struct addr bcast;
	uint32_t mask;
	
	printf("%s:", device);
	
	if ((info->intf_info & INTF_INFO_FLAGS) != 0)
		printf(" flags=%x<%s>", info->intf_flags,
		    flags2string(info->intf_flags));

	if ((info->intf_info & INTF_INFO_MTU) != 0)
		printf(" mtu %d", info->intf_mtu);

	printf("\n");

	if ((info->intf_info & INTF_INFO_ADDR) != 0) {
		addr_btom(info->intf_addr.addr_bits, &mask, IP_ADDR_LEN);
		mask = ntohl(mask);
		addr_bcast(&info->intf_addr, &bcast);

		printf("\tinet %s netmask 0x%x broadcast %s\n",
		    addr_ntoa(&info->intf_addr), mask, addr_ntoa(&bcast));
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	struct intf_info info;
	char *cmd, *device;
	int i;

	if (argc < 2)
		usage();

	cmd = argv[1];

	if ((intf = intf_open()) == NULL)
		err(1, "intf_open");

	if (strcmp(cmd, "show") == 0) {
		if (intf_loop(intf, print_intf, NULL) < 0)
			err(1, "intf_loop");
	} else if (strcmp(cmd, "get") == 0) {
		device = argv[2];

		if (intf_get(intf, device, &info) < 0)
			err(1, "intf_get");

		print_intf(device, &info, NULL);
	} else if (strcmp(cmd, "set") == 0) {
		device = argv[2];

		if (intf_get(intf, device, &info) < 0)
			err(1, "intf_get");

		if (addr_pton(argv[3], &info.intf_addr) < 0)
			err(1, "addr_pton");
		
		info.intf_info |= INTF_INFO_ADDR;
		
		for (i = 4; i < argc; i++) {
			if (strcmp(argv[i], "up") == 0)
				info.intf_flags |= INTF_FLAG_UP;
			else if (strcmp(argv[i], "down") == 0)
				info.intf_flags &= ~INTF_FLAG_UP;
			else if (strcmp(argv[i], "arp") == 0)
				info.intf_flags &= ~INTF_FLAG_NOARP;
			else if (strcmp(argv[i], "noarp") == 0)
				info.intf_flags |= INTF_FLAG_NOARP;
		}
		if (intf_set(intf, device, &info) < 0)
			err(1, "intf_set");
	} else
		usage();
	
	intf_close(intf);

	exit(0);
}

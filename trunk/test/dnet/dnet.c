/*
 * dnet.c
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

struct module {
	char	 *name;
	void	(*usage)(int die);
	int	(*main)(int argc, char *argv[]);
};

static struct module dnet_modules[] = {
	{ "addr",	addr_usage,	addr_main },
	{ "hex",	hex_usage,	hex_main },
	{ "eth",	eth_usage,	eth_main },
	{ "arp",	arp_usage,	arp_main },
	{ "ip",		ip_usage,	ip_main },
	{ "icmp",	icmp_usage,	icmp_main },
	{ "tcp",	tcp_usage,	tcp_main },
	{ "udp",	udp_usage,	udp_main },
	{ "send",	send_usage,	send_main },
	{ NULL,		NULL,		NULL }
};

static void
usage(void)
{
	struct module *m;

	for (m = dnet_modules; m->name != NULL; m++)
		m->usage(0);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct module *m;
	
	if (argc < 2)
		usage();

	for (m = dnet_modules; m->name != NULL; m++) {
		if (strcmp(argv[1], m->name) == 0)
			return (m->main(argc - 2, argv + 2));
	}
	usage();
	
	exit(1);
}

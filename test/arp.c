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

#include "dnet.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: arp show\n"
	                "Usage: arp get host\n"
	                "Usage: arp add host mac\n"
			"Usage: arp delete host\n");
	exit(1);
}

static int
print_arp(const struct arp_entry *entry, void *arg)
{
	printf("%s at %s\n", addr_ntoa(&entry->arp_pa),
	    addr_ntoa(&entry->arp_ha));
	return (0);
}

int
main(int argc, char *argv[])
{
	struct arp_entry entry;
	arp_t *arp;
	char *cmd;

	if (argc < 2)
		usage();

	cmd = argv[1];

	if ((arp = arp_open()) == NULL)
		err(1, "arp_open");
	
	if (strcmp(cmd, "show") == 0) {
		if (arp_loop(arp, print_arp, NULL) < 0)
			err(1, "arp_loop");
	} else if (strcmp(cmd, "get") == 0) {
		if (addr_pton(argv[2], &entry.arp_pa) < 0)
			err(1, "addr_pton");
		if (arp_get(arp, &entry) < 0)
			err(1, "arp_get");
		print_arp(&entry, NULL);
	} else if (strcmp(cmd, "add") == 0) {
		if (addr_pton(argv[2], &entry.arp_pa) < 0 ||
		    addr_pton(argv[3], &entry.arp_ha) < 0)
			err(1, "addr_pton");
		if (arp_add(arp, &entry) < 0)
			err(1, "arp_add");
		printf("%s added\n", addr_ntoa(&entry.arp_pa));
	} else if (strcmp(cmd, "delete") == 0) {
		if (addr_pton(argv[2], &entry.arp_pa) < 0)
			err(1, "addr_pton");
		if (arp_delete(arp, &entry) < 0)
			err(1, "arp_delete");
		printf("%s deleted\n", addr_ntoa(&entry.arp_pa));
	} else
		usage();

	arp_close(arp);

	exit(0);
}

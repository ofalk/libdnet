/*
 * route.c
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

#include <dnet.h>

static void
usage(void)
{
	fprintf(stderr, "Usage: route show\n"
	                "Usage: route get dst\n"
	                "Usage: route add dst gw\n"
	                "Usage: route delete dst\n"
	                "Usage: route flush\n");
	exit(1);
}

static int
print_route(struct addr *dst, struct addr *gw, void *arg)
{
	printf("%-20s %-20s\n", addr_ntoa(dst), addr_ntoa(gw));
	return (0);
}

static int
delete_route(struct addr *dst, struct addr *gw, void *arg)
{
	route_t *r = (route_t *)arg;

	if (route_delete(r, dst) < 0)
		return (-1);

	return (print_route(dst, gw, NULL));
}

int
main(int argc, char *argv[])
{
	struct addr dst, gw;
	route_t *r;
	char *cmd;

	if (argc < 2)
		usage();

	cmd = argv[1];
	
	if ((r = route_open()) == NULL)
		err(1, "route_open");

	if (strcmp(cmd, "show") == 0) {
		printf("%-20s %-20s\n", "Destination", "Gateway");
		
		if (route_loop(r, print_route, NULL) < 0)
			err(1, "route_loop");
	} else if (strcmp(cmd, "get") == 0) {
		if (addr_aton(argv[2], &dst) < 0)
			err(1, "addr_aton");
		
		if (route_get(r, &dst, &gw) < 0)
			err(1, "route_get");

		printf("get %s %s: gateway %s\n",
		    (dst.addr_bits < IP_ADDR_BITS) ? "net" : "host",
		    addr_ntoa(&dst), addr_ntoa(&gw));
	} else if (strcmp(cmd, "add") == 0) {
		if (addr_aton(argv[2], &dst) < 0 ||
		    addr_aton(argv[3], &gw) < 0)
			err(1, "addr_aton");
		
		if (route_add(r, &dst, &gw) < 0)
			err(1, "route_add");
		
		printf("add %s %s: gateway %s\n",
		    (dst.addr_bits < IP_ADDR_BITS) ? "net" : "host",
		    addr_ntoa(&dst), addr_ntoa(&gw));
	} else if (strcmp(cmd, "delete") == 0) {
		if (addr_aton(argv[2], &dst) < 0)
			err(1, "addr_aton");

		if (route_delete(r, &dst) < 0)
			err(1, "route_delete");

		printf("delete %s %s\n",
		    (dst.addr_bits < IP_ADDR_BITS) ? "net" : "host",
		    addr_ntoa(&dst));
	} else if (strcmp(cmd, "flush") == 0) {
		if (route_loop(r, delete_route, r) < 0)
			err(1, "route_loop");
	} else
		usage();

	route_close(r);
	
	exit(0);
}

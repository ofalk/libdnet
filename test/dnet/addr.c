/*
 * addr.c
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
addr_usage(int die)
{
	fprintf(stderr, "Usage: dnet addr <value> ...\n");
	if (die)
		exit(1);
}

int
addr_main(int argc, char *argv[])
{
	struct addr addr;
	int c, len;
	
	if (argc == 0)
		addr_usage(1);
	
	for (c = 0; c < argc; c++) {
		if (addr_aton(argv[c], &addr) < 0)
			addr_usage(1);
		
		len = addr.addr_bits / 8;
		
		if (write(STDOUT_FILENO, addr.addr_data8, len) != len)
			err(1, "write");
	}
	return (0);
}

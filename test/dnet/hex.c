/*
 * hex.c
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
hex_usage(int die)
{
	fprintf(stderr, "Usage: dnet hex <value> ...\n");
	if (die)
		exit(1);
}

int
hex_main(int argc, char *argv[])
{
	int c, len;
	
	if (argc == 0)
		hex_usage(1);
	
	for (c = 0; c < argc; c++) {
		if ((len = fmt_aton(argv[c], argv[c])) < 0)
			hex_usage(1);
		
		if (write(STDOUT_FILENO, argv[c], len) != len)
			err(1, "write");
	}
	return (0);
}

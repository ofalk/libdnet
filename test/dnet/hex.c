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
#include "aton.h"
#include "mod.h"

void
hex_usage(void)
{
	fprintf(stderr, "Usage: dnet hex <string> ...\n");
	exit(1);
}

int
hex_main(int argc, char *argv[])
{
	int c, len;
	
	if (argc == 1 || *(argv[1]) == '-')
		hex_usage();
	
	for (c = 1; c < argc; c++) {
		if ((len = fmt_aton(argv[c], (u_char *)argv[c])) < 0)
			hex_usage();
		
		if (write(STDOUT_FILENO, argv[c], len) != len)
			err(1, "write");
	}
	return (0);
}

struct mod mod_hex = {
	"hex",
	MOD_TYPE_DATA,
	hex_main
};

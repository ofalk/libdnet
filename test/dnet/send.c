/*
 * send.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
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
send_usage(int die)
{
	fprintf(stderr, "Usage: dnet send [<device>]\n");
	if (die)
		exit(1);
}

int
send_main(int argc, char *argv[])
{
	eth_t *eth;
	ip_t *ip;
	u_char *p, buf[IP_LEN_MAX];	/* XXX */
	int c, len;

	if (isatty(STDIN_FILENO))
		err(1, "cannot read packet to send from tty");

	p = buf;
	len = sizeof(buf) - (p - buf);
	
	while ((c = read(STDIN_FILENO, p, len)) > 0) {
		p += c;
		len -= c;
	}
	len = p - buf;
	
	if (argc == 0) {
		if ((ip = ip_open()) == NULL)
			err(1, "ip_open");
		if (ip_send(ip, buf, len) != len)
			err(1, "ip_send");
		ip_close(ip);
	} else if (argc == 1) {
		if ((eth = eth_open(argv[0])) == NULL)
			err(1, "eth_open");
		if (eth_send(eth, buf, len) != len)
			err(1, "eth_send");
		eth_close(eth);
	} else
		send_usage(1);
	
	exit(0);
}

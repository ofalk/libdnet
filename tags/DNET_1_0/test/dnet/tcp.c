/*
 * tcp.c
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
tcp_usage(int die)
{
	fprintf(stderr, "Usage: dnet tcp [sport|dport|flags|seq|ack|win|urp value] ...\n");
	if (die)
		exit(1);
}

static int
port_aton(char *string, uint16_t *port)
{
	struct servent *sp;
	long l;
	char *p;
	
	if ((sp = getservbyname(string, "tcp")) != NULL) {
		*port = sp->s_port;
	} else {
		l = strtol(string, &p, 10);
		if (*string == '\0' || *p != '\0' || l > 0xffff)
			return (-1);
		*port = htons(l & 0xffff);
	}
	return (0);
}

static int
seq_aton(char *string, uint32_t *seq)
{
	char *p;
	
	*seq = strtol(string, &p, 10);
	if (*string == '\0' || *p != '\0')
		return (-1);

	return (0);
}

static int
flags_aton(char *string, uint8_t *flags)
{
	char *p;

	*flags = 0;
	
	for (p = string; *p != '\0'; p++) {
		switch (*p) {
		case 'S':
			*flags |= TH_SYN;
			break;
		case 'A':
			*flags |= TH_ACK;
			break;
		case 'F':
			*flags |= TH_FIN;
			break;
		case 'R':
			*flags |= TH_RST;
			break;
		case 'P':
			*flags |= TH_PUSH;
			break;
		case 'U':
			*flags |= TH_URG;
			break;
		default:
			return (-1);
		}
	}
	return (0);
}

int
tcp_main(int argc, char *argv[])
{
	struct tcp_hdr *tcp;
	u_char *p, buf[IP_LEN_MAX];	/* XXX */
	char *name, *value;
	int c, len;
	
	srand(time(NULL));
	
	tcp = (struct tcp_hdr *)buf;
	
	memset(tcp, 0, sizeof(*tcp));
	tcp->th_sport = rand() & 0xffff;
	tcp->th_dport = rand() & 0xffff;
	tcp->th_seq = rand();
	tcp->th_ack = 0;
	tcp->th_off = 5;
	tcp->th_flags = TH_SYN;
	tcp->th_win = TCP_WIN_MAX;
	tcp->th_urp = 0;

	for (c = 0; c + 1 < argc; c += 2) {
		name = argv[c];
		value = argv[c + 1];
		
		if (strcmp(name, "sport") == 0) {
			if (port_aton(value, &tcp->th_sport) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "dport") == 0) {
			if (port_aton(value, &tcp->th_dport) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "flags") == 0) {
			if (flags_aton(value, &tcp->th_flags) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "seq") == 0) {
			if (seq_aton(value, &tcp->th_seq) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "ack") == 0) {
			if (seq_aton(value, &tcp->th_ack) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "win") == 0) {
			if (port_aton(value, &tcp->th_win) < 0)
				tcp_usage(1);
		} else if (strcmp(name, "urp") == 0) {
			if (port_aton(value, &tcp->th_urp) < 0)
				tcp_usage(1);
		} else
			tcp_usage(1);
	}
	argc -= c;
	argv += c;
	
	if (argc != 0)
		tcp_usage(1);

	p = buf + TCP_HDR_LEN;
	
	if (!isatty(STDIN_FILENO)) {
		len = sizeof(buf) - (p - buf);
		while ((c = read(STDIN_FILENO, p, len)) > 0) {
			p += c;
			len -= c;
		}
	}
	len = p - buf;
	
	if (write(STDOUT_FILENO, buf, len) != len)
		err(1, "write");

	return (0);
}

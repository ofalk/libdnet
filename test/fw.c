/*
 * fw.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnet.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: fw show\n"
	    "Usage: fw add|delete allow|block in|out device|any "
	    "proto src[:sport[-max]] dst[:dport[-max]] [type/code]\n"
	    "Usage: fw flush\n");
	exit(1);
}

static int
print_rule(struct fw_rule *fr, void *arg)
{
	struct protoent *pr;
	char proto[16], sport[16], dport[16], typecode[16];

	if ((pr = getprotobynumber(fr->proto)) == NULL)
		snprintf(proto, sizeof(proto), "%d", fr->proto);
	else
		strlcpy(proto, pr->p_name, sizeof(proto));

	sport[0] = dport[0] = typecode[0] = '\0';
	
	switch (fr->proto) {
	case IP_PROTO_ICMP:
		if (fr->sport[1] && fr->dport[1])
			snprintf(typecode, sizeof(typecode), " %d/%d",
			    fr->sport[0], fr->dport[0]);
		else if (fr->sport[1])
			snprintf(typecode, sizeof(typecode), " %d",
			    fr->sport[0]);
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		if (fr->sport[0] == fr->sport[1])
			snprintf(sport, sizeof(sport), ":%d",
			    fr->sport[0]);
		else
			snprintf(sport, sizeof(sport), ":%d-%d",
			    fr->sport[0], fr->sport[1]);
		
		if (fr->dport[0] == fr->dport[1])
			snprintf(dport, sizeof(dport), ":%d",
			    fr->dport[0]);
		else
			snprintf(dport, sizeof(dport), ":%d-%d",
			    fr->dport[0], fr->dport[1]);
		break;
	}
	printf("%s %s %s %s %s%s %s%s%s\n",
	    fr->op == FW_OP_ALLOW ? "allow" : "block",
	    fr->direction == FW_DIR_IN ? "in" : "out",
	    *fr->device ? fr->device : "any", proto,
	    addr_ntoa(&fr->src), sport, addr_ntoa(&fr->dst), dport, typecode);

	return (0);
}

static int
delete_rule(struct fw_rule *fr, void *arg)
{
	fw_t *fw = (fw_t *)arg;

	if (fw_delete(fw, fr) < 0)
		return (-1);

	printf("- ");
	
	return (print_rule(fr, NULL));
}
	
static int
arg_to_fr(int argc, char *argv[], struct fw_rule *fr)
{
	struct protoent *pr;
	char *p;

	if (argc < 6) {
		errno = EINVAL;
		return (-1);
	}
	memset(fr, 0, sizeof(*fr));

	fr->op = strcmp(argv[0], "allow") ? FW_OP_BLOCK : FW_OP_ALLOW;
	
	fr->direction = strcmp(argv[1], "in") ? FW_DIR_OUT : FW_DIR_IN;

	if (strcmp(argv[2], "any") != 0)
		strlcpy(fr->device, argv[2], sizeof(fr->device));
	
	if ((pr = getprotobyname(argv[3])) != NULL)
		fr->proto = pr->p_proto;
	else
		fr->proto = atoi(argv[3]);

	p = strtok(argv[4], ":");
	
	if (addr_aton(p, &fr->src) < 0)
		return (-1);

	if ((p = strtok(NULL, ":")) != NULL) {
		fr->sport[0] = (u_short)strtol(p, &p, 10);
		if (*p == '-')
			fr->sport[1] = (u_short)strtol(p + 1, NULL, 10);
		else
			fr->sport[1] = fr->sport[0];
	}
	p = strtok(argv[5], ":");
	
	if (addr_aton(p, &fr->dst) < 0)
		return (-1);

	if ((p = strtok(NULL, ":")) != NULL) {
		fr->dport[0] = (u_short)strtol(p, &p, 10);
		if (*p == '-')
			fr->dport[1] = (u_short)strtol(p + 1, NULL, 10);
		else
			fr->dport[1] = fr->dport[0];
	}
	if (argc > 6) {
		if (fr->proto != IP_PROTO_ICMP && fr->proto != IP_PROTO_IGMP) {
			errno = EINVAL;
			return (-1);
		}
		fr->sport[0] = (u_short)strtol(argv[6], &p, 10);
		fr->sport[1] = 0xff;
		if (*p != '/') {
			errno = EINVAL;
			return (-1);
		}
		fr->dport[0] = (u_short)strtol(p + 1, NULL, 10);
		fr->dport[1] = 0xff;
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	struct fw_rule fr;
	fw_t *fw;
	
	if (argc < 2)
		usage();

	if ((fw = fw_open()) == NULL)
		err(1, "fw_open");
	
	if (strcmp(argv[1], "show") == 0) {
		if (fw_loop(fw, print_rule, NULL) < 0)
			err(1, "fw_loop");
	} else if (strcmp(argv[1], "add") == 0) {
		if (arg_to_fr(argc - 2, argv + 2, &fr) < 0)
			err(1, "arg_to_fr");
		printf("+ ");
		print_rule(&fr, NULL);
		if (fw_add(fw, &fr) < 0)
			err(1, "fw_delete");
	} else if (strcmp(argv[1], "delete") == 0) {
		if (arg_to_fr(argc - 2, argv + 2, &fr) < 0)
			err(1, "arg_to_fr");
		printf("- ");
		print_rule(&fr, NULL);
		if (fw_delete(fw, &fr) < 0)
			err(1, "fw_delete");
	} else if (strcmp(argv[1], "flush") == 0) {
		if (fw_loop(fw, delete_rule, fw) < 0)
			err(1, "fw_loop");
	} else
		usage();
	
	fw_close(fw);

	exit(0);
}

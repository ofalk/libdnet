/*
 * fw-pf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct fw_handle {
	int	fd;
};

static void
fr_to_pr(struct fw_rule *fr, struct pf_rule *pr)
{
	memset(pr, 0, sizeof(*pr));
	
	strlcpy(pr->ifname, fr->device, sizeof(pr->ifname));
	
	pr->action = (fr->op == FW_OP_ALLOW) ? PF_PASS : PF_DROP;
	pr->direction = (fr->direction == FW_DIR_IN) ? PF_IN : PF_OUT;
	pr->proto = fr->proto;

	pr->src.addr.v4.s_addr = fr->src.addr_ip;
	addr_btom(fr->src.addr_bits, &pr->src.mask.v4.s_addr);
	
	pr->dst.addr.v4.s_addr = fr->dst.addr_ip;
	addr_btom(fr->dst.addr_bits, &pr->dst.mask.v4.s_addr);
	
	switch (fr->proto) {
	case IP_PROTO_ICMP:
		if (fr->sport[1])
			pr->type = (u_char)(fr->sport[0] & fr->sport[1]) + 1;
		if (fr->dport[1])
			pr->code = (u_char)(fr->dport[0] & fr->dport[1]) + 1;
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		pr->src.port[0] = htons(fr->sport[0]);
		pr->src.port[1] = htons(fr->sport[1]);
		if (pr->src.port[0] == pr->src.port[1])
			pr->src.port_op = PF_OP_EQ;
		else
			pr->src.port_op = PF_OP_IRG;

		pr->dst.port[0] = htons(fr->dport[0]);
		pr->dst.port[1] = htons(fr->dport[1]);
		if (pr->dst.port[0] == pr->dst.port[1])
			pr->dst.port_op = PF_OP_EQ;
		else
			pr->dst.port_op = PF_OP_IRG;
		break;
	}
}

static int
pr_to_fr(struct pf_rule *pr, struct fw_rule *fr)
{
	memset(fr, 0, sizeof(*fr));
	
	strlcpy(fr->device, pr->ifname, sizeof(fr->device));

	if (pr->action == PF_DROP)
		fr->op = FW_OP_BLOCK;
	else if (pr->action == PF_PASS)
		fr->op = FW_OP_ALLOW;
	else
		return (-1);
	
	fr->direction = pr->direction == PF_IN ? FW_DIR_IN : FW_DIR_OUT;
	fr->proto = pr->proto;

	fr->src.addr_type = ADDR_TYPE_IP;
	addr_mtob(pr->src.mask.v4.s_addr, &fr->src.addr_bits);
	fr->src.addr_ip = pr->src.addr.v4.s_addr;
	
 	fr->dst.addr_type = ADDR_TYPE_IP;
	addr_mtob(pr->dst.mask.v4.s_addr, &fr->dst.addr_bits);
	fr->dst.addr_ip = pr->dst.addr.v4.s_addr;
	
	switch (fr->proto) {
	case IP_PROTO_ICMP:
		if (pr->type) {
			fr->sport[0] = pr->type - 1;
			fr->sport[1] = 0xff;
		}
		if (pr->code) {
			fr->dport[0] = pr->code - 1;
			fr->dport[1] = 0xff;
		}
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		fr->sport[0] = ntohs(pr->src.port[0]);
		fr->sport[1] = ntohs(pr->src.port[1]);
		if (pr->src.port_op == PF_OP_EQ)
			fr->sport[1] = fr->sport[0];

		fr->dport[0] = ntohs(pr->dst.port[0]);
		fr->dport[1] = ntohs(pr->dst.port[1]);
		if (pr->dst.port_op == PF_OP_EQ)
			fr->dport[1] = fr->dport[0];
	}
	return (0);
}

fw_t *
fw_open(void)
{
	fw_t *fw;

	if ((fw = calloc(1, sizeof(*fw))) == NULL)
		return (NULL);

	if ((fw->fd = open("/dev/pf", O_RDWR)) < 0) {
		free(fw);
		return (NULL);
	}
	return (fw);
}

int
fw_add(fw_t *fw, struct fw_rule *rule)
{
	struct pfioc_changerule pcr;
	
	if (fw == NULL || rule == NULL) {
		errno = EINVAL;
		return (-1);
	}	
	fr_to_pr(rule, &pcr.newrule);
	
	pcr.action = PF_CHANGE_ADD_TAIL;
	
	return (ioctl(fw->fd, DIOCCHANGERULE, &pcr));
}

int
fw_delete(fw_t *fw, struct fw_rule *rule)
{
	struct pfioc_changerule pcr;
	
	if (fw == NULL || rule == NULL) {
		errno = EINVAL;
		return (-1);
	}
	fr_to_pr(rule, &pcr.oldrule);
	
	pcr.action = PF_CHANGE_REMOVE;

	return (ioctl(fw->fd, DIOCCHANGERULE, &pcr));
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct pfioc_rule pr;
	struct fw_rule fr;
	u_int32_t n, max;
	int ret;
	
	if (ioctl(fw->fd, DIOCGETRULES, &pr) < 0)
		return (-1);
	
	for (n = 0, max = pr.nr; n < max; n++) {
		pr.nr = n;
		
		if (ioctl(fw->fd, DIOCGETRULE, &pr) < 0)
			return (-1);
		
		if (pr_to_fr(&pr.rule, &fr) < 0)
			continue;
		
		if ((ret = callback(&fr, arg)) != 0)
			return (ret);
	}
	return (0);
}

int
fw_close(fw_t *fw)
{
	if (fw == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(fw->fd) < 0)
		return (-1);
	
	free(fw);
	return (0);
}

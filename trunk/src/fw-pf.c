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

#include <assert.h>
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
	
	strlcpy(pr->ifname, fr->fw_device, sizeof(pr->ifname));
	
	pr->action = (fr->fw_op == FW_OP_ALLOW) ? PF_PASS : PF_DROP;
	pr->direction = (fr->fw_dir == FW_DIR_IN) ? PF_IN : PF_OUT;
	pr->proto = fr->fw_proto;

	pr->src.addr.v4.s_addr = fr->fw_src.addr_ip;
	addr_btom(fr->fw_src.addr_bits, &pr->src.mask.v4.s_addr, IP_ADDR_LEN);
	
	pr->dst.addr.v4.s_addr = fr->fw_dst.addr_ip;
	addr_btom(fr->fw_dst.addr_bits, &pr->dst.mask.v4.s_addr, IP_ADDR_LEN);
	
	switch (fr->fw_proto) {
	case IP_PROTO_ICMP:
		if (fr->fw_sport[1])
			pr->type = (u_char)(fr->fw_sport[0] &
			    fr->fw_sport[1]) + 1;
		if (fr->fw_dport[1])
			pr->code = (u_char)(fr->fw_dport[0] &
			    fr->fw_dport[1]) + 1;
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		pr->src.port[0] = htons(fr->fw_sport[0]);
		pr->src.port[1] = htons(fr->fw_sport[1]);
		if (pr->src.port[0] == pr->src.port[1])
			pr->src.port_op = PF_OP_EQ;
		else
			pr->src.port_op = PF_OP_IRG;

		pr->dst.port[0] = htons(fr->fw_dport[0]);
		pr->dst.port[1] = htons(fr->fw_dport[1]);
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
	
	strlcpy(fr->fw_device, pr->ifname, sizeof(fr->fw_device));

	if (pr->action == PF_DROP)
		fr->fw_op = FW_OP_BLOCK;
	else if (pr->action == PF_PASS)
		fr->fw_op = FW_OP_ALLOW;
	else
		return (-1);
	
	fr->fw_dir = pr->direction == PF_IN ? FW_DIR_IN : FW_DIR_OUT;
	fr->fw_proto = pr->proto;

	fr->fw_src.addr_type = ADDR_TYPE_IP;
	addr_mtob(&pr->src.mask.v4.s_addr, IP_ADDR_LEN, &fr->fw_src.addr_bits);
	fr->fw_src.addr_ip = pr->src.addr.v4.s_addr;
	
 	fr->fw_dst.addr_type = ADDR_TYPE_IP;
	addr_mtob(&pr->dst.mask.v4.s_addr, IP_ADDR_LEN, &fr->fw_dst.addr_bits);
	fr->fw_dst.addr_ip = pr->dst.addr.v4.s_addr;
	
	switch (fr->fw_proto) {
	case IP_PROTO_ICMP:
		if (pr->type) {
			fr->fw_sport[0] = pr->type - 1;
			fr->fw_sport[1] = 0xff;
		}
		if (pr->code) {
			fr->fw_dport[0] = pr->code - 1;
			fr->fw_dport[1] = 0xff;
		}
		break;
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		fr->fw_sport[0] = ntohs(pr->src.port[0]);
		fr->fw_sport[1] = ntohs(pr->src.port[1]);
		if (pr->src.port_op == PF_OP_EQ)
			fr->fw_sport[1] = fr->fw_sport[0];

		fr->fw_dport[0] = ntohs(pr->dst.port[0]);
		fr->fw_dport[1] = ntohs(pr->dst.port[1]);
		if (pr->dst.port_op == PF_OP_EQ)
			fr->fw_dport[1] = fr->fw_dport[0];
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
	
	assert(fw != NULL && rule != NULL);

	fr_to_pr(rule, &pcr.newrule);
	
	pcr.action = PF_CHANGE_ADD_TAIL;
	
	return (ioctl(fw->fd, DIOCCHANGERULE, &pcr));
}

int
fw_delete(fw_t *fw, struct fw_rule *rule)
{
	struct pfioc_changerule pcr;
	
	assert(fw != NULL && rule != NULL);

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
	assert(fw != NULL);

	if (close(fw->fd) < 0)
		return (-1);
	
	free(fw);
	return (0);
}

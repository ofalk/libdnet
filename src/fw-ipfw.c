/*
 * fw-ipfw.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip_fw.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct fw_handle {
	int	fd;
};

static void
fr_to_ipfw(struct fw_rule *fr, struct ip_fw *ipfw)
{
	int i;
	
	memset(ipfw, 0, sizeof(*ipfw));

	if (fr->direction == FW_DIR_IN) {
		if (*fr->device != '\0') {
			strlcpy(ipfw->fw_in_if.fu_via_if.name,
			    fr->device, FW_IFNLEN);
			ipfw->fw_in_if.fu_via_if.unit = -1;
			ipfw->fw_flg |= IP_FW_F_IIFNAME;
		}
		ipfw->fw_flg |= IP_FW_F_IN;
	} else {
		if (*fr->device != '\0') {
			strlcpy(ipfw->fw_out_if.fu_via_if.name,
			    fr->device, FW_IFNLEN);
			ipfw->fw_out_if.fu_via_if.unit = -1;
			ipfw->fw_flg |= IP_FW_F_OIFNAME;
		}
		ipfw->fw_flg |= IP_FW_F_OUT;
	}
	if (fr->op == FW_OP_ALLOW)
		ipfw->fw_flg |= IP_FW_F_ACCEPT;
	else
		ipfw->fw_flg |= IP_FW_F_DENY;
	
	ipfw->fw_prot = fr->proto;
	ipfw->fw_src.s_addr = fr->src.addr_ip;
	ipfw->fw_dst.s_addr = fr->dst.addr_ip;
	addr_btom(fr->src.addr_bits, &ipfw->fw_smsk.s_addr);
	addr_btom(fr->dst.addr_bits, &ipfw->fw_dmsk.s_addr);

	switch (fr->proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		i = 0;
		if (fr->sport[0] != fr->sport[1]) {
			ipfw->fw_flg |= IP_FW_F_SRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->sport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->sport[1];
			IP_FW_SETNSRCP(ipfw, 2);
		} else {
			ipfw->fw_uar.fw_pts[i++] = fr->sport[0];
			IP_FW_SETNSRCP(ipfw, 1);
		}
		if (fr->dport[0] != fr->dport[1]) {
			ipfw->fw_flg |= IP_FW_F_DRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->dport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->dport[1];
			IP_FW_SETNDSTP(ipfw, 2);
		} else {
			ipfw->fw_uar.fw_pts[i++] = fr->dport[0];
			IP_FW_SETNDSTP(ipfw, 1);
		}
		break;
	}
}

static void
ipfw_to_fr(struct ip_fw *ipfw, struct fw_rule *fr)
{
	int i;
	
	memset(fr, 0, sizeof(fr));

	strlcpy(fr->device, ipfw->fw_in_if.fu_via_if.name, sizeof(fr->device));

	fr->op = (ipfw->fw_flg & IP_FW_F_ACCEPT) ? FW_OP_ALLOW : FW_OP_BLOCK;
	fr->direction = (ipfw->fw_flg & IP_FW_F_IN) ? FW_DIR_IN : FW_DIR_OUT;
	fr->proto = ipfw->fw_prot;

	fr->src.addr_type = fr->dst.addr_type = ADDR_TYPE_IP;
	fr->src.addr_ip = ipfw->fw_src.s_addr;
	fr->dst.addr_ip = ipfw->fw_dst.s_addr;
	addr_mtob(ipfw->fw_smsk.s_addr, &fr->src.addr_bits);
	addr_mtob(ipfw->fw_dmsk.s_addr, &fr->dst.addr_bits);

	switch (fr->proto) {
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		if (ipfw->fw_flg & IP_FW_F_SRNG) {
			fr->sport[0] = ipfw->fw_uar.fw_pts[0];
			fr->sport[1] = ipfw->fw_uar.fw_pts[1];
		} else
			fr->sport[0] = fr->sport[1] = ipfw->fw_uar.fw_pts[0];
		
		if (ipfw->fw_flg & IP_FW_F_DRNG) {
			i = IP_FW_GETNSRCP(ipfw);
			fr->dport[0] = ipfw->fw_uar.fw_pts[i];
			fr->dport[1] = ipfw->fw_uar.fw_pts[i + 1];
		} else
			fr->dport[0] = fr->dport[1] = ipfw->fw_uar.fw_pts[0];
		break;
	}
}

fw_t *
fw_open(void)
{
	fw_t *fw;
	
	if ((fw = calloc(1, sizeof(*fw))) == NULL)
		return (NULL);

	if ((fw->fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) < 0) {
		free(fw);
		return (NULL);
	}
	return (fw);
}

int
fw_add(fw_t *fw, struct fw_rule *rule)
{
	struct ip_fw ipfw;
	
	if (fw == NULL || rule == NULL) {
		errno = EINVAL;
		return (-1);
	}
	fr_to_ipfw(rule, &ipfw);

	return (setsockopt(fw->fd, IPPROTO_IP, IP_FW_ADD,
	    &ipfw, sizeof(ipfw)));
}

int
fw_delete(fw_t *fw, struct fw_rule *rule)
{
	struct ip_fw ipfw;
	struct fw_rule fr;
	int i;
	
	if (fw == NULL || rule == NULL) {
		errno = EINVAL;
		return (-1);
	}
        memset(&ipfw, 0, sizeof(ipfw));

	for (i = 0; i < 65535; i++) {
		ipfw.fw_number = i;
		if (setsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
		    &ipfw, sizeof(ipfw)) < 0) {
			if (errno != EINVAL)
				return (-1);
			break;
		}
		ipfw_to_fr(&ipfw, &fr);

		if (memcmp(&fr, rule, sizeof(fr)) == 0) {
			if (setsockopt(fw->fd, IPPROTO_IP, IP_FW_DEL,
			    &ipfw, sizeof(ipfw)) < 0)
				return (-1);
			break;
		}
	}
	if (i == 65535) {
		errno = ESRCH;
		return (-1);
	}
	return (0);
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct ip_fw ipfw;
	struct fw_rule fr;
	int i, ret;
	
	memset(&ipfw, 0, sizeof(ipfw));
	
	for (i = 0; i < 65535; i++) {
		ipfw.fw_number = i;
		if (setsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
		    &ipfw, sizeof(ipfw)) < 0) {
			if (errno != EINVAL)
				return (-1);
			break;
		}
		ipfw_to_fr(&ipfw, &fr);
		
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

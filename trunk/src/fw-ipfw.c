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
fr_to_ipfw_device(char *device, char *name, short *unit)
{
	char *p;

	p = strpbrk(device, "0123456789");
	*unit = atoi(p);
	strlcpy(name, device, p - device + 1);
}

static void
fr_to_ipfw(struct fw_rule *fr, struct ip_fw *ipfw)
{
	int i;
	
	memset(ipfw, 0, sizeof(*ipfw));

	if (fr->direction == FW_DIR_IN) {
		if (*fr->device != '\0') {
			fr_to_ipfw_device(fr->device,
			    ipfw->fw_in_if.fu_via_if.name,
			    &ipfw->fw_in_if.fu_via_if.unit);
			ipfw->fw_flg |= IP_FW_F_IIFNAME;
		}
		ipfw->fw_flg |= IP_FW_F_IN;
	} else {
		if (*fr->device != '\0') {
			fr_to_ipfw_device(fr->device,
			    ipfw->fw_out_if.fu_via_if.name,
			    &ipfw->fw_out_if.fu_via_if.unit);
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
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		i = 0;
		if (fr->sport[0] != fr->sport[1]) {
			ipfw->fw_flg |= IP_FW_F_SRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->sport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->sport[1];
			IP_FW_SETNSRCP(ipfw, 2);
		} else if (fr->sport[0] > 0) {
			ipfw->fw_uar.fw_pts[i++] = fr->sport[0];
			IP_FW_SETNSRCP(ipfw, 1);
		}
		if (fr->dport[0] != fr->dport[1]) {
			ipfw->fw_flg |= IP_FW_F_DRNG;
			ipfw->fw_uar.fw_pts[i++] = fr->dport[0];
			ipfw->fw_uar.fw_pts[i++] = fr->dport[1];
			IP_FW_SETNDSTP(ipfw, 2);
		} else if (fr->dport[0] > 0) {
			ipfw->fw_uar.fw_pts[i++] = fr->dport[0];
			IP_FW_SETNDSTP(ipfw, 1);
		}
		break;
	case IP_PROTO_ICMP:
		if (fr->sport[1]) {
			ipfw->fw_uar.fw_icmptypes[fr->sport[0] / 32] |=
			    1 << (fr->sport[0] % 32);
			ipfw->fw_flg |= IP_FW_F_ICMPBIT;
		}
		/* XXX - no support for ICMP code. */
	  	break;
	}
}

static void
ipfw_to_fr(struct ip_fw *ipfw, struct fw_rule *fr)
{
	int i;
	
	memset(fr, 0, sizeof(*fr));

	if ((ipfw->fw_flg & IP_FW_F_IN) && *ipfw->fw_in_if.fu_via_if.name)
		snprintf(fr->device, sizeof(fr->device), "%s%d",
		    ipfw->fw_in_if.fu_via_if.name,
		    ipfw->fw_in_if.fu_via_if.unit);
	else if ((ipfw->fw_flg & IP_FW_F_OUT) &&
	    *ipfw->fw_out_if.fu_via_if.name)
		snprintf(fr->device, sizeof(fr->device), "%s%d",
		    ipfw->fw_out_if.fu_via_if.name,
		    ipfw->fw_out_if.fu_via_if.unit);
	
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
		if ((ipfw->fw_flg & IP_FW_F_SRNG) &&
		    IP_FW_GETNSRCP(ipfw) == 2) {
			fr->sport[0] = ipfw->fw_uar.fw_pts[0];
			fr->sport[1] = ipfw->fw_uar.fw_pts[1];
		} else if (IP_FW_GETNSRCP(ipfw) == 1) {
			fr->sport[0] = fr->sport[1] = ipfw->fw_uar.fw_pts[0];
		} else if (IP_FW_GETNSRCP(ipfw) == 0) {
		  	fr->sport[0] = 0;
			fr->sport[1] = TCP_PORT_MAX;
		}
		
		if ((ipfw->fw_flg & IP_FW_F_DRNG) &&
		    IP_FW_GETNDSTP(ipfw) == 2) {
			i = IP_FW_GETNSRCP(ipfw);
			fr->dport[0] = ipfw->fw_uar.fw_pts[i];
			fr->dport[1] = ipfw->fw_uar.fw_pts[i + 1];
		} else if (IP_FW_GETNDSTP(ipfw) == 1) {
			i = IP_FW_GETNSRCP(ipfw);
			fr->dport[0] = fr->dport[1] = ipfw->fw_uar.fw_pts[i];
		} else if (IP_FW_GETNDSTP(ipfw) == 0) {
		  	fr->dport[0] = 0;
			fr->dport[1] = TCP_PORT_MAX;
		}
		break;
	case IP_PROTO_ICMP:
		if (ipfw->fw_flg & IP_FW_F_ICMPBIT) {
			for (i = 0; i < IP_FW_ICMPTYPES_DIM * 32; i++) {
				if (ipfw->fw_uar.fw_icmptypes[i / 32] &
				    (1U << (i % 32))) {
					fr->sport[0] = i;
					fr->sport[1] = 0xff;
					break;
				}
			}
		}
	  	/* XXX - no support for ICMP code. */
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

static int
fw_cmp(struct fw_rule *a, struct fw_rule *b)
{
	if (strcmp(a->device, b->device) != 0 || a->op != b->op ||
	    a->direction != b->direction || a->proto != b->proto || 
	    addr_cmp(&a->src, &b->src) != 0 ||
	    addr_cmp(&a->dst, &b->dst) != 0 ||
	    memcmp(a->sport, b->sport, sizeof(a->sport)) != 0 ||
	    memcmp(a->dport, b->dport, sizeof(a->dport)) != 0)
		return (-1);
	return (0);
}

int
fw_delete(fw_t *fw, struct fw_rule *rule)
{
	struct ip_fw *ipfw;
	struct fw_rule fr;
	int nbytes, nalloc, ret;
	u_char *buf, *new;

	if (rule == NULL) {
		errno = EINVAL;
		return (-1);
	}
	nbytes = nalloc = sizeof(*ipfw);
	if ((buf = malloc(nbytes)) == NULL)
		return (-1);
	
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 + 200;
		nbytes = nalloc;
		if ((new = realloc(buf, nbytes)) == NULL) {
			if (buf)
				free(buf);
			return (-1);
		}
		buf = new;
		if (getsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
			       buf, &nbytes) < 0) {
			free(buf);
			return (-1);
		}
	}
	ret = 0;
	for (ipfw = (struct ip_fw *)buf; ipfw->fw_number < 65535; ipfw++) {
		ipfw_to_fr(ipfw, &fr);
		if (fw_cmp(&fr, rule) == 0) {
			if (setsockopt(fw->fd, IPPROTO_IP, IP_FW_DEL,
			    ipfw, sizeof(*ipfw)) < 0) {
				free(buf);
				return (-1);
			}
			free(buf);
			return (0);
		}
	}
	errno = ESRCH;
	free(buf);
	return (-1);
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct ip_fw *ipfw;
	struct fw_rule fr;
	int nbytes, nalloc, ret;
	u_char *buf, *new;

	nbytes = nalloc = sizeof(*ipfw);
	if ((buf = malloc(nbytes)) == NULL)
		return (-1);
	
	while (nbytes >= nalloc) {
		nalloc = nalloc * 2 + 200;
		nbytes = nalloc;
		if ((new = realloc(buf, nbytes)) == NULL) {
			if (buf)
				free(buf);
			return (-1);
		}
		buf = new;
		if (getsockopt(fw->fd, IPPROTO_IP, IP_FW_GET,
			       buf, &nbytes) < 0) {
			free(buf);
			return (-1);
		}
	}
	ret = 0;
	for (ipfw = (struct ip_fw *)buf; ipfw->fw_number < 65535; ipfw++) {
		ipfw_to_fr(ipfw, &fr);
		if ((ret = callback(&fr, arg)) != 0)
			break;
	}
	free(buf);
	return (ret);
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

/*
 * fw-ipf.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_IP_FIL_COMPAT_H
# include <netinet/ip_fil_compat.h>
#else
# include <netinet/ip_compat.h>
#endif
#include <netinet/ip_fil.h>
#ifdef IP6EQ
#define HAVE_I6ADDR	1
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KMEM_NAME	"/dev/kmem"

typedef u_int32_t ip_addr_t;

#include "dnet/eth.h"
#include "dnet/addr.h"
#include "dnet/tcp.h"
#include "dnet/fw.h"

struct fw_handle {
	int	fd;
	int	kfd;
};

static void
rule_to_ipf(struct fw_rule *rule, struct frentry *fr)
{
	memset(fr, 0, sizeof(*fr));

	if (*rule->device != '\0') {
		strlcpy(fr->fr_ifname, rule->device, IFNAMSIZ);
		strlcpy(fr->fr_oifname, rule->device, IFNAMSIZ);
	}
	if (rule->op == FW_OP_ALLOW)
		fr->fr_flags |= FR_PASS;
	else
		fr->fr_flags |= FR_BLOCK;
	
	fr->fr_ip.fi_p = rule->proto;
#ifdef HAVE_IP6ADDR
	fr->fr_ip.fi_saddr = rule->src.addr_ip;
	fr->fr_ip.fi_daddr = rule->dst.addr_ip;
	addr_btom(rule->src.addr_bits, &fr->fr_mip.fi_saddr, IP_ADDR_LEN);
	addr_btom(rule->dst.addr_bits, &fr->fr_mip.fi_daddr, IP_ADDR_LEN);
#else
	fr->fr_ip.fi_src.s_addr = rule->src.addr_ip;
	fr->fr_ip.fi_dst.s_addr = rule->dst.addr_ip;
	addr_btom(rule->src.addr_bits, &fr->fr_mip.fi_src.s_addr, IP_ADDR_LEN);
	addr_btom(rule->dst.addr_bits, &fr->fr_mip.fi_dst.s_addr, IP_ADDR_LEN);
#endif
	switch (rule->proto) {
	case IPPROTO_ICMP:
		fr->fr_icmpm = rule->sport[1] << 8 | (rule->dport[1] & 0xff);
		fr->fr_icmp = rule->sport[0] << 8 | (rule->dport[0] & 0xff);
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		fr->fr_sport = rule->sport[0];
		if (rule->sport[0] != rule->sport[1]) {
			fr->fr_scmp = FR_INRANGE;
			fr->fr_stop = rule->sport[1];
		} else
			fr->fr_scmp = FR_EQUAL;

		fr->fr_dport = rule->dport[0];
		if (rule->dport[0] != rule->dport[1]) {
			fr->fr_dcmp = FR_INRANGE;
			fr->fr_dtop = rule->dport[1];
		} else
			fr->fr_dcmp = FR_EQUAL;
		break;
	}
}

static void
ipf_ports_to_rule(u_char cmp, u_short port, u_short top, u_short *range)
{
	switch (cmp) {
	case FR_EQUAL:
		range[0] = range[1] = port;
		break;
	case FR_NEQUAL:
		range[0] = port - 1;
		range[1] = port + 1;
		break;
	case FR_LESST:
		range[0] = 0;
		range[1] = port - 1;
		break;
	case FR_GREATERT:
		range[0] = port + 1;
		range[1] = TCP_PORT_MAX;
		break;
	case FR_LESSTE:
		range[0] = 0;
		range[1] = port;
		break;
	case FR_GREATERTE:
		range[0] = port;
		range[1] = TCP_PORT_MAX;
		break;
	case FR_OUTRANGE:
		range[0] = port;
		range[1] = top;
		break;
	case FR_INRANGE:
		range[0] = top;
		range[1] = port;
		break;
	default:
		range[0] = 0;
		range[1] = TCP_PORT_MAX;
	}
}

static void
ipf_to_rule(struct frentry *fr, struct fw_rule *rule)
{
	memset(rule, 0, sizeof(*rule));

	strlcpy(rule->device, fr->fr_ifname, sizeof(rule->device));
	rule->op = (fr->fr_flags & FR_PASS) ? FW_OP_ALLOW : FW_OP_BLOCK;
	rule->direction = (fr->fr_flags & FR_INQUE) ? FW_DIR_IN : FW_DIR_OUT;
	rule->proto = fr->fr_ip.fi_p;

	rule->src.addr_type = rule->dst.addr_type = ADDR_TYPE_IP;
#ifdef HAVE_I6ADDR
	rule->src.addr_ip = fr->fr_ip.fi_saddr;
	rule->dst.addr_ip = fr->fr_ip.fi_daddr;
	addr_mtob(&fr->fr_mip.fi_saddr, IP_ADDR_LEN,
	    &rule->src.addr_bits);
	addr_mtob(&fr->fr_mip.fi_daddr, IP_ADDR_LEN,
	    &rule->dst.addr_bits);
#else
	rule->src.addr_ip = fr->fr_ip.fi_src.s_addr;
	rule->dst.addr_ip = fr->fr_ip.fi_dst.s_addr;
	addr_mtob(&fr->fr_mip.fi_src.s_addr, IP_ADDR_LEN,
	    &rule->src.addr_bits);
	addr_mtob(&fr->fr_mip.fi_dst.s_addr, IP_ADDR_LEN,
	    &rule->dst.addr_bits);
#endif
	switch (rule->proto) {
	case IPPROTO_ICMP:
		rule->sport[0] = ntohs(fr->fr_icmp & fr->fr_icmpm) >> 8;
		rule->sport[1] = ntohs(fr->fr_icmpm) >> 8;
		rule->dport[0] = ntohs(fr->fr_icmp & fr->fr_icmpm) & 0xff;
		rule->dport[1] = ntohs(fr->fr_icmpm) & 0xff;
		break;
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ipf_ports_to_rule(fr->fr_scmp, fr->fr_sport,
		    fr->fr_stop, rule->sport);
		ipf_ports_to_rule(fr->fr_dcmp, fr->fr_dport,
		    fr->fr_dtop, rule->dport);
		break;
	}
}

fw_t *
fw_open(void)
{
	fw_t *fw;
	
	if ((fw = calloc(1, sizeof(*fw))) == NULL)
		return (NULL);

	if ((fw->fd = open(IPL_NAME, O_RDWR, 0)) < 0) {
		free(fw);
		return (NULL);
	}
	if ((fw->kfd = open(KMEM_NAME, O_RDONLY)) < 0) {
		close(fw->fd);
		free(fw);
		return (NULL);
	}
	return (fw);
}

int
fw_add(fw_t *fw, struct fw_rule *rule)
{
	struct frentry fr;
	
	assert(fw != NULL && rule != NULL);
	
	rule_to_ipf(rule, &fr);
	
	return (ioctl(fw->fd, SIOCADDFR, &fr));
}

int
fw_delete(fw_t *fw, struct fw_rule *rule)
{
	struct frentry fr;
	
	assert(fw != NULL && rule != NULL);

	rule_to_ipf(rule, &fr);
	
	return (ioctl(fw->fd, SIOCDELFR, &fr));
}

static int
fw_kcopy(fw_t *fw, u_char *buf, off_t pos, ssize_t n)
{
	int i;
	
	if (lseek(fw->kfd, pos, 0) < 0)
		return (-1);

	while ((i = read(fw->kfd, buf, n)) < n) {
		if (i <= 0)
			return (-1);
		buf += i;
		n -= i;
	}
	return (0);
}

int
fw_loop(fw_t *fw, fw_handler callback, void *arg)
{
	struct friostat fio;
	struct friostat *fiop = &fio;
	struct frentry *frp, fr;
	struct fw_rule rule;
	int ret;
	
	memset(&fio, 0, sizeof(fio));
#ifdef __OpenBSD__
	if (ioctl(fw->fd, SIOCGETFS, fiop) < 0)
#else
	if (ioctl(fw->fd, SIOCGETFS, &fiop) < 0)	/* XXX - darren! */
#endif
		return (-1);

	for (frp = fio.f_fout[(int)fio.f_active]; frp != NULL; frp = fr.fr_next) {
		if (fw_kcopy(fw, (u_char *)&fr, (u_long)frp, sizeof(fr)) < 0)
			return (-1);
		ipf_to_rule(&fr, &rule);
		if ((ret = callback(&rule, arg)) != 0)
			return (ret);
	}
	for (frp = fio.f_fin[(int)fio.f_active]; frp != NULL; frp = fr.fr_next) {
		if (fw_kcopy(fw, (u_char *)&fr, (u_long)frp, sizeof(fr)) < 0)
			return (-1);
		ipf_to_rule(&fr, &rule);
		if ((ret = callback(&rule, arg)) != 0)
			return (ret);
	}
	return (0);
}

int
fw_close(fw_t *fw)
{
	assert(fw != NULL);

	if (close(fw->fd) < 0 || close(fw->kfd) < 0)
		return (-1);
	
	free(fw);
	return (0);
}

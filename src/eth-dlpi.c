/*
 * eth-dlpi.c
 *
 * Based on Neal Nuckolls' 1992 "How to Use DLPI" paper.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/bufmod.h>
#endif
#ifdef HAVE_SYS_DLPI_H
#include <sys/dlpi.h>
#elif defined(HAVE_SYS_DLPIHDR_H)
#include <sys/dlpihdr.h>
#endif
#ifdef HAVE_SYS_DLPI_EXT_H
#include <sys/dlpi_ext.h>
#endif
#include <sys/stream.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include "dnet.h"

struct eth_handle {
	int	fd;
	int	sap_first;
};

int	eth_get_hwaddr(eth_t *e, struct addr *ha);

static int
dlpi_msg(int fd, union DL_primitives *dlp, int rlen, int flags,
    int ack, int alen, int size)
{
	struct strbuf ctl;

	ctl.maxlen = 0;
	ctl.len = rlen;
	ctl.buf = (caddr_t)dlp;
	
	if (putmsg(fd, &ctl, NULL, flags) < 0)
		return (-1);
	
	ctl.maxlen = size;
	ctl.len = 0;
	
	flags = 0;

	if (getmsg(fd, &ctl, NULL, &flags) < 0)
		return (-1);
	
	if (dlp->dl_primitive != ack || ctl.len < alen)
		return (-1);
	
	return (0);
}

#if defined(DLIOCRAW) || defined(HAVE_SYS_DLPIHDR_H)
static int
strioctl(int fd, int cmd, int len, char *dp)
{
	struct strioctl str;
	
	str.ic_cmd = cmd;
	str.ic_timout = -1;
	str.ic_len = len;
	str.ic_dp = dp;
	
	if (ioctl(fd, I_STR, &str) < 0)
		return (-1);
	
	return (str.ic_len);
}
#endif

#ifdef HAVE_SYS_DLPIHDR_H
/* XXX - OSF1 is nuts */
#define ND_GET	('N' << 8 + 0)

static int
eth_match_ppa(eth_t *e, char *device)
{
	char *p, dev[16], buf[256];
	int len, ppa;

	strlcpy(buf, "dl_ifnames", sizeof(buf));
	
	if ((len = strioctl(e->fd, ND_GET, sizeof(buf), buf)) < 0)
		return (-1);
	
	for (p = buf; p < buf + len; p += strlen(p) + 1) {
		ppa = -1;
		if (sscanf(p, "%s (PPA %d)\n", dev, &ppa) != 2)
			break;
		if (strcmp(dev, device) == 0)
			break;
	}
	return (ppa);
}
#endif

eth_t *
eth_open(char *device)
{
	union DL_primitives *dlp;
	u_int32_t buf[8192];
	char *p, dev[16];
	eth_t *e;
	int ppa;

	if ((e = calloc(1, sizeof(*e))) == NULL)
		return (NULL);
	
#ifdef HAVE_SYS_DLPIHDR_H
	if ((e->fd = open("/dev/streams/dlb", O_RDWR)) < 0) {
		free(e);
		return (NULL);
	}
	if ((ppa = eth_match_ppa(e, device)) < 0) {
		errno = ESRCH;
		eth_close(e);
		return (NULL);
	}
#else
	snprintf(dev, sizeof(dev), "/dev/%s", device);
	
	if ((p = strpbrk(dev, "0123456789")) == NULL) {
		errno = EINVAL;
		return (NULL);
	}
	ppa = atoi(p);
	*p = '\0';

	if ((e->fd = open(dev, O_RDWR)) < 0) {
		snprintf(dev, sizeof(dev), "/dev/%s", device);
		if ((e->fd = open(dev, O_RDWR)) < 0) {
			free(e);
			return (NULL);
		}
	}
#endif
	dlp = (union DL_primitives *)buf;
	dlp->info_req.dl_primitive = DL_INFO_REQ;
	
	if (dlpi_msg(e->fd, dlp, DL_INFO_REQ_SIZE, RS_HIPRI,
	    DL_INFO_ACK, DL_INFO_ACK_SIZE, sizeof(buf)) < 0) {
		eth_close(e);
		return (NULL);
	}
	e->sap_first = (dlp->info_ack.dl_sap_length > 0);
	
	if (dlp->info_ack.dl_provider_style == DL_STYLE2) {
		dlp->attach_req.dl_primitive = DL_ATTACH_REQ;
		dlp->attach_req.dl_ppa = ppa;
		
		if (dlpi_msg(e->fd, dlp, DL_ATTACH_REQ_SIZE, 0,
		    DL_OK_ACK, DL_OK_ACK_SIZE, sizeof(buf)) < 0) {
			eth_close(e);
			return (NULL);
		}
	}
	memset(&dlp->bind_req, 0, DL_BIND_REQ_SIZE);
	dlp->bind_req.dl_primitive = DL_BIND_REQ;
#ifdef DL_HP_RAWDLS
	dlp->bind_req.dl_sap = ETH_TYPE_IP + 1;		/* XXX */
	dlp->bind_req.dl_service_mode = DL_HP_RAWDLS;
#else
	dlp->bind_req.dl_service_mode = DL_CLDLS;
#endif
	if (dlpi_msg(e->fd, dlp, DL_BIND_REQ_SIZE, 0,
	    DL_BIND_ACK, DL_BIND_ACK_SIZE, sizeof(buf)) < 0) {
		eth_close(e);
		return (NULL);
	}
#ifdef DLIOCRAW
	if (strioctl(e->fd, DLIOCRAW, 0, NULL) < 0) {
		eth_close(e);
		return (NULL);
	}
#endif
	return (e);
}

ssize_t
eth_send(eth_t *e, const void *buf, size_t len)
{
#if defined(DLIOCRAW)
	return (write(e->fd, buf, len));
#else
	union DL_primitives *dlp;
	struct strbuf ctl, data;
	struct eth_hdr *eth;
	u_int32_t ctlbuf[8192];

	eth = (struct eth_hdr *)buf;
	
	dlp = (union DL_primitives *)ctlbuf;
	dlp->unitdata_req.dl_primitive = DL_UNITDATA_REQ;
	dlp->unitdata_req.dl_dest_addr_length = ETH_ADDR_LEN;
	dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;
	dlp->unitdata_req.dl_priority.dl_min =
	    dlp->unitdata_req.dl_priority.dl_max = 0;
	
	ctl.maxlen = 0;
	ctl.len = DL_UNITDATA_REQ_SIZE + ETH_ADDR_LEN + sizeof(eth->eth_type);
	ctl.buf = (char *)ctlbuf;

	if (e->sap_first) {
		memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE,
		    &eth->eth_type, sizeof(eth->eth_type));
		memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE + sizeof(eth->eth_type),
		    eth->eth_dst.data, ETH_ADDR_LEN);
	} else {
		memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE,
		    eth->eth_dst.data, ETH_ADDR_LEN);
		memcpy(ctlbuf + DL_UNITDATA_REQ_SIZE + ETH_ADDR_LEN,
		    &eth->eth_type, sizeof(eth->eth_type));
	}
	data.maxlen = 0;
	data.len = len;
	data.buf = (char *)buf;

	return (putmsg(e->fd, &ctl, &data, 0));
#endif
}

int
eth_close(eth_t *e)
{
	if (e == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(e->fd) < 0)
		return (-1);
	
	free(e);
	return (0);
}

int
eth_get_hwaddr(eth_t *e, struct addr *ha)
{
	union DL_primitives *dlp;
	u_char buf[2048];
	
	dlp = (union DL_primitives *)buf;
	dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
	dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;

	if (dlpi_msg(e->fd, dlp, DL_PHYS_ADDR_REQ_SIZE, 0,
	    DL_PHYS_ADDR_ACK, DL_PHYS_ADDR_ACK_SIZE, sizeof(buf)) < 0)
		return (-1);

	ha->addr_type = ADDR_TYPE_ETH;
	ha->addr_bits = ETH_ADDR_BITS;

	memcpy(&ha->addr_eth, buf + dlp->physaddr_ack.dl_addr_offset, 
	    ETH_ADDR_LEN);

	return (0);
}

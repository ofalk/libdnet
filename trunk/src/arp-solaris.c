/*
 * arp-solaris.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 * 
 * $Id$
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#undef IP_ADDR_LEN
#include <net/if_arp.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <stropts.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct arp_handle {
	int	fd;
};

arp_t *
arp_open(void)
{
	arp_t *r;
	
	if ((r = malloc(sizeof(*r))) == NULL)
		return (NULL);
	
	if ((r->fd = open(IP_DEV_NAME, O_RDWR)) < 0) {
		free(r);
		return (NULL);
	}
	return (r);
}

int
arp_add(arp_t *a, struct addr *pa, struct addr *ha)
{
	struct arpreq ar;
	struct sockaddr_in sin;
	int fd;
	
	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(pa, &ar.arp_pa) < 0 ||
	    addr_ntos(ha, &ar.arp_ha) < 0)
		return (-1);
	
	ar.arp_flags = ATF_PERM | ATF_COM;
	
	if (ioctl(a->fd, SIOCSARP, &ar) < 0)
		return (-1);

	/* XXX - force entry into ipNetToMediaTable. */
	addr_ntos(pa, (struct sockaddr *)&sin);
	sin.sin_port = htons(666);
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (-1);

	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(fd);
		return (-1);
	}
	write(fd, NULL, 0);
	
	close(fd);
	
	return (0);
}

int
arp_delete(arp_t *a, struct addr *pa)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(pa, &ar.arp_pa) < 0)
		return (-1);
	
	ar.arp_flags = ATF_PERM;
	
	if (ioctl(a->fd, SIOCDARP, &ar) < 0)
		return (-1);

	return (0);
}

int
arp_get(arp_t *a, struct addr *pa, struct addr *ha)
{
	struct arpreq ar;

	memset(&ar, 0, sizeof(ar));
	
	if (addr_ntos(pa, &ar.arp_pa) < 0)
		return (-1);
	
	ar.arp_flags = ATF_PERM;
	
	if (ioctl(a->fd, SIOCGARP, &ar) < 0)
		return (-1);

	return (addr_ston(&ar.arp_ha, ha));
}

int
arp_loop(arp_t *r, arp_handler callback, void *arg)
{
	struct strbuf msg;
	struct T_optmgmt_req *tor;
	struct T_optmgmt_ack *toa;
	struct T_error_ack *tea;
	struct opthdr *opt;
	mib2_ipNetToMediaEntry_t *arp, *arpend;
	u_char buf[8192];
	int flags, rc, atable, ret;

	tor = (struct T_optmgmt_req *)buf;
	toa = (struct T_optmgmt_ack *)buf;
	tea = (struct T_error_ack *)buf;

	tor->PRIM_type = T_OPTMGMT_REQ;
	tor->OPT_offset = sizeof(*tor);
	tor->OPT_length = sizeof(*opt);
	tor->MGMT_flags = T_CURRENT;
	
	opt = (struct opthdr *)(tor + 1);
	opt->level = MIB2_IP;
	opt->name = opt->len = 0;
	
	msg.maxlen = sizeof(buf);
	msg.len = sizeof(*tor) + sizeof(*opt);
	msg.buf = buf;
	
	if (putmsg(r->fd, &msg, NULL, 0) < 0)
		return (-1);
	
	opt = (struct opthdr *)(toa + 1);
	msg.maxlen = sizeof(buf);
	
	for (;;) {
		flags = 0;
		if ((rc = getmsg(r->fd, &msg, NULL, &flags)) < 0)
			return (-1);

		/* See if we're finished. */
		if (rc == 0 &&
		    msg.len >= sizeof(*toa) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS && opt->len == 0)
			break;

		if (msg.len >= sizeof(*tea) && tea->PRIM_type == T_ERROR_ACK)
			return (-1);
		
		if (rc != MOREDATA || msg.len < sizeof(*toa) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS)
			return (-1);
		
		atable = (opt->level == MIB2_IP && opt->name == MIB2_IP_22);
		
		msg.maxlen = sizeof(buf) - (sizeof(buf) % sizeof(*arp));
		msg.len = 0;
		flags = 0;
		
		do {
			struct addr pa, ha;
			
			rc = getmsg(r->fd, NULL, &msg, &flags);
			
			if (rc != 0 && rc != MOREDATA)
				return (-1);
			
			if (!atable)
				continue;
			
			arp = (mib2_ipNetToMediaEntry_t *)msg.buf;
			arpend = (mib2_ipNetToMediaEntry_t *)
			    (msg.buf + msg.len);

			pa.addr_type = ADDR_TYPE_IP;
			pa.addr_bits = IP_ADDR_BITS;
			
			ha.addr_type = ADDR_TYPE_ETH;
			ha.addr_bits = ETH_ADDR_BITS;

			for ( ; arp < arpend; arp++) {
				pa.addr_ip = arp->ipNetToMediaNetAddress;
				
				memcpy(&ha.addr_eth,
				    arp->ipNetToMediaPhysAddress.o_bytes,
				    ETH_ADDR_LEN);
				
				if ((ret = callback(&pa, &ha, arg)) != 0)
					return (ret);
			}
		} while (rc == MOREDATA);
	}
	return (0);
}

int
arp_close(arp_t *r)
{
	if (r == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (close(r->fd) < 0)
		return (-1);
	
	free(r);
	return (0);
}

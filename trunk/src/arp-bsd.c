/*
 * arp-bsd.c
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_STREAMS_ROUTE
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

struct arp_handle {
	int	fd;
	pid_t	pid;
	int	seq;
};

struct arpmsg {
	struct rt_msghdr	rtm;
	u_char			addrs[256];
};

arp_t *
arp_open(void)
{
	arp_t *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return (NULL);

#ifdef HAVE_STREAMS_ROUTE
	if ((a->fd = open("/dev/route", O_RDWR, 0)) < 0) {
#else
	if ((a->fd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
#endif
		free(a);
		return (NULL);
	}
	a->pid = getpid();

	return (a);
}

static int
arp_msg(arp_t *a, struct arpmsg *msg)
{
	int len;
	
	msg->rtm.rtm_version = RTM_VERSION;
	msg->rtm.rtm_seq = ++a->seq; 
	
#ifdef HAVE_STREAMS_ROUTE
	return (ioctl(a->fd, RTSTR_SEND, &msg->rtm));
#else
	if (write(a->fd, msg, msg->rtm.rtm_msglen) < 0) {
		if (errno != ESRCH || msg->rtm.rtm_type != RTM_DELETE)
			return (-1);
	}
	/* XXX - should we only read RTM_GET responses here? */
	while ((len = read(a->fd, msg, sizeof(*msg))) > 0) {
		if (len < sizeof(msg->rtm))
			return (-1);
		
		if (msg->rtm.rtm_seq == a->seq && msg->rtm.rtm_pid == a->pid)
			break;
	}
	if (len < 0)
		return (-1);
	
	return (0);
#endif
}

int
arp_add(arp_t *a, const struct addr *pa, const struct addr *ha)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	int index, type;
	
	assert(a != NULL && pa != NULL && ha != NULL);
	
	if (pa->addr_type != ADDR_TYPE_IP || ha->addr_type != ADDR_TYPE_ETH) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);
	
	if (addr_ntos(pa, (struct sockaddr *)sin) < 0)
		return (-1);
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(a, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < sizeof(msg.rtm) + sizeof(*sin) + sizeof(*sa)) {
		errno = EADDRNOTAVAIL;
		return (-1);
	}
	if (sin->sin_addr.s_addr == pa->addr_ip) {
		if ((msg.rtm.rtm_flags & RTF_LLINFO) == 0 ||
		    (msg.rtm.rtm_flags & RTF_GATEWAY) != 0) {
			errno = EADDRINUSE;
			return (-1);
		}
	}
	if (sa->sa_family != AF_LINK) {
		errno = EADDRNOTAVAIL;
		return (-1);
	} else {
		index = ((struct sockaddr_dl *)sa)->sdl_index;
		type = ((struct sockaddr_dl *)sa)->sdl_type;
	}
	if (addr_ntos(pa, (struct sockaddr *)sin) < 0 || addr_ntos(ha, sa) < 0)
		return (-1);

	((struct sockaddr_dl *)sa)->sdl_index = index;
	((struct sockaddr_dl *)sa)->sdl_type = type;
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_ADD;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
	msg.rtm.rtm_inits = RTV_EXPIRE;
	msg.rtm.rtm_flags = RTF_HOST | RTF_STATIC;
#ifdef HAVE_SOCKADDR_SA_LEN
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sin->sin_len + sa->sa_len;
#else
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin) + sizeof(*sa);
#endif
	return (arp_msg(a, &msg));
}

int
arp_delete(arp_t *a, const struct addr *pa)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;

	assert(a != NULL && pa != NULL);
	
	if (pa->addr_type != ADDR_TYPE_IP) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);

	if (addr_ntos(pa, (struct sockaddr *)sin) < 0)
		return (-1);

	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(a, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < sizeof(msg.rtm) + sizeof(*sin) + sizeof(*sa)) {
		errno = ESRCH;
		return (-1);
	}
	if (sin->sin_addr.s_addr == pa->addr_ip) {
		if ((msg.rtm.rtm_flags & RTF_LLINFO) == 0 ||
		    (msg.rtm.rtm_flags & RTF_GATEWAY) != 0) {
			errno = EADDRINUSE;
			return (-1);
		}
	}
	if (sa->sa_family != AF_LINK) {
		errno = ESRCH;
		return (-1);
	}
	msg.rtm.rtm_type = RTM_DELETE;
	
	return (arp_msg(a, &msg));
}

int
arp_get(arp_t *a, const struct addr *pa, struct addr *ha)
{
	struct arpmsg msg;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	
	assert(a != NULL && pa != NULL && ha != NULL);
	
	if (pa->addr_type != ADDR_TYPE_IP) {
		errno = EAFNOSUPPORT;
		return (-1);
	}
	sin = (struct sockaddr_in *)msg.addrs;
	sa = (struct sockaddr *)(sin + 1);
	
	if (addr_ntos(pa, (struct sockaddr *)sin) < 0)
		return (-1);
	
	memset(&msg.rtm, 0, sizeof(msg.rtm));
	msg.rtm.rtm_type = RTM_GET;
	msg.rtm.rtm_addrs = RTA_DST;
	msg.rtm.rtm_flags = RTF_LLINFO;
	msg.rtm.rtm_msglen = sizeof(msg.rtm) + sizeof(*sin);
	
	if (arp_msg(a, &msg) < 0)
		return (-1);
	
	if (msg.rtm.rtm_msglen < sizeof(msg.rtm) + sizeof(*sin) + sizeof(*sa) ||
	    sin->sin_addr.s_addr != pa->addr_ip || sa->sa_family != AF_LINK) {
		errno = ESRCH;
		return (-1);
	}
	if (addr_ston(sa, ha) < 0)
		return (-1);
	
	return (0);
}

#ifdef HAVE_SYS_SYSCTL_H
int
arp_loop(arp_t *a, arp_handler callback, void *arg)
{
	struct rt_msghdr *rtm;
	struct sockaddr_in *sin;
	struct sockaddr *sa;
	struct addr ip, mac;
	char *buf, *lim, *next;
	size_t len;
	int ret, mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET,
			    NET_RT_FLAGS, RTF_LLINFO };

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (-1);

	if (len == 0 || (buf = malloc(len)) == NULL)
		return (-1);

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
	lim = buf + len;
	ret = 0;
	
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sin = (struct sockaddr_in *)(rtm + 1);
		sa = (struct sockaddr *)(sin + 1);
		
		if (addr_ston((struct sockaddr *)sin, &ip) < 0 ||
		    addr_ston(sa, &mac) < 0)
			continue;
		
		if ((ret = callback(&ip, &mac, arg)) != 0)
			break;
	}
	free(buf);
	
	return (ret);
}
#else
int
arp_loop(arp_t *a, arp_handler callback, void *arg)
{
	errno = ENOSYS;
	return (-1);
}
#endif

int
arp_close(arp_t *a)
{
	assert(a != NULL);
	
	if (close(a->fd) < 0)
		return (-1);
	
	free(a);
	return (0);
}

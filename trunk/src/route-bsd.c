/*
 * route-bsd.c
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 * Copyright (c) 1999 Masaki Hirabaru <masaki@merit.edu>
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
#ifdef HAVE_SOLARIS_DEV_IP
#include <sys/stream.h>
#include <sys/tihdr.h>
#include <sys/tiuser.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#undef IP_ADDR_LEN
#endif
#include <net/route.h>
#include <netinet/in.h>

#ifdef HAVE_SOLARIS_DEV_IP
#include <fcntl.h>
#include <stropts.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet.h"

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

struct route_handle {
	int	fd;
	pid_t	pid;
	int	seq;
#ifdef HAVE_SOLARIS_DEV_IP
	int	ip_fd;
#endif
};

static int
route_msg(route_t *r, int type, u_char *buf, int buflen,
    struct addr *dst, struct addr *gw)
{
	struct rt_msghdr *rtm;
	struct sockaddr *sa;
	int len;

	if (buflen < sizeof(*rtm) + (3 * sizeof(*sa))) {
		errno = ENOBUFS;
		return (-1);
	}
	memset(buf, 0, buflen);
	
	rtm = (struct rt_msghdr *)buf;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = type;
	rtm->rtm_flags = RTF_UP;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = r->pid;
	rtm->rtm_seq = ++r->seq;

	/* Destination */
	sa = (struct sockaddr *)(rtm + 1);
	if (addr_ntos(dst, sa) < 0)
		return (-1);
#ifdef HAVE_SOCKADDR_SA_LEN
	sa = (struct sockaddr *)((u_char *)sa + ROUNDUP(sa->sa_len));
#else
	sa = (struct sockaddr *)((u_char *)sa + sizeof(struct sockaddr_in));
#endif
	/* Gateway */
	if (type != RTM_GET && gw != NULL) {
		rtm->rtm_flags |= RTF_GATEWAY;
		rtm->rtm_addrs |= RTA_GATEWAY;
		if (addr_ntos(gw, sa) < 0)
			return (-1);
#ifdef HAVE_SOCKADDR_SA_LEN
		sa = (struct sockaddr *)((u_char *)sa + ROUNDUP(sa->sa_len));
#else
		sa = (struct sockaddr *)((u_char *)sa +
		    sizeof(struct sockaddr_in));
#endif
	}
	/* Netmask */
	if (dst->addr_ip == IP_ADDR_ANY || dst->addr_bits < IP_ADDR_BITS) {
		rtm->rtm_addrs |= RTA_NETMASK;
		if (addr_btos(dst->addr_bits, sa) < 0)
			return (-1);
#ifdef HAVE_SOCKADDR_SA_LEN
		sa = (struct sockaddr *)((u_char *)sa + ROUNDUP(sa->sa_len));
#else
		sa = (struct sockaddr *)((u_char *)sa +
		    sizeof(struct sockaddr_in));
#endif
	} else
		rtm->rtm_flags |= RTF_HOST;
	
	rtm->rtm_msglen = (u_char *)sa - buf;
	
	if (write(r->fd, buf, rtm->rtm_msglen) < 0)
		return (-1);

	while ((len = read(r->fd, buf, buflen)) != -1) {
		if (len < sizeof(*rtm))
			return (-1);
		
		if (rtm->rtm_type == type &&
		    rtm->rtm_pid == r->pid &&
		    rtm->rtm_seq == r->seq) {
			if (rtm->rtm_errno) {
				errno = rtm->rtm_errno;
				return (-1);
			}
			break;
		}
	}
	if (type == RTM_GET && rtm->rtm_addrs & (RTA_DST|RTA_GATEWAY)){
		sa = (struct sockaddr *)(rtm + 1);
#ifdef HAVE_SOCKADDR_SA_LEN
		sa = (struct sockaddr *)((u_char *)sa + ROUNDUP(sa->sa_len));
#else
		sa = (struct sockaddr *)((u_char *)sa + sizeof(struct sockaddr_in));
#endif
		if (addr_ston(sa, gw) < 0)
			return (-1);

		if (gw->addr_type != ADDR_TYPE_IP) {
			errno = EINVAL;
			return (-1);
		}
	}
	return (0);
}

route_t *
route_open(void)
{
	route_t *r;
	
	if ((r = malloc(sizeof(*r))) == NULL)
		return (NULL);
	
	if ((r->fd = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		free(r);
		return (NULL);
	}
#ifdef HAVE_SOLARIS_DEV_IP
	if ((r->ip_fd = open(IP_DEV_NAME, O_RDWR)) < 0) {
		close(r->fd);
		free(r);
		return (NULL);
	}
#endif
	r->pid = getpid();
	r->seq = 0;
	
	return (r);
}

int
route_add(route_t *r, struct addr *dst, struct addr *gw)
{
	u_char buf[BUFSIZ];

	if (dst == NULL || gw == NULL) {
		errno = EDESTADDRREQ;
		return (-1);
	}
	if (route_msg(r, RTM_ADD, buf, sizeof(buf), dst, gw) < 0)
		return (-1);
	
	return (0);
}

int
route_delete(route_t *r, struct addr *dst)
{
	struct addr gw;
	u_char buf[BUFSIZ];
	
	if (dst == NULL) {
		errno = EDESTADDRREQ;
		return (-1);
	}
	if (route_get(r, dst, &gw) < 0)
		return (-1);
	
	if (route_msg(r, RTM_DELETE, buf, sizeof(buf), dst, &gw) < 0)
		return (-1);
	
	return (0);
}

int
route_get(route_t *r, struct addr *dst, struct addr *gw)
{
	u_char buf[BUFSIZ];
	
	if (dst == NULL) {
		errno = EDESTADDRREQ;
		return (-1);
	} else if (gw == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (route_msg(r, RTM_GET, buf, sizeof(buf), dst, gw) < 0)
		return (-1);
	
	return (0);
}

#ifdef HAVE_SYS_SYSCTL_H
int
route_loop(route_t *r, route_handler callback, void *arg)
{
	struct rt_msghdr *rtm;
	struct addr dst, gw;
	struct sockaddr *sa;
	char *buf, *lim, *next;
	size_t len;
	int ret, mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return (-1);

	if (len == 0)
		return (0);
	
	if ((buf = malloc(len)) == NULL)
		return (-1);
	
	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		free(buf);
		return (-1);
	}
	lim = buf + len;
	ret = 0;
	
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sa = (struct sockaddr *)(rtm + 1);

		if (addr_ston(sa, &dst) < 0 ||
		    (rtm->rtm_addrs & RTA_GATEWAY) == 0)
			continue;

#ifdef HAVE_SOCKADDR_SA_LEN
		sa = (struct sockaddr *)((u_char *)sa + ROUNDUP(sa->sa_len));
#else
		sa = (struct sockaddr *)((u_char *)sa +
		    sizeof(struct sockaddr_in));
#endif
		if (addr_ston(sa, &gw) < 0)
			continue;

		if (dst.addr_type != ADDR_TYPE_IP ||
		    gw.addr_type != ADDR_TYPE_IP)
			continue;
		
		if (rtm->rtm_addrs & RTA_NETMASK) {
#ifdef HAVE_SOCKADDR_SA_LEN
			sa = (struct sockaddr *)((u_char *)sa +
			    ROUNDUP(sa->sa_len));
#else
			sa = (struct sockaddr *)((u_char *)sa +
			    sizeof(struct sockaddr_in));
#endif
			if (addr_stob(sa, &dst.addr_bits) < 0)
				continue;
		}
		if ((ret = callback(&dst, &gw, arg)) != 0)
			break;
	}
	free(buf);
	
	return (ret);
}
#elif defined(HAVE_SOLARIS_DEV_IP)

#ifdef IRE_DEFAULT		/* This means Solaris 5.6 */
/* I'm not sure if they are compatible, though -- masaki */
#define IRE_ROUTE IRE_CACHE
#define IRE_ROUTE_REDIRECT IRE_HOST_REDIRECT
#endif /* IRE_DEFAULT */

int
route_loop(route_t *r, route_handler callback, void *arg)
{
	struct strbuf msg;
	struct T_optmgmt_req *tor;
	struct T_optmgmt_ack *toa;
	struct T_error_ack *tea;
	struct opthdr *opt;
	mib2_ipRouteEntry_t *rt, *rtend;
	u_char buf[8192];
	int flags, rc, rtable, ret;

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
	
	if (putmsg(r->ip_fd, &msg, NULL, 0) < 0)
		return (-1);
	
	opt = (struct opthdr *)(toa + 1);
	msg.maxlen = sizeof(buf);
	
	for (;;) {
		flags = 0;
		if ((rc = getmsg(r->ip_fd, &msg, NULL, &flags)) < 0)
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
		
		rtable = (opt->level == MIB2_IP && opt->name == MIB2_IP_21);
		
		msg.maxlen = sizeof(buf) - (sizeof(buf) % sizeof(*rt));
		msg.len = 0;
		flags = 0;
		
		do {
			struct sockaddr_in sin;
			struct addr dst, gw;
			
			rc = getmsg(r->ip_fd, NULL, &msg, &flags);
			
			if (rc != 0 && rc != MOREDATA)
				return (-1);
			
			if (!rtable)
				continue;
			
			rt = (mib2_ipRouteEntry_t *)msg.buf;
			rtend = (mib2_ipRouteEntry_t *)(msg.buf + msg.len);

			sin.sin_family = AF_INET;

			for ( ; rt < rtend; rt++) {
				if ((rt->ipRouteInfo.re_ire_type &
				    (IRE_BROADCAST|IRE_ROUTE_REDIRECT|
					IRE_LOCAL|IRE_ROUTE)) != 0 ||
				    rt->ipRouteNextHop == IP_ADDR_ANY)
					continue;

				sin.sin_addr.s_addr = rt->ipRouteNextHop;
				addr_ston((struct sockaddr *)&sin, &gw);
				
				sin.sin_addr.s_addr = rt->ipRouteDest;
				addr_ston((struct sockaddr *)&sin, &dst);
				
				sin.sin_addr.s_addr = rt->ipRouteMask;
				addr_stob((struct sockaddr *)&sin,
				    &dst.addr_bits);
				
				if ((ret = callback(&dst, &gw, arg)) != 0)
					return (ret);
			}
		} while (rc == MOREDATA);
	}
	return (0);
}
#else
int
route_loop(route_t *r, route_handler callback, void *arg)
{
	errno = EOPNOTSUPP;
	return (-1);
}
#endif

int
route_close(route_t *r)
{
	if (r == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (
#ifdef HAVE_SOLARIS_DEV_IP
		close(r->ip_fd) < 0 ||
#endif
		close(r->fd) < 0)
		return (-1);
	
	free(r);
	return (0);
}

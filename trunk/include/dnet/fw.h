/*
 * fw.h
 *
 * Network firewalling operations.
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_FW_H
#define DNET_FW_H

struct fw_rule {
	char		device[14];	/* interface name */
	u_char		op:4,		/* operation */
			direction:4;	/* direction */
	u_char		proto;		/* IP protocol */
	struct addr	src;		/* src address / net */
	struct addr	dst;		/* dst address / net */
	u_short		sport[2];	/* range or ICMP type / mask */
	u_short		dport[2];	/* range or ICMP code / mask */
};

#define FW_OP_ALLOW	1
#define FW_OP_BLOCK	2

#define FW_DIR_IN	1
#define FW_DIR_OUT	2

typedef struct fw_handle fw_t;

typedef int (*fw_handler)(struct fw_rule *rule, void *arg);

fw_t	*fw_open(void);
int	 fw_add(fw_t *f, struct fw_rule *rule);
int	 fw_delete(fw_t *f, struct fw_rule *rule);
int	 fw_loop(fw_t *f, fw_handler callback, void *arg);
int	 fw_close(fw_t *f);

#define fw_fill_rule(h, dev, op, dir, p, src, dst, sp1, sp2, dp1, dp2)	\
do {									\
	struct fw_rule *fw_fill_p = (struct fw_rule *)(h);		\
	strlcpy(fw_fill_p->device, device, sizeof(fw_fill_p->device));	\
	fw_fill_p->op = op; fw_fill_p->direction = dir;			\
	fw_fill_p->proto = p;						\
	memset(&fw_fill_p->src, src, sizeof(&fw_fill_p->src));		\
	memset(&fw_fill_p->dst, dst, sizeof(&fw_fill_p->dst));		\
	fw_fill_p->sport[0] = sp1; fw_fill_p->sport[1] = sp2;		\
	fw_fill_p->dport[0] = dp1; fw_fill_p->dport[1] = dp2;		\
} while (0)
 
#endif /* DNET_FW_H */

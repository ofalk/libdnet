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

#ifdef __cplusplus
extern "C" {
#endif
	
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

#define fw_fill_rule(rule, dev, op, dir, p, src, dst, sp1, sp2, dp1, dp2) \
do {									\
	strlcpy((rule)->device, device, sizeof((rule)->device));	\
	(rule)->op = op; (rule)->direction = dir;			\
	(rule)->proto = p;						\
	memset(&(rule)->src, src, sizeof(&(rule)->src));		\
	memset(&(rule)->dst, dst, sizeof(&(rule)->dst));		\
	(rule)->sport[0] = sp1; (rule)->sport[1] = sp2;			\
	(rule)->dport[0] = dp1; (rule)->dport[1] = dp2;			\
} while (0)

#ifdef __cplusplus
}
#endif

#endif /* DNET_FW_H */

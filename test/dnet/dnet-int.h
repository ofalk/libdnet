/*
 * dnet-int.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_INT_H
#define DNET_INT_H

void	eth_usage(int die);
int	eth_main(int argc, char *argv[]);

void	arp_usage(int die);
int	arp_main(int argc, char *argv[]);

void	ip_usage(int die);
int	ip_main(int argc, char *argv[]);

void	icmp_usage(int die);
int	icmp_main(int argc, char *argv[]);

void	tcp_usage(int die);
int	tcp_main(int argc, char *argv[]);

void	udp_usage(int die);
int	udp_main(int argc, char *argv[]);

#endif /* DNET_INT_H */

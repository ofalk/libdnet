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

void	addr_usage(int die);
int	addr_main(int argc, char *argv[]);

void	hex_usage(int die);
int	hex_main(int argc, char *argv[]);

void	send_usage(int die);
int	send_main(int argc, char *argv[]);

int	type_aton(char *string, uint16_t *type);
int	op_aton(char *string, uint16_t *op);
int	proto_aton(char *string, uint8_t *proto);
int	off_aton(char *string, uint16_t *off);
int	port_aton(char *string, uint16_t *port);
int	seq_aton(char *string, uint32_t *seq);
int	flags_aton(char *string, uint8_t *flags);
int	fmt_aton(char *string, u_char *buf);

#endif /* DNET_INT_H */

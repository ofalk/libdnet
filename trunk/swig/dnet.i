//
// dnet.i
//
// Copyright (c) 2003 Dug Song <dugsong@monkey.org>
//
// $Id$

%module dnet

%{
#include <sys/types.h>
#include <dnet.h>
%}

#include "cstring.i"

// XXX
typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;

// Typemaps for opaque blobs
%apply(char *STRING, int LENGTH) { (char *buf1, int len1) };
%apply(char *STRING, int LENGTH) { (char *buf2, int len2) };
%apply(char *STRING, int LENGTH) { (char *buf3, int len3) };
%apply(char *STRING, int LENGTH) { (char *buf4, int len4) };
%cstring_output_allocate_size(char **dstp, int *dlenp, free(*$1));

#ifdef SWIGPYTHON
// Handle for Python callbacks
%inline %{
struct cb_handle {
	PyObject	*func;
	PyObject	*arg;
};
%}
#endif

//
// addr.h
//
#define ADDR_TYPE_NONE		0	/* No address set */
#define	ADDR_TYPE_ETH		1	/* Ethernet */
#define	ADDR_TYPE_IP		2	/* Internet Protocol v4 */
#define	ADDR_TYPE_IP6		3	/* Internet Protocol v6 */

struct addr {
	uint16_t		addr_type;
	uint16_t		addr_bits;
	// XXX - how to provide direct access to addr_{ip,eth,ip6,...} ?
%extend {
	addr() {
		return ((struct addr *)calloc(1, sizeof(struct addr)));
	}
	addr(char *addrtxt) {
		struct addr *a = calloc(1, sizeof(*a));
		if (addr_aton(addrtxt, a) < 0) {
			free(a);
			a = NULL;
		}
		return (a);
	}
	// XXX - how to get a = dnet.addr(); b = a; to work correctly?
	~addr() {
		free(self);
	}
	%name(aton) void __aton(char *addrtxt) {
		addr_aton(addrtxt, self);
	}
	%name(ntoa) char *__ntoa() {
		return (addr_ntoa(self));
	}
	char *__str__() {
		static char str[256];
		snprintf(str, sizeof(str), "<addr object, type=%d, bits=%d>",
		    self->addr_type, self->addr_bits);
		return (str);
	}
}
};

//
// arp.h
//
#define ARP_HDR_LEN	8	/* base ARP header length */
#define ARP_ETHIP_LEN	20	/* base ARP message length */

/*
 * Hardware address format
 */
#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */

/*
 * Protocol address format
 */
#define ARP_PRO_IP	0x0800	/* IP protocol */

/*
 * ARP operation
 */
#define	ARP_OP_REQUEST		1	/* request to resolve ha given pa */
#define	ARP_OP_REPLY		2	/* response giving hardware address */
#define	ARP_OP_REVREQUEST	3	/* request to resolve pa given ha */
#define	ARP_OP_REVREPLY		4	/* response giving protocol address */

%cstring_chunk_output(char *arp_ethip, ARP_ETHIP_LEN);
%inline %{ 
void __arp_pack_hdr_ethip(char *arp_ethip, int op,
	char *sha, int shlen, char *spa, int splen, 
	char *dha, int dhlen, char *dpa, int dplen) {
	if (shlen == ETH_ADDR_LEN && dhlen == ETH_ADDR_LEN &&
	    splen == IP_ADDR_LEN && dplen == IP_ADDR_LEN)
		arp_pack_hdr_ethip(arp_ethip, op, *sha, *spa, *dha, *dpa);
}
%}
%name(arp_pack_hdr_ethip) void __arp_pack_hdr_ethip(char *arp_ethip, int op,
        char *buf1, int len1, char *buf2, int len2,
        char *buf3, int len3, char *buf4, int len4);

#ifdef SWIGPYTHON
%inline %{
int __arp_loop_cb(const struct arp_entry *entry, void *arg)
{
	struct cb_handle *cb = (struct cb_handle *)arg;
	PyObject *arglist, *result;
	
	if (PyCallable_Check(cb->func)) {
		arglist = Py_BuildValue("OOO", 
		    SWIG_NewPointerObj((void *)&entry->arp_pa, 
		    SWIGTYPE_p_addr, 1),
		    SWIG_NewPointerObj((void *)&entry->arp_ha,
		    SWIGTYPE_p_addr, 1), cb->arg);
		result = PyObject_CallObject(cb->func, arglist);
		Py_DECREF(arglist);
		if (result == NULL)
			return (-1);
		Py_DECREF(result);	
	}
	return (0);
}
%}
#endif

%name(arp) struct arp_handle {
%extend {
	arp_handle() {
		return (arp_open());
	}
	~arp_handle() {
		arp_close(self);
	}
	int add(struct addr *pa, struct addr *ha) {
		struct arp_entry entry;

		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		memcpy(&entry.arp_ha, ha, sizeof(*ha));
		return (arp_add(self, &entry));
	}
	int delete(struct addr *pa) {
		struct arp_entry entry;

		memset(&entry, 0, sizeof(entry));
		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		return (arp_delete(self, &entry));
	}
	%newobject get;
	struct addr *get(struct addr *pa) {
		struct arp_entry entry;
		struct addr *ha = NULL;

		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		if (arp_get(self, &entry) == 0) {
			ha = calloc(1, sizeof(*ha));
			memcpy(ha, &entry.arp_ha, sizeof(*ha));
		}
		return (ha);
	}
#ifdef SWIGPYTHON
	void loop(PyObject *callback, PyObject *arg) {
		struct cb_handle cb;

		cb.func = callback;
		cb.arg = arg;
		arp_loop(self, __arp_loop_cb, &cb);
	}
#endif
}
};

//
// eth.h
//
#define ETH_ADDR_LEN	6
#define ETH_ADDR_BITS	48
#define ETH_CRC_LEN	4
#define ETH_HDR_LEN	14

#define ETH_LEN_MIN	64		/* minimum frame length with CRC */
#define ETH_LEN_MAX	1518		/* maximum frame length with CRC */

#define ETH_MTU		(ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
#define ETH_MIN		(ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

/*
 * Ethernet payload types
 */
#define ETH_TYPE_IP	0x0800		/* IP protocol */
#define ETH_TYPE_ARP	0x0806		/* address resolution protocol */
#define ETH_TYPE_IPV6	0x86DD		/* IPv6 protocol */

#define ETH_ADDR_BROADCAST	"\xff\xff\xff\xff\xff\xff"

%cstring_chunk_output(char *eth_hdr, ETH_HDR_LEN);
%inline %{ 
void __eth_pack_hdr(char *eth_hdr,
	char *dst, int dlen, char *src, int slen, int type) {
	if (dlen == ETH_ADDR_LEN && slen == ETH_ADDR_LEN)
		eth_pack_hdr(eth_hdr, *dst, *src, type);
}
%}
%name(eth_pack_hdr) void __eth_pack_hdr(char *eth_hdr,
	char *buf1, int len1, char *buf2, int len2, int type);

%cstring_chunk_output(char *eth_addr, ETH_ADDR_LEN);
%name(eth) struct eth_handle {
%extend {
	eth_handle(char *buf1, int len1) {
		return (eth_open(buf1));
	}
	~eth_handle() {
		eth_close(self);
	}
	void get(char *eth_addr) {
		eth_get(self, (eth_addr_t *)eth_addr);
	}
	int set(char *buf1, int len1) {
		if (len1 == ETH_ADDR_LEN)
			return (eth_set(self, (eth_addr_t *)buf1));
		return (-1);
	}
	int send(char *buf1, int len1) {
		return (eth_send(self, buf1, len1));
	}
}
};

//
// fw.h
//
#define FW_OP_ALLOW	1
#define FW_OP_BLOCK	2

#define FW_DIR_IN	1
#define FW_DIR_OUT	2

%inline %{ 
struct fw_rule *__fw_pack_rule(char *dev, int op, int dir, int p, 
	struct addr *src, struct addr *dst, 
	int sp1, int sp2, int dp1, int dp2) {
	struct fw_rule *rule = malloc(sizeof(*rule));
	fw_pack_rule(rule, dev, op, dir, p, *src, *dst, sp1, sp2, dp1, dp2);
	return (rule);
}
%}
%newobject fw_pack_rule;
%name(fw_pack_rule) struct fw_rule *__fw_pack_rule(char *dev, int op,
	int dir, int p, struct addr *src, struct addr *dst, 
	int sp1, int sp2, int dp1, int dp2);

%name(fw) struct fw_handle {
%extend {
	fw_handle() {
		return (fw_open());
	}
	~fw_handle() {
		fw_close(self);
	}
	int add(struct fw_rule *rule) {
		return (fw_add(self, rule));
	}
	int delete(struct fw_rule *rule) {
		return (fw_delete(self, rule));
	}
}
};

//
// icmp.h
//
%cstring_chunk_output(char *icmp_hdr, ICMP_HDR_LEN);
%inline %{
void __icmp_pack_hdr(char *icmp_hdr, int type, int code) {
	icmp_pack_hdr(icmp_hdr, type, code);
}
void __icmp_pack_hdr_echo(char **dstp, int *dlenp, int type, int code,
	int id, int seq, char *src, int slen) {
	*dlenp = ICMP_LEN_MIN + slen;
        *dstp = malloc(*dlenp);
	icmp_pack_hdr_echo(*dstp, type, code, id, seq, src, slen);
}
%}
%name(icmp_pack_hdr) void __icmp_pack_hdr(char *icmp_hdr, int type, int code);
%name(icmp_pack_hdr_echo) void __icmp_pack_hdr_echo(char **dstp, int *dlenp,
	int type, int code, int id, int seq, char *buf1, int len1);

//
// ip.h
//
#define IP_ADDR_LEN	4		/* IP address length */
#define IP_ADDR_BITS	32		/* IP address bits */

#define IP_HDR_LEN	20		/* base IP header length */
#define IP_OPT_LEN	2		/* base IP option length */
#define IP_OPT_LEN_MAX	40
#define IP_HDR_LEN_MAX	(IP_HDR_LEN + IP_OPT_LEN_MAX)

#define IP_LEN_MAX	65535
#define IP_LEN_MIN	IP_HDR_LEN

/*
 * Fragmentation flags (ip_off)
 */
#define IP_RF		0x8000		/* reserved */
#define IP_DF		0x4000		/* don't fragment */
#define IP_MF		0x2000		/* more fragments (not last frag) */
#define IP_OFFMASK	0x1fff		/* mask for fragment offset */

/*
 * Time-to-live (ip_ttl), seconds
 */
#define IP_TTL_DEFAULT	64		/* default ttl, RFC 1122, RFC 1340 */
#define IP_TTL_MAX	255		/* maximum ttl */

/*
 * Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
 */
#define	IP_PROTO_IP		0		/* dummy for IP */
#define	IP_PROTO_ICMP		1		/* ICMP */
#define	IP_PROTO_IGMP		2		/* IGMP */
#define	IP_PROTO_TCP		6		/* TCP */
#define	IP_PROTO_UDP		17		/* UDP */
#define IP_PROTO_IPV6		41		/* IPv6 */
#define IP_PROTO_ROUTING	43		/* IPv6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#define IP_PROTO_ICMPV6		58		/* ICMP for IPv6 */
#define IP_PROTO_NONE		59		/* IPv6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IPv6 destination options */
#define	IP_PROTO_RAW		255		/* Raw IP packets */
#define IP_PROTO_RESERVED	IP_PROTO_RAW	/* Reserved */
#define	IP_PROTO_MAX		255

/*
 * Reserved addresses
 */
#define IP_ADDR_ANY		"\x00\x00\x00\x00"	/* 0.0.0.0 */
#define IP_ADDR_BROADCAST	"\xff\xff\xff\xff"	/* 255.255.255.255 */
#define IP_ADDR_LOOPBACK	"\x7f\x00\x00\x01"	/* 127.0.0.1 */
#define IP_ADDR_MCAST_ALL	"\xe0\x00\x00\x01"	/* 224.0.0.1 */
#define IP_ADDR_MCAST_LOCAL	"\xe0\x00\x00\xff"	/* 224.0.0.225 */

%cstring_chunk_output(char *ip_hdr, IP_HDR_LEN);
%cstring_chunk_output(char *ip_addr, IP_ADDR_LEN);
%inline %{ 
void __ip_pack_hdr(char *ip_hdr,
	int tos, int len, int id, int off, int ttl, int p,
	char *src, int slen, char *dst, int dlen) {
	if (slen == IP_ADDR_LEN && dlen == IP_ADDR_LEN)
		ip_pack_hdr(ip_hdr, tos, len, id, off, ttl, p, 
		    *(uint32_t *)src, *(uint32_t *)dst);
}
void __ip_aton(char *buf, char *ip_addr) {
	ip_aton(buf, (ip_addr_t *)ip_addr);
}
char *__ip_ntoa(char *buf1, int len1) {
	if (len1 != IP_ADDR_LEN)
		return (NULL);
	return (ip_ntoa((ip_addr_t *)buf1));
}
void __ip_checksum(char **dstp, int *dlenp, char *src, int slen) {
	*dstp = malloc(slen); *dlenp = slen;
	memcpy(*dstp, src, *dlenp);
	ip_checksum(*dstp, *dlenp);
}
%}
%name(ip_pack_hdr) void __ip_pack_hdr(char *ip_hdr,
	int tos, int len, int id, int off, int ttl, int p,
	char *buf1, int len1, char *buf2, int len2);
%name(ip_aton) void __ip_aton(char *buf, char *ip_addr);
%name(ip_ntoa) char *__ip_ntoa(char *buf1, int len1);
%name(ip_checksum) void __ip_checksum(char **dstp, int *dlenp,
	char *buf1, int len1);

%name(ip) struct ip_handle {
%extend {
	ip_handle() {
		return (ip_open());
	}
	~ip_handle() {
		ip_close(self);
	}
	int send(char *buf1, int len1) {
		return (ip_send(self, buf1, len1));
	}
}
};

//
// route.h
//
#ifdef SWIGPYTHON
%inline %{
int __route_loop_cb(const struct route_entry *entry, void *arg)
{
	struct cb_handle *cb = (struct cb_handle *)arg;
	PyObject *arglist, *result;
	
	if (PyCallable_Check(cb->func)) {
		arglist = Py_BuildValue("OOO", 
		    SWIG_NewPointerObj((void *)&entry->route_dst, 
		    SWIGTYPE_p_addr, 1),
		    SWIG_NewPointerObj((void *)&entry->route_gw,
		    SWIGTYPE_p_addr, 1), cb->arg);
		result = PyObject_CallObject(cb->func, arglist);
		Py_DECREF(arglist);
		if (result == NULL)
			return (-1);
		Py_DECREF(result);	
	}
	return (0);
}
%}
#endif

%name(route) struct route_handle {
%extend  {
	route_handle() {
		return (route_open());
	}
	~route_handle() {
		route_close(self);
	}
	int add(struct addr *dst, struct addr *gw) {
		struct route_entry entry;

		memcpy(&entry.route_dst, dst, sizeof(*dst));
		memcpy(&entry.route_gw, gw, sizeof(*gw));
		return (route_add(self, &entry));
	}
	int delete(struct addr *dst) {
		struct route_entry entry;

		memset(&entry, 0, sizeof(entry));
		memcpy(&entry.route_dst, dst, sizeof(*dst));
		return (route_delete(self, &entry));
	}
	%newobject get;
	struct addr *get(struct addr *dst) {
		struct route_entry entry;
		struct addr *gw = NULL;

		memcpy(&entry.route_dst, dst, sizeof(*dst));
		if (route_get(self, &entry) == 0) {
			gw = calloc(1, sizeof(*gw));
			memcpy(gw, &entry.route_gw, sizeof(*gw));
		}
		return (gw);
	}
#ifdef SWIGPYTHON
	void loop(PyObject *callback, PyObject *arg) {
		struct cb_handle cb;

		cb.func = callback;
		cb.arg = arg;
		route_loop(self, __route_loop_cb, &cb);
	}
#endif
}
};


/* -*- fundamental -*-
 *
 * dnet.i
 *
 * Copyright (c) 2003 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

%module dnet

// XXX - audit %newobject - diff

%{
#include <sys/types.h>
#include <dnet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
%}

%include "cstring.i"
%include "exception.i"

typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;

/* Typemaps for opaque blobs */
%apply(char *STRING, int LENGTH) { (char *buf1, int len1) };
%apply(char *STRING, int LENGTH) { (char *buf2, int len2) };
%apply(char *STRING, int LENGTH) { (char *buf3, int len3) };
%apply(char *STRING, int LENGTH) { (char *buf4, int len4) };
%cstring_output_allocate_size(char **dstp, int *dlenp, free(*$1));

#ifdef SWIGPYTHON
/* Python callback handle */
%{
struct cb_handle {
	PyObject	*func;
	PyObject	*arg;
};
%}
#endif

/* Exception handling */
%{
static char		_dnet_errmsg[256];
static int		_dnet_errcode = 0;

static void
dnet_exception(int code, const char *fmt, ...)
{
	va_list ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		vsnprintf(_dnet_errmsg, sizeof(_dnet_errmsg), fmt, ap);
		va_end(ap);
	} else {
		strncpy(_dnet_errmsg, strerror(errno), 
		    sizeof(_dnet_errmsg) - 1);
		_dnet_errmsg[sizeof(_dnet_errmsg) - 1] = '\0';
	}
	_dnet_errcode = code;
}
%}

%exception {
	$action
	if (_dnet_errcode != 0) {
		int code = _dnet_errcode;
		_dnet_errcode = 0;
		SWIG_exception(code, _dnet_errmsg);
		return (NULL);
	}
}

/*
 * addr.h
 */
#define ADDR_TYPE_NONE		0	/* No address set */

#define	ADDR_TYPE_ETH		1	/* Ethernet */
#define	ADDR_TYPE_IP		2	/* Internet Protocol v4 */
#define	ADDR_TYPE_IP6		3	/* Internet Protocol v6 */

#ifdef SWIGPYTHON
/* Helper routines for addr_{eth,ip,ip6} members */
%{
	static PyObject *__addr_data_get(struct addr *a, int type, int len) {
		if (a->addr_type != type) {
			dnet_exception(SWIG_TypeError, "address type is %d",
				a->addr_type);
			return (NULL);
		}
		return (PyString_FromStringAndSize(a->addr_data8, len));
	}
	static void __addr_data_set(struct addr *a, PyObject *obj, int len) {
		char *p;
		int n;

		if (PyArg_Parse(obj, "s#:addr_data_set", &p, &n) && n == len) {
			memcpy(a->addr_data8, p, len);
		} else
			dnet_exception(SWIG_ValueError, "expected %d-byte "
			    "binary string", len);
	}
	static PyObject *addr_eth_get(struct addr *a) {
		return (__addr_data_get(a, ADDR_TYPE_ETH, ETH_ADDR_LEN));
	}
	static void addr_eth_set(struct addr *a, PyObject *obj) {
		__addr_data_set(a, obj, ETH_ADDR_LEN);
	}
	static PyObject *addr_ip_get(struct addr *a) {
		return (__addr_data_get(a, ADDR_TYPE_IP, IP_ADDR_LEN));
	}
	static void addr_ip_set(struct addr *a, PyObject *obj) {
		__addr_data_set(a, obj, IP_ADDR_LEN);
	}
	static PyObject *addr_ip6_get(struct addr *a) {
		return (__addr_data_get(a, ADDR_TYPE_IP6, IP6_ADDR_LEN));
	}
	static void addr_ip6_set(struct addr *a, PyObject *obj) {
		__addr_data_set(a, obj, IP6_ADDR_LEN);
	}
%}
#endif /* SWIGPYTHON */

struct addr {
	%name(type) uint16_t	addr_type;
	%name(bits) uint16_t	addr_bits;
%extend {
#ifdef SWIGPYTHON
	PyObject		*eth;
	PyObject		*ip;
	PyObject		*ip6;
#endif
	addr(void) {
		return ((struct addr *)calloc(1, sizeof(struct addr)));
	}
	addr(char *addrtxt) {
		struct addr *a = calloc(1, sizeof(*a));
		if (addr_aton(addrtxt, a) < 0) {
			free(a), a = NULL;
			dnet_exception(SWIG_ValueError, NULL);
		}
		return (a);
	}
	~addr(void) {
		free(self);
	}
	%newobject bcast;
	%name(bcast) struct addr *__bcast(void) {
		struct addr *a = malloc(sizeof(*a));

		if (addr_bcast(self, a) < 0) {
			free(a), a = NULL;
			dnet_exception(SWIG_RuntimeError, NULL);
		}
		return (a);
	}
	%newobject net;
	%name(net) struct addr *__net(void) {
		struct addr *a = malloc(sizeof(*a));

		if (addr_net(self, a) < 0) {
			free(a), a = NULL;
			dnet_exception(SWIG_RuntimeError, NULL);
		}
		return (a);
	}
#ifdef SWIGPYTHON
	int __cmp__(struct addr *other) {
		return (other != NULL ? addr_cmp(self, other) : 1);
	}
	int __contains__(struct addr *other) {
		struct addr s1, s2, o1, o2;

		if (addr_net(self, &s1) != 0 || addr_bcast(self, &s2) != 0 ||
		    addr_net(other, &o1) != 0 || addr_bcast(other, &o2) != 0)
			return (0);
		return (addr_cmp(&o1, &s1) >= 0 && addr_cmp(&o2, &s2) <= 0);
	}
	long __len__(void) {
		long len = 0;
		
		// XXX - only handle IPv4 now, also need to handle > MAXINT
		if (self->addr_type == ADDR_TYPE_IP) {
			len = pow(2, IP_ADDR_BITS - self->addr_bits);
		} else if (self->addr_type == ADDR_TYPE_ETH ||
		    self->addr_type == ADDR_TYPE_IP6) {
			len = 1;
		}
		return (len);
	}
	char *__str__(void) {
		return (addr_ntoa(self));
	}
#endif /* SWIGPYTHON */
}
};

/*
 * eth.h
 */
#define ETH_ADDR_LEN	6
#define ETH_ADDR_BITS	48
#define ETH_CRC_LEN	4
#define ETH_HDR_LEN	14

#define ETH_LEN_MIN	64		/* minimum frame length with CRC */
#define ETH_LEN_MAX	1518		/* maximum frame length with CRC */

#define ETH_MTU		(ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
#define ETH_MIN		(ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)

#define ETH_TYPE_IP	0x0800		/* IP protocol */
#define ETH_TYPE_ARP	0x0806		/* address resolution protocol */
#define ETH_TYPE_IPV6	0x86DD		/* IPv6 protocol */

#ifdef SWIGPYTHON
%pythoncode %{
ETH_ADDR_BROADCAST =	"\xff\xff\xff\xff\xff\xff"
%}
#endif

%cstring_chunk_output(char *eth_hdr, ETH_HDR_LEN);
%cstring_chunk_output(char *eth_addr, ETH_ADDR_LEN);

%inline %{
void __eth_pack_hdr(char *eth_hdr,
	char *buf1, int len1, char *buf2, int len2, int type) {
	if (len1 == ETH_ADDR_LEN && len2 == ETH_ADDR_LEN) {
		eth_pack_hdr(eth_hdr, *buf1, *buf2, type);
	} else
		dnet_exception(SWIG_ValueError, "invalid MAC addresses");
}
void __eth_aton(char *buf, char *eth_addr) {
	if (eth_aton(buf, (eth_addr_t *)eth_addr) < 0)
		dnet_exception(SWIG_RuntimeError, NULL);
}
char *__eth_ntoa(char *buf1, int len1) {
	if (len1 != ETH_ADDR_LEN) {
		dnet_exception(SWIG_ValueError, 
		    "expected 6-byte binary string");
		return (NULL);
	}
	return (eth_ntoa((eth_addr_t *)buf1));
}
%}
#ifdef SWIGPYTHON
%pythoncode %{
def eth_pack_hdr(dst=ETH_ADDR_BROADCAST, src=ETH_ADDR_BROADCAST, type=ETH_TYPE_IP):
	"""Return a packed binary string representing an Ethernet header."""
	return _dnet.__eth_pack_hdr(dst, src, type)

def eth_aton(string):
	"""Convert an Ethernet MAC address from a printable string to a
	packed binary string ('\\x00\\xde\\xad\\xbe\\xef\\x00')."""
	return _dnet.__eth_aton(string)

def eth_ntoa(eth_addr_string):
	"""Convert an Ethernet MAC address from 6-byte packed binary string to
	a printable string ('00:de:ad:be:ef:00')."""
	return _dnet.__eth_ntoa(eth_addr)

%}
#else
%name(eth_pack_hdr) void __eth_pack_hdr(char *eth_hdr, char *buf1, int len1,
	char *buf2, int len2, int type);
%name(eth_aton) void __eth_aton(char *buf, char *eth_addr);
%name(eth_ntoa) char *__eth_ntoa(char *buf1, int len1);
#endif

%name(eth) struct eth_handle {
%extend {
	eth_handle(char *buf1, int len1) {
		eth_t *eth = eth_open(buf1);
		if (eth == NULL)
			dnet_exception(SWIG_RuntimeError, NULL);
		return (eth);
	}
	~eth_handle(void) {
		eth_close(self);
	}
	void get(char *eth_addr) {
		if (eth_get(self, (eth_addr_t *)eth_addr) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	void set(char *buf1, int len1) {
		if (len1 != ETH_ADDR_LEN) {
			dnet_exception(SWIG_ValueError,
			    "expected a 6-byte binary string");
		} else if (eth_set(self, (eth_addr_t *)buf1) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	int send(char *buf1, int len1) {
		return (eth_send(self, buf1, len1));
	}
}
};

#if 0 // XXX - want to do this right later
/*
 * fw.h
 */
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
	fw_handle(void) {
		return (fw_open());
	}
	~fw_handle(void) {
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
#endif

/*
 * icmp.h
 */
%cstring_chunk_output(char *icmp_hdr, ICMP_HDR_LEN);

%inline %{
void __icmp_pack_hdr(char *icmp_hdr, int type, int code) {
	icmp_pack_hdr(icmp_hdr, type, code);
}
void __icmp_pack_hdr_echo(char **dstp, int *dlenp, int type, int code,
	int id, int seq, char *buf1, int len1) {
	*dlenp = ICMP_LEN_MIN + len1;
        *dstp = calloc(1, *dlenp);
	icmp_pack_hdr_echo(*dstp, type, code, id, seq, buf1, len1);
}
%}
#ifdef SWIGPYTHON
%pythoncode %{
def icmp_pack_hdr(type=8, code=0):
	"""Return a packed binary string representing an ICMP header."""
	return _dnet.__icmp_pack_hdr(type, code)

def icmp_pack_hdr_echo(type=8, code=0, id=0, seq=0, data=''):
	"""Return a packed binary string representing an ICMP echo message."""
	return _dnet.__icmp_pack_hdr_echo(type, code, id, seq, data);

%}
#else
%name(icmp_pack_hdr) void __icmp_pack_hdr(char *icmp_hdr, int type, int code);
%name(icmp_pack_hdr_echo) void __icmp_pack_hdr_echo(char **dstp, int *dlenp,
	int type, int code, int id, int seq, char *buf1, int len1);
#endif

/*
 * ip.h
 */
#define IP_ADDR_LEN	4		/* IP address length */
#define IP_ADDR_BITS	32		/* IP address bits */

#define IP_HDR_LEN	20		/* base IP header length */
#define IP_OPT_LEN	2		/* base IP option length */
#define IP_OPT_LEN_MAX	40
#define IP_HDR_LEN_MAX	(IP_HDR_LEN + IP_OPT_LEN_MAX)

#define IP_LEN_MAX	65535
#define IP_LEN_MIN	IP_HDR_LEN

#define IP_RF		0x8000		/* reserved */
#define IP_DF		0x4000		/* don't fragment */
#define IP_MF		0x2000		/* more fragments (not last frag) */
#define IP_OFFMASK	0x1fff		/* mask for fragment offset */

#define IP_TTL_DEFAULT	64		/* default ttl, RFC 1122, RFC 1340 */
#define IP_TTL_MAX	255		/* maximum ttl */

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

#ifdef SWIGPYTHON
%pythoncode %{
IP_ADDR_ANY =			"\x00\x00\x00\x00"
IP_ADDR_BROADCAST =		"\xff\xff\xff\xff"
IP_ADDR_LOOPBACK =		"\x7f\x00\x00\x01"
IP_ADDR_MCAST_ALL =		"\xe0\x00\x00\x01"
IP_ADDR_MCAST_LOCAL =		"\xe0\x00\x00\xff"
%}
#endif

%cstring_chunk_output(char *ip_hdr, IP_HDR_LEN);
%cstring_chunk_output(char *ip_addr, IP_ADDR_LEN);

%inline %{
void __ip_pack_hdr(char *ip_hdr,
	int tos, int len, int id, int off, int ttl, int p,
	char *buf1, int len1, char *buf2, int len2) {
	if (len1 == IP_ADDR_LEN && len2 == IP_ADDR_LEN)
		ip_pack_hdr(ip_hdr, tos, len, id, off, ttl, p, 
		    *(uint32_t *)buf1, *(uint32_t *)buf2);
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
#ifdef SWIGPYTHON
%pythoncode %{
def ip_pack_hdr(tos=0, len=IP_HDR_LEN, id=0, off=0, ttl=IP_TTL_DEFAULT, p=IP_PROTO_IP, src=IP_ADDR_ANY, dst=IP_ADDR_ANY):
	"""Return a packed binary string representing an IP header."""
	return _dnet.__ip_pack_hdr(tos, len, id, off, ttl, p, src, dst)

def ip_aton(string):
	"""Return a packed binary string representing an IP address."""
	return _dnet.__ip_aton(string)

def ip_ntoa(addr):
	"""Return the printable string represention of a packed IP address."""
	return _dnet.__ip_ntoa(addr)

def ip_checksum(packet):
	"Return a packed binary string representing an IP packet "
	"with the IP and transport-layer checksums set."
	return _dnet.__ip_checksum(packet)

%}
#else
%name(ip_pack_hdr) void __ip_pack_hdr(char *ip_hdr, int tos, int len, int id,
	int off, int ttl, int p, char *buf1, int len1, char *buf2, int len2);
%name(ip_aton) void __ip_aton(char *buf, char *ip_addr);
%name(ip_ntoa) char *__ip_ntoa(char *buf1, int len1);
%name(ip_checksum) void __ip_checksum(char **dstp, int *dlenp,
	char *buf1, int len1);
#endif

%name(ip) struct ip_handle {
%extend {
	ip_handle(void) {
		ip_t *ip = ip_open();
		if (ip == NULL)
			dnet_exception(SWIG_RuntimeError, NULL);
		return (ip);
	}
	~ip_handle(void) {
		ip_close(self);
	}
	int send(char *buf1, int len1) {
		return (ip_send(self, buf1, len1));
	}
}
};

/*
 * arp.h
 */
#define ARP_HDR_LEN	8	/* base ARP header length */
#define ARP_ETHIP_LEN	20	/* base ARP message length */

#define ARP_HRD_ETH 	0x0001	/* ethernet hardware */
#define ARP_HRD_IEEE802	0x0006	/* IEEE 802 hardware */

#define ARP_PRO_IP	0x0800	/* IP protocol */

#define	ARP_OP_REQUEST		1	/* request to resolve ha given pa */
#define	ARP_OP_REPLY		2	/* response giving hardware address */
#define	ARP_OP_REVREQUEST	3	/* request to resolve pa given ha */
#define	ARP_OP_REVREPLY		4	/* response giving protocol address */

%cstring_chunk_output(char *arp_ethip, ARP_HDR_LEN + ARP_ETHIP_LEN);

%inline %{ 
void __arp_pack_hdr_ethip(char *arp_ethip, int op,
        char *buf1, int len1, char *buf2, int len2,
        char *buf3, int len3, char *buf4, int len4) {
	if (len1 == ETH_ADDR_LEN && len2 == IP_ADDR_LEN &&
	    len3 == ETH_ADDR_LEN && len4 == IP_ADDR_LEN) {
		arp_pack_hdr_ethip(arp_ethip, op, *buf1, *buf2, *buf3, *buf4);
	} else
		dnet_exception(SWIG_ValueError, "invalid argument lengths");
}
%}
#ifdef SWIGPYTHON
%pythoncode %{
def arp_pack_hdr_ethip(op=ARP_OP_REQUEST, sha=ETH_ADDR_BROADCAST, spa=IP_ADDR_ANY, dha=ETH_ADDR_BROADCAST, dpa=IP_ADDR_ANY):
	"""Return a packed binary string representing an Ethernet/IP ARP message."""
	return _dnet.__arp_pack_hdr_ethip(op, sha, spa, dha, dpa)

%}
#else
%name(arp_pack_hdr_ethip) void __arp_pack_hdr_ethip(char *arp_ethip, int op,
	char *buf1, int len1, char *buf2, int len2,
	char *buf3, int len3, char *buf4, int len4);
#endif

%name(arp) struct arp_handle {
%extend {
	arp_handle(void) {
		arp_t *arp = arp_open();
		if (arp == NULL)
			dnet_exception(SWIG_RuntimeError, NULL);
		return (arp);
	}
	~arp_handle(void) {
		arp_close(self);
	}
	void add(struct addr *pa, struct addr *ha) {
		struct arp_entry entry;

		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		memcpy(&entry.arp_ha, ha, sizeof(*ha));
		if (arp_add(self, &entry) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	void delete(struct addr *pa) {
		struct arp_entry entry;

		memset(&entry, 0, sizeof(entry));
		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		if (arp_delete(self, &entry) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	%newobject get;
	struct addr *get(struct addr *pa) {
		struct arp_entry entry;
		struct addr *ha = NULL;

		memcpy(&entry.arp_pa, pa, sizeof(*pa));
		if (arp_get(self, &entry) == 0) {
			ha = calloc(1, sizeof(*ha));
			memcpy(ha, &entry.arp_ha, sizeof(*ha));
		} else {
			dnet_exception(SWIG_RuntimeError, NULL);
		}
		return (ha);
	}
#ifdef SWIGPYTHON
%{
	int __arp_loop_cb(const struct arp_entry *entry, void *arg) {
		struct cb_handle *cb = (struct cb_handle *)arg;
		PyObject *arglist, *result = NULL;
	
		if (PyCallable_Check(cb->func)) {
			arglist = Py_BuildValue("OOO", 
			    SWIG_NewPointerObj((void *)&entry->arp_pa, 
			    SWIGTYPE_p_addr, 1),
			    SWIG_NewPointerObj((void *)&entry->arp_ha,
			    SWIGTYPE_p_addr, 1), cb->arg);
			result = PyObject_CallObject(cb->func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(result);	
		}
		return (result == NULL ? -1 : 0);
	}
%}
	void loop(PyObject *callback, PyObject *arg) {
		struct cb_handle cb;

		cb.func = callback;
		cb.arg = arg;
		arp_loop(self, __arp_loop_cb, &cb);
	}
#endif
}
};

/*
 * rand.h
 */
%name(rand) struct rand_handle {
%extend {
	rand_handle(void) {
		return (rand_open());
	}
	~rand_handle(void) {
		rand_close(self);
	}
	void get(char **dstp, int *dlenp, int len) {
		*dstp = malloc(len); *dlenp = len;
		if (rand_get(self, *dstp, *dlenp) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	void set(char *buf1, int len1) {
		if (rand_set(self, buf1, len1) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	void add(char *buf1, int len1) {
		if (rand_add(self, buf1, len1) < 0)
			dnet_exception(SWIG_RuntimeError, NULL);
	}
	unsigned char uint8(void) {
		return (rand_uint8(self));
	}
	unsigned short uint16(void) {
		return (rand_uint16(self));
	}
	unsigned int uint32(void) {
		return (rand_uint32(self));
	}
}
};

/*
 * route.h
 */
%name(route) struct route_handle {
%extend {
	route_handle(void) {
		route_t *r = route_open();
		if (r == NULL)
			dnet_exception(SWIG_RuntimeError, NULL);
		return (r);
	}
	~route_handle(void) {
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
%{
	int __route_loop_cb(const struct route_entry *entry, void *arg) {
		struct cb_handle *cb = (struct cb_handle *)arg;
		PyObject *arglist, *result = NULL;
		
		if (PyCallable_Check(cb->func)) {
			arglist = Py_BuildValue("OOO", 
			    SWIG_NewPointerObj((void *)&entry->route_dst, 
			    SWIGTYPE_p_addr, 1),
			    SWIG_NewPointerObj((void *)&entry->route_gw,
			    SWIGTYPE_p_addr, 1), cb->arg);
			result = PyObject_CallObject(cb->func, arglist);
			Py_DECREF(arglist);
			Py_XDECREF(result);
		}
		return (result == NULL ? -1 : 0);
	}
%}
	void loop(PyObject *callback, PyObject *arg) {
		struct cb_handle cb;

		cb.func = callback;
		cb.arg = arg;
		route_loop(self, __route_loop_cb, &cb);
	}
#endif
}
};

/*
 * tcp.h
 */
#define TCP_HDR_LEN	20		/* base TCP header length */

#define TH_FIN		0x01		/* end of data */
#define TH_SYN		0x02		/* synchronize sequence numbers */
#define TH_RST		0x04		/* reset connection */
#define TH_PUSH		0x08		/* push */
#define TH_ACK		0x10		/* acknowledgement number set */
#define TH_URG		0x20		/* urgent pointer set */
#define TH_ECE		0x40		/* ECN echo, RFC 3168 */
#define TH_CWR		0x80		/* congestion window reduced */

#define TCP_PORT_MAX	65535		/* maximum port */
#define TCP_WIN_MAX	65535		/* maximum (unscaled) window */

#ifdef SWIGPYTHON
%pythoncode %{
def tcp_pack_hdr(sport=0, dport=0, seq=0, ack=0, flags=TH_SYN, win=0, urp=0):
	"""Return a packed binary string representing a TCP header."""
	return struct.pack("!HHIIBBHHH",
	    sport, dport, seq, ack, 5 << 4, flags, win, 0, urp)

%}
#endif

/*
 * udp.h
 */
#define UDP_HDR_LEN	8
#define UDP_PORT_MAX	65535

#ifdef SWIGPYTHON
%pythoncode %{
def udp_pack_hdr(sport=0, dport=0, ulen=UDP_HDR_LEN):
	"""Return a packed binary string representing a UDP header."""
	return struct.pack("!HHHH", sport, dport, ulen, 0)

%}
#endif

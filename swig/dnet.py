# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.
import _dnet
def _swig_setattr(self,class_type,name,value):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    self.__dict__[name] = value

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0


ADDR_TYPE_NONE = _dnet.ADDR_TYPE_NONE
ADDR_TYPE_ETH = _dnet.ADDR_TYPE_ETH
ADDR_TYPE_IP = _dnet.ADDR_TYPE_IP
ADDR_TYPE_IP6 = _dnet.ADDR_TYPE_IP6
class addr_iter(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, addr_iter, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, addr_iter, name)
    def __init__(self,*args):
        _swig_setattr(self, addr_iter, 'this', apply(_dnet.new_addr_iter,args))
        _swig_setattr(self, addr_iter, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_addr_iter):
        try:
            if self.thisown: destroy(self)
        except: pass
    def __iter__(*args): return apply(_dnet.addr_iter___iter__,args)
    def next(*args): return apply(_dnet.addr_iter_next,args)
    def __repr__(self):
        return "<C addr_iter instance at %s>" % (self.this,)

class addr_iterPtr(addr_iter):
    def __init__(self,this):
        _swig_setattr(self, addr_iter, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, addr_iter, 'thisown', 0)
        _swig_setattr(self, addr_iter,self.__class__,addr_iter)
_dnet.addr_iter_swigregister(addr_iterPtr)

class addr(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, addr, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, addr, name)
    __swig_setmethods__["type"] = _dnet.addr_type_set
    __swig_getmethods__["type"] = _dnet.addr_type_get
    if _newclass:type = property(_dnet.addr_type_get,_dnet.addr_type_set)
    __swig_setmethods__["bits"] = _dnet.addr_bits_set
    __swig_getmethods__["bits"] = _dnet.addr_bits_get
    if _newclass:bits = property(_dnet.addr_bits_get,_dnet.addr_bits_set)
    __swig_setmethods__["eth"] = _dnet.addr_eth_set
    __swig_getmethods__["eth"] = _dnet.addr_eth_get
    if _newclass:eth = property(_dnet.addr_eth_get,_dnet.addr_eth_set)
    __swig_setmethods__["ip"] = _dnet.addr_ip_set
    __swig_getmethods__["ip"] = _dnet.addr_ip_get
    if _newclass:ip = property(_dnet.addr_ip_get,_dnet.addr_ip_set)
    __swig_setmethods__["ip6"] = _dnet.addr_ip6_set
    __swig_getmethods__["ip6"] = _dnet.addr_ip6_get
    if _newclass:ip6 = property(_dnet.addr_ip6_get,_dnet.addr_ip6_set)
    def __init__(self,*args):
        _swig_setattr(self, addr, 'this', apply(_dnet.new_addr,args))
        _swig_setattr(self, addr, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_addr):
        try:
            if self.thisown: destroy(self)
        except: pass
    def bcast(*args): return apply(_dnet.addr_bcast,args)
    def net(*args): return apply(_dnet.addr_net,args)
    def __cmp__(*args): return apply(_dnet.addr___cmp__,args)
    def __contains__(*args): return apply(_dnet.addr___contains__,args)
    def __iter__(*args): return apply(_dnet.addr___iter__,args)
    def __len__(*args): return apply(_dnet.addr___len__,args)
    def __str__(*args): return apply(_dnet.addr___str__,args)
    def __repr__(self):
        return "<C addr instance at %s>" % (self.this,)

class addrPtr(addr):
    def __init__(self,this):
        _swig_setattr(self, addr, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, addr, 'thisown', 0)
        _swig_setattr(self, addr,self.__class__,addr)
_dnet.addr_swigregister(addrPtr)

ETH_ADDR_LEN = _dnet.ETH_ADDR_LEN
ETH_ADDR_BITS = _dnet.ETH_ADDR_BITS
ETH_CRC_LEN = _dnet.ETH_CRC_LEN
ETH_HDR_LEN = _dnet.ETH_HDR_LEN
ETH_LEN_MIN = _dnet.ETH_LEN_MIN
ETH_LEN_MAX = _dnet.ETH_LEN_MAX
ETH_MTU = _dnet.ETH_MTU
ETH_MIN = _dnet.ETH_MIN
ETH_TYPE_IP = _dnet.ETH_TYPE_IP
ETH_TYPE_ARP = _dnet.ETH_TYPE_ARP
ETH_TYPE_IPV6 = _dnet.ETH_TYPE_IPV6
ETH_ADDR_BROADCAST =	"\xff\xff\xff\xff\xff\xff"


__eth_pack_hdr = _dnet.__eth_pack_hdr

__eth_aton = _dnet.__eth_aton

__eth_ntoa = _dnet.__eth_ntoa

def eth_pack_hdr(dst=ETH_ADDR_BROADCAST, src=ETH_ADDR_BROADCAST, type=ETH_TYPE_IP):
	"""Return a packed binary string representing an Ethernet header.
	
	Keyword arguments:
	dst  -- destination address			(6-byte binary string)
	src  -- source address				(6-byte binary address)
	type -- Ethernet payload type (ETH_TYPE_*)	(uint16)
	"""
	return _dnet.__eth_pack_hdr(dst, src, type)
def eth_aton(string):
	"""Convert an Ethernet MAC address from a printable string to a
	packed binary string ('\\x00\\xde\\xad\\xbe\\xef\\x00')."""
	return _dnet.__eth_aton(string)
def eth_ntoa(eth_addr_string):
	"""Convert an Ethernet MAC address from 6-byte packed binary string to
	a printable string ('00:de:ad:be:ef:00')."""
	return _dnet.__eth_ntoa(eth_addr)


class eth(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, eth, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, eth, name)
    def __init__(self,*args):
        _swig_setattr(self, eth, 'this', apply(_dnet.new_eth,args))
        _swig_setattr(self, eth, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_eth):
        try:
            if self.thisown: destroy(self)
        except: pass
    def get(*args): return apply(_dnet.eth_get,args)
    def set(*args): return apply(_dnet.eth_set,args)
    def send(*args): return apply(_dnet.eth_send,args)
    def __repr__(self):
        return "<C eth instance at %s>" % (self.this,)

class ethPtr(eth):
    def __init__(self,this):
        _swig_setattr(self, eth, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, eth, 'thisown', 0)
        _swig_setattr(self, eth,self.__class__,eth)
_dnet.eth_swigregister(ethPtr)

__icmp_pack_hdr = _dnet.__icmp_pack_hdr

__icmp_pack_hdr_echo = _dnet.__icmp_pack_hdr_echo

def icmp_pack_hdr(type=8, code=0):
	"""Return a packed binary string representing an ICMP header.
	
	Keyword arguments:
	type -- type of message	(ICMP_TYPE_*)	(uint8)
	code -- type subcode (ICMP_CODE_*)	(uint8)
	"""
	return _dnet.__icmp_pack_hdr(type, code)
def icmp_pack_hdr_echo(type=8, code=0, id=0, seq=0, data=''):
	"""Return a packed binary string representing an ICMP echo message.
	
	Keyword arguments:
	type -- type of message (ICMP_TYPE_*)	(uint8)
	code -- type subcode (ICMP_CODE_*)	(uint8)
	id   -- message ID			(uint8)
	seq  -- sequence number			(uint8)
	data -- message data			(binary string)
	"""
	return _dnet.__icmp_pack_hdr_echo(type, code, id, seq, data);


IP_ADDR_LEN = _dnet.IP_ADDR_LEN
IP_ADDR_BITS = _dnet.IP_ADDR_BITS
IP_HDR_LEN = _dnet.IP_HDR_LEN
IP_OPT_LEN = _dnet.IP_OPT_LEN
IP_OPT_LEN_MAX = _dnet.IP_OPT_LEN_MAX
IP_HDR_LEN_MAX = _dnet.IP_HDR_LEN_MAX
IP_LEN_MAX = _dnet.IP_LEN_MAX
IP_LEN_MIN = _dnet.IP_LEN_MIN
IP_RF = _dnet.IP_RF
IP_DF = _dnet.IP_DF
IP_MF = _dnet.IP_MF
IP_OFFMASK = _dnet.IP_OFFMASK
IP_TTL_DEFAULT = _dnet.IP_TTL_DEFAULT
IP_TTL_MAX = _dnet.IP_TTL_MAX
IP_PROTO_IP = _dnet.IP_PROTO_IP
IP_PROTO_ICMP = _dnet.IP_PROTO_ICMP
IP_PROTO_IGMP = _dnet.IP_PROTO_IGMP
IP_PROTO_TCP = _dnet.IP_PROTO_TCP
IP_PROTO_UDP = _dnet.IP_PROTO_UDP
IP_PROTO_IPV6 = _dnet.IP_PROTO_IPV6
IP_PROTO_ROUTING = _dnet.IP_PROTO_ROUTING
IP_PROTO_FRAGMENT = _dnet.IP_PROTO_FRAGMENT
IP_PROTO_ICMPV6 = _dnet.IP_PROTO_ICMPV6
IP_PROTO_NONE = _dnet.IP_PROTO_NONE
IP_PROTO_DSTOPTS = _dnet.IP_PROTO_DSTOPTS
IP_PROTO_RAW = _dnet.IP_PROTO_RAW
IP_PROTO_RESERVED = _dnet.IP_PROTO_RESERVED
IP_PROTO_MAX = _dnet.IP_PROTO_MAX
IP_ADDR_ANY =			"\x00\x00\x00\x00"
IP_ADDR_BROADCAST =		"\xff\xff\xff\xff"
IP_ADDR_LOOPBACK =		"\x7f\x00\x00\x01"
IP_ADDR_MCAST_ALL =		"\xe0\x00\x00\x01"
IP_ADDR_MCAST_LOCAL =		"\xe0\x00\x00\xff"


__ip_pack_hdr = _dnet.__ip_pack_hdr

__ip_aton = _dnet.__ip_aton

__ip_ntoa = _dnet.__ip_ntoa

__ip_checksum = _dnet.__ip_checksum

def ip_pack_hdr(tos=0, len=IP_HDR_LEN, id=0, off=0, ttl=IP_TTL_DEFAULT, p=IP_PROTO_IP, src=IP_ADDR_ANY, dst=IP_ADDR_ANY):
	"""Return a packed binary string representing an IP header.
	
	Keyword arguments:
	tos -- type of service			(uint8)
	len -- length (IP_HDR_LEN + payload)	(uint16)
	id  -- packet ID			(uint16)
	off -- fragmentation offset		(uint16)
	ttl -- time-to-live			(uint8)
	p   -- protocol (IP_PROTO_*)		(uint8)
	src -- source address			(4-byte binary string)
	dst -- destination address		(4-byte binary string)
	"""
	return _dnet.__ip_pack_hdr(tos, len, id, off, ttl, p, src, dst)
def ip_aton(string):
	"""Return a packed binary string representing an IP address."""
	return _dnet.__ip_aton(string)
def ip_ntoa(addr):
	"""Return the printable string represention of a packed IP address."""
	return _dnet.__ip_ntoa(addr)
def ip_checksum(packet):
	"""Return a packed binary string representing an IP packet \
with the IP and transport-layer checksums set."""
	return _dnet.__ip_checksum(packet)


class ip(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, ip, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, ip, name)
    def __init__(self,*args):
        _swig_setattr(self, ip, 'this', apply(_dnet.new_ip,args))
        _swig_setattr(self, ip, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_ip):
        try:
            if self.thisown: destroy(self)
        except: pass
    def send(*args): return apply(_dnet.ip_send,args)
    def __repr__(self):
        return "<C ip instance at %s>" % (self.this,)

class ipPtr(ip):
    def __init__(self,this):
        _swig_setattr(self, ip, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, ip, 'thisown', 0)
        _swig_setattr(self, ip,self.__class__,ip)
_dnet.ip_swigregister(ipPtr)

ARP_HDR_LEN = _dnet.ARP_HDR_LEN
ARP_ETHIP_LEN = _dnet.ARP_ETHIP_LEN
ARP_HRD_ETH = _dnet.ARP_HRD_ETH
ARP_HRD_IEEE802 = _dnet.ARP_HRD_IEEE802
ARP_PRO_IP = _dnet.ARP_PRO_IP
ARP_OP_REQUEST = _dnet.ARP_OP_REQUEST
ARP_OP_REPLY = _dnet.ARP_OP_REPLY
ARP_OP_REVREQUEST = _dnet.ARP_OP_REVREQUEST
ARP_OP_REVREPLY = _dnet.ARP_OP_REVREPLY
__arp_pack_hdr_ethip = _dnet.__arp_pack_hdr_ethip

def arp_pack_hdr_ethip(op=ARP_OP_REQUEST, sha=ETH_ADDR_BROADCAST, spa=IP_ADDR_ANY, dha=ETH_ADDR_BROADCAST, dpa=IP_ADDR_ANY):
	"""Return a packed binary string representing an Ethernet/IP ARP message.
	
	Keyword arguments:
	op  -- operation (ARP_OP_*)		(uint16)
	sha -- sender hardware address		(6-byte binary string)
	spa -- sender protocol address		(4-byte binary string)
	dha -- destination hardware address	(6-byte binary string)
	dpa -- destination protocol address	(4-byte binary string)
	"""
	return _dnet.__arp_pack_hdr_ethip(op, sha, spa, dha, dpa)


class arp(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, arp, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, arp, name)
    def __init__(self,*args):
        _swig_setattr(self, arp, 'this', apply(_dnet.new_arp,args))
        _swig_setattr(self, arp, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_arp):
        try:
            if self.thisown: destroy(self)
        except: pass
    def add(*args): return apply(_dnet.arp_add,args)
    def delete(*args): return apply(_dnet.arp_delete,args)
    def get(*args): return apply(_dnet.arp_get,args)
    def loop(*args): return apply(_dnet.arp_loop,args)
    def __repr__(self):
        return "<C arp instance at %s>" % (self.this,)

class arpPtr(arp):
    def __init__(self,this):
        _swig_setattr(self, arp, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, arp, 'thisown', 0)
        _swig_setattr(self, arp,self.__class__,arp)
_dnet.arp_swigregister(arpPtr)

class rand(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, rand, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, rand, name)
    def __init__(self,*args):
        _swig_setattr(self, rand, 'this', apply(_dnet.new_rand,args))
        _swig_setattr(self, rand, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_rand):
        try:
            if self.thisown: destroy(self)
        except: pass
    def get(*args): return apply(_dnet.rand_get,args)
    def set(*args): return apply(_dnet.rand_set,args)
    def add(*args): return apply(_dnet.rand_add,args)
    def uint8(*args): return apply(_dnet.rand_uint8,args)
    def uint16(*args): return apply(_dnet.rand_uint16,args)
    def uint32(*args): return apply(_dnet.rand_uint32,args)
    def __repr__(self):
        return "<C rand instance at %s>" % (self.this,)

class randPtr(rand):
    def __init__(self,this):
        _swig_setattr(self, rand, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, rand, 'thisown', 0)
        _swig_setattr(self, rand,self.__class__,rand)
_dnet.rand_swigregister(randPtr)

class route(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, route, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, route, name)
    def __init__(self,*args):
        _swig_setattr(self, route, 'this', apply(_dnet.new_route,args))
        _swig_setattr(self, route, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_route):
        try:
            if self.thisown: destroy(self)
        except: pass
    def add(*args): return apply(_dnet.route_add,args)
    def delete(*args): return apply(_dnet.route_delete,args)
    def get(*args): return apply(_dnet.route_get,args)
    def loop(*args): return apply(_dnet.route_loop,args)
    def __repr__(self):
        return "<C route instance at %s>" % (self.this,)

class routePtr(route):
    def __init__(self,this):
        _swig_setattr(self, route, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, route, 'thisown', 0)
        _swig_setattr(self, route,self.__class__,route)
_dnet.route_swigregister(routePtr)

TCP_HDR_LEN = _dnet.TCP_HDR_LEN
TH_FIN = _dnet.TH_FIN
TH_SYN = _dnet.TH_SYN
TH_RST = _dnet.TH_RST
TH_PUSH = _dnet.TH_PUSH
TH_ACK = _dnet.TH_ACK
TH_URG = _dnet.TH_URG
TH_ECE = _dnet.TH_ECE
TH_CWR = _dnet.TH_CWR
TCP_PORT_MAX = _dnet.TCP_PORT_MAX
TCP_WIN_MAX = _dnet.TCP_WIN_MAX
def tcp_pack_hdr(sport=0, dport=0, seq=0, ack=0, flags=TH_SYN, win=0, urp=0):
	"""Return a packed binary string representing a TCP header.
	
	Keyword arguments:
	sport  -- source port			(uint16)
	dport  -- destination port		(uint16)
	seq    -- sequence number		(uint32)
	ack    -- acknowledgement number	(uint32)
	flags  -- control flags (TH_*)		(uint8)
	win    -- window size			(uint16)
	urp    -- urgent pointer                (uint16)
	"""
	return struct.pack("!HHIIBBHHH",
	    sport, dport, seq, ack, 5 << 4, flags, win, 0, urp)


UDP_HDR_LEN = _dnet.UDP_HDR_LEN
UDP_PORT_MAX = _dnet.UDP_PORT_MAX
def udp_pack_hdr(sport=0, dport=0, ulen=UDP_HDR_LEN):
	"""Return a packed binary string representing a UDP header.
	
	Keyword arguments:
	sport -- source port				(uint16)
	dport -- destination port			(uint16)
	ulen  -- length (UDP_HDR_LEN + payload)		(uint16)
	"""
	return struct.pack("!HHHH", sport, dport, ulen, 0)



import sys

if sys.version[0] == '2':
    __doc__ = \
        """This module provides a simplified interface to several low-level
        networking routines, including network address manipulation, kernel
        arp(4) cache and route(4) table lookup and manipulation, network
        firewalling, network interface lookup and manipulation, and raw IP
        packet and Ethernet frame transmission.

        Try 'help(X)' where X is any class, object, method, or function for
        more information.
        
        Classes:
            
            addr([addr_string]) -- network address object
            arp()               -- kernel ARP table handle
            eth(device_string)  -- Ethernet device handle
            ip()                -- raw IP handle
            rand()              -- pseudorandom number generator
            route()             -- kernel routing table handle

        Functions:
        
        Several auxiliary functions are available to convert between the
        printable and binary string representations of network addresses,
        and to pack network protocol headers and packets into binary
        strings for sending.
            
            arp_pack_hdr_ethip(...) -- create Ethernet/IP ARP message
            eth_aton(...)           -- text Ethernet address -> binary
            eth_ntoa(...)           -- binary Ethernet address -> text
            eth_pack_hdr(...)       -- create Ethernet frame header
            icmp_pack_hdr(...)      -- create ICMP message header
            icmp_pack_hdr_echo(...) -- create ICMP echo message
            ip_aton(...)            -- text IP address -> binary
            ip_ntoa(...)            -- binary IP address -> text
            ip_pack_hdr(...)        -- create IP packet header
            ip_checksum(...)        -- create IP/transport cksum'd pkt
        
        Exceptions:
        
        RuntimeError is raised on underlying OS-level errors, instead
        of OSError. ValueError or TypeError are raised on invalid
        arguments passed to a method or function.
        
        """
    
    ### addr
    addr.bcast.__setattr__('__doc__',
        """Return a new addr object representing the broadcast address.""")
    addr.net.__setattr__('__doc__',
        """Return a new addr object representing the network address.""")
    
    ### eth
    eth.get.__setattr__('__doc__',
        """Return the MAC address associated with the device as a
        binary string.""")
    eth.set.__setattr__('__doc__',
        """Set the MAC address for the device, returning 0 on success,
        -1 on failure.
        
        Arguments:
        eth_addr -- 6-byte binary string (e.g. '\\x00\\xde\\xad\\xbe\\xef\\x00')
        """)
    eth.send.__setattr__('__doc__',
        """Send an Ethernet frame, returning the number of bytes sent
        or -1 on failure.

        Arguments:
        frame -- binary string representing an Ethernet frame
        """)
    
    ### ip
    ip.send.__setattr__('__doc__',
        """Send an IP packet, returning the number of bytes sent
        or -1 on failure.
        
        Arguments:
        packet -- binary string representing an IP packet
        """)
    
    ### arp
    arp.add.__setattr__('__doc__',
        """Add a kernel ARP entry.

        Arguments:
        proto_addr -- protocol address object (usually IP)
        hw_addr    -- hardware address object (usually Ethernet)
        """)
    arp.delete.__setattr__('__doc__',
        """Delete a kernel ARP entry.

        Arguments:
        proto_addr -- protocol address object (usually IP)
        """)
    arp.get.__setattr__('__doc__',
        """Lookup a kernel ARP entry, returning an addr object for the
        hardware address.

        Arguments:
        proto_addr -- protocol address object (usually IP)
        """)
    arp.loop.__setattr__('__doc__',
        """Execute a callback for each kernel ARP table entry.

        Arguments:
        callback -- function with (proto_addr, hw_addr, arg) prototype
        arg      -- argument to be passed to the callback on execution
        """)

    ### rand
    rand.get.__setattr__('__doc__',
        """Return a string of random bytes.

        Arguments:
        length -- number of random bytes to generate
        """)
    rand.set.__setattr__('__doc__',
        """Initialize the PRNG from a known seed.
        
        Arguments:
        string -- binary string
        """)
    rand.add.__setattr__('__doc__',
        """Add additional entropy into the mix.

        Arguments:
        string -- binary string
        """)
    rand.uint8.__setattr__('__doc__',
        """Return a random unsigned byte.""")
    rand.uint16.__setattr__('__doc__',
        """Return a random unsigned short.""")
    rand.uint32.__setattr__('__doc__',
        """Return a random unsigned int.""")

    ### route
    route.add.__setattr__('__doc__',
        """Add a kernel routing table entry.

        Arguments:
        dst_addr -- destination address object
        gw_addr  -- gateway address object
        """)
    route.delete.__setattr__('__doc__',
        """Delete a kernel routing table entry.

        Arguments:
        dst_addr -- destination address object
        """)
    route.get.__setattr__('__doc__',
        """Lookup a kernel route entry, returning an addr object for
        the gateway address.

        Arguments:
        dst_addr -- destination address object
        """)
    route.loop.__setattr__('__doc__',
        """Execute a callback for each kernel route table entry.
        
        Arguments:
        callback -- function with (dst_addr, gw_addr, arg) prototype
        arg      -- argument to be passed to the callback on execution
        """)


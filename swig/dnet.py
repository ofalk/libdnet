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


class cb_handle(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, cb_handle, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, cb_handle, name)
    __swig_setmethods__["func"] = _dnet.cb_handle_func_set
    __swig_getmethods__["func"] = _dnet.cb_handle_func_get
    if _newclass:func = property(_dnet.cb_handle_func_get,_dnet.cb_handle_func_set)
    __swig_setmethods__["arg"] = _dnet.cb_handle_arg_set
    __swig_getmethods__["arg"] = _dnet.cb_handle_arg_get
    if _newclass:arg = property(_dnet.cb_handle_arg_get,_dnet.cb_handle_arg_set)
    def __init__(self,*args):
        _swig_setattr(self, cb_handle, 'this', apply(_dnet.new_cb_handle,args))
        _swig_setattr(self, cb_handle, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_cb_handle):
        try:
            if self.thisown: destroy(self)
        except: pass
    def __repr__(self):
        return "<C cb_handle instance at %s>" % (self.this,)

class cb_handlePtr(cb_handle):
    def __init__(self,this):
        _swig_setattr(self, cb_handle, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, cb_handle, 'thisown', 0)
        _swig_setattr(self, cb_handle,self.__class__,cb_handle)
_dnet.cb_handle_swigregister(cb_handlePtr)

ADDR_TYPE_NONE = _dnet.ADDR_TYPE_NONE
ADDR_TYPE_ETH = _dnet.ADDR_TYPE_ETH
ADDR_TYPE_IP = _dnet.ADDR_TYPE_IP
ADDR_TYPE_IP6 = _dnet.ADDR_TYPE_IP6
class addr(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, addr, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, addr, name)
    __swig_setmethods__["addr_type"] = _dnet.addr_addr_type_set
    __swig_getmethods__["addr_type"] = _dnet.addr_addr_type_get
    if _newclass:addr_type = property(_dnet.addr_addr_type_get,_dnet.addr_addr_type_set)
    __swig_setmethods__["addr_bits"] = _dnet.addr_addr_bits_set
    __swig_getmethods__["addr_bits"] = _dnet.addr_addr_bits_get
    if _newclass:addr_bits = property(_dnet.addr_addr_bits_get,_dnet.addr_addr_bits_set)
    def __init__(self,*args):
        _swig_setattr(self, addr, 'this', apply(_dnet.new_addr,args))
        _swig_setattr(self, addr, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_addr):
        try:
            if self.thisown: destroy(self)
        except: pass
    def aton(*args): return apply(_dnet.addr_aton,args)
    def ntoa(*args): return apply(_dnet.addr_ntoa,args)
    def __str__(*args): return apply(_dnet.addr___str__,args)
    def __repr__(self):
        return "<C addr instance at %s>" % (self.this,)

class addrPtr(addr):
    def __init__(self,this):
        _swig_setattr(self, addr, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, addr, 'thisown', 0)
        _swig_setattr(self, addr,self.__class__,addr)
_dnet.addr_swigregister(addrPtr)

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

arp_pack_hdr_ethip = _dnet.arp_pack_hdr_ethip

__arp_loop_cb = _dnet.__arp_loop_cb

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
ETH_ADDR_BROADCAST = _dnet.ETH_ADDR_BROADCAST
__eth_pack_hdr = _dnet.__eth_pack_hdr

eth_pack_hdr = _dnet.eth_pack_hdr

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

FW_OP_ALLOW = _dnet.FW_OP_ALLOW
FW_OP_BLOCK = _dnet.FW_OP_BLOCK
FW_DIR_IN = _dnet.FW_DIR_IN
FW_DIR_OUT = _dnet.FW_DIR_OUT
__fw_pack_rule = _dnet.__fw_pack_rule

fw_pack_rule = _dnet.fw_pack_rule

class fw(_object):
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, fw, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, fw, name)
    def __init__(self,*args):
        _swig_setattr(self, fw, 'this', apply(_dnet.new_fw,args))
        _swig_setattr(self, fw, 'thisown', 1)
    def __del__(self, destroy= _dnet.delete_fw):
        try:
            if self.thisown: destroy(self)
        except: pass
    def add(*args): return apply(_dnet.fw_add,args)
    def delete(*args): return apply(_dnet.fw_delete,args)
    def __repr__(self):
        return "<C fw instance at %s>" % (self.this,)

class fwPtr(fw):
    def __init__(self,this):
        _swig_setattr(self, fw, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, fw, 'thisown', 0)
        _swig_setattr(self, fw,self.__class__,fw)
_dnet.fw_swigregister(fwPtr)

__icmp_pack_hdr = _dnet.__icmp_pack_hdr

__icmp_pack_hdr_echo = _dnet.__icmp_pack_hdr_echo

icmp_pack_hdr = _dnet.icmp_pack_hdr

icmp_pack_hdr_echo = _dnet.icmp_pack_hdr_echo

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
IP_ADDR_ANY = _dnet.IP_ADDR_ANY
IP_ADDR_BROADCAST = _dnet.IP_ADDR_BROADCAST
IP_ADDR_LOOPBACK = _dnet.IP_ADDR_LOOPBACK
IP_ADDR_MCAST_ALL = _dnet.IP_ADDR_MCAST_ALL
IP_ADDR_MCAST_LOCAL = _dnet.IP_ADDR_MCAST_LOCAL
__ip_pack_hdr = _dnet.__ip_pack_hdr

__ip_aton = _dnet.__ip_aton

__ip_ntoa = _dnet.__ip_ntoa

__ip_checksum = _dnet.__ip_checksum

ip_pack_hdr = _dnet.ip_pack_hdr

ip_aton = _dnet.ip_aton

ip_ntoa = _dnet.ip_ntoa

ip_checksum = _dnet.ip_checksum

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

__route_loop_cb = _dnet.__route_loop_cb

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



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


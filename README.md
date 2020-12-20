libdnet
-------

This is a fork of https://github.com/ofalk/libdnet to address an open issue with addr_pton()
calling gethostbyname().  This fork just removes the handling of host names as the first
argument to addr_pton() since it can't do the right thing in a dual-stack world (there is
no right thing to do; does the user want the AAAA record or the A record?  If there is
more than one record (even if the same type), which one do we want to use?  etc.).
Basically, keep any resolver calls out of addr.c.

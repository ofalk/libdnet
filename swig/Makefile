
CC=	gcc

CFLAGS=	-g -O2 -fPIC -I/usr/local/include -I/usr/local/include/python2.2

LDFLAGS=-shared

all: _dnet.so

_dnet.so: dnet_python.o
	$(LD) $(LDFLAGS) -o $@ dnet_python.o -L/usr/local/lib -ldnet

dnet.so: dnet_tcl.o
	$(LD) $(LDFLAGS) -o $@ dnet_tcl.o -L/usr/local/lib -ldnet

dnet_python.c: dnet.i
	swig -v -includeall -shadow -python -o $@ dnet.i

dnet_tcl.c: dnet.i
	swig -tcl -o $@ dnet.i

clean:
	rm -f *~ *.c *.o dnet.py dnet.pyc *.so *.core

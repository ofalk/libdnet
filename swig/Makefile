
CFLAGS=	-g -O2 -Wall
TCLDIR=	/misc/arbor/arbortcl/tcl8.3.4

all: build

dnet.py dnet_python.c: dnet.i doc.py
	swig -v -python -shadow -o dnet_python.c dnet.i
	cat doc.py >> dnet.py

build: dnet.py dnet_python.c
	python setup.py build

install: build
	python setup.py install

tcl: dnet.i
	swig -tcl -namespace -o dnet_tcl.c dnet.i
	sh ../libtool --mode compile gcc -I../include -I$(TCLDIR)/generic $(CFLAGS) -c dnet_tcl.c
	sh ../libtool --mode link gcc -o libdnet_tcl.la -rpath $(TCLDIR):/usr/local/lib -version-info 0:0:0 dnet_tcl.lo -ldnet
	cp .libs/libdnet_tcl.so.0.0 dnet.so

clean:
	rm -rf build *~ *.core

distclean: clean
	rm -f dnet.py* *.c


if PYTHON
# XXX - lots of nasty automake fudging here...

noinst_SCRIPTS = python-build

dnet.py dnet_python.c: dnet.i doc.py
	swig -v -python -shadow -o dnet_python.c dnet.i
	cat doc.py >> dnet.py

python-build: dnet.py dnet_python.c
	python setup.py build
	touch python-build

python-clean:
	rm -rf *build

clean: python-clean

endif

#if TCL
#noinst_LTLIBRARIES = dnet.la
#endif

#dnet_tcl.c: dnet.i
#	swig -v -tcl -namespace -o dnet_tcl.c dnet.i

#dnet_la_SOURCES = dnet_tcl.c

#dnet_la_CFLAGS = -I../include -I@TCLINC@

#dnet_la_LDFLAGS = -module -rpath @TCLLIB@:@PREFIX@/lib -L../src -ldnet

install-exec-local:
if PYTHON
	python setup.py install --prefix=$(DESTDIR)$(prefix)
endif
	@true

CLEANFILES = *~ *.core

DISTCLEANFILES = dnet.py *.pyc *.c

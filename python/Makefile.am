## $Id$

include $(top_srcdir)/Makefile.am.common

if PYTHON
# XXX - nasty automake fudging here...

noinst_SCRIPTS = python-build

dnet.c: dnet.pyx
	pyrexc dnet.pyx

python-build: dnet.c
	python setup.py build
	touch python-build

python-clean:
	rm -rf *build

clean: python-clean

endif

install-exec-local:
if PYTHON
	python setup.py install --prefix=$(DESTDIR)$(prefix)
endif
	@true

EXTRA_DIST = setup.py dnet.pyx dnet.c

DISTCLEANFILES = *~

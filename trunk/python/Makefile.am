## $Id$

include $(top_srcdir)/Makefile.am.common

if PYTHON
# XXX - nasty automake fudging here...

noinst_SCRIPTS = python-build

$(srcdir)/dnet.c: $(srcdir)/dnet.pyx
	pyrexc $(srcdir)/dnet.pyx

python-build: $(srcdir)/dnet.c
	$(PYTHON) setup.py build --build-lib build
	touch python-build

python-clean:
	rm -rf *build

clean: python-clean

distclean: clean

install-exec-local:
	python $(srcdir)/setup.py install --prefix=$(DESTDIR)$(prefix)

TESTS = test.py
endif

EXTRA_DIST = dnet.pyx dnet.c setup.py.in test.py

DISTCLEANFILES = *~

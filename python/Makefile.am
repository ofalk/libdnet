## $Id$

include $(top_srcdir)/Makefile.am.common

if PYTHON
# XXX - nasty automake fudging here...

noinst_SCRIPTS = python-build


python-build:
	$(PYTHON) -m pip install -e .
	touch python-build

python-clean:
	rm -rf build dnet.c 
clean: python-clean

distclean: clean

python-install:
	$(PYTHON) -m pip install --prefix=$(DESTDIR)$(prefix) .

install-exec-local: python-install

TESTS = test.py

else

install-exec-local:

endif

EXTRA_DIST = dnet.pyx dnet.c pyproject.toml.in test.py interfacefinder.py

DISTCLEANFILES = *~


all: build

dnet_python.c: dnet.i
	swig -v -includeall -shadow -python -o $@ dnet.i

build: dnet_python.c
	python setup.py build

install: build
	python setup.py install

clean:
	rm -rf build *~ *.core

distclean: clean
	rm -f dnet.py *.c

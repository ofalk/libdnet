#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name="dnet",
      version="1.8",
      description="low-level networking routines",
      author="Dug Song",
      author_email="dugsong@monkey.org",
      url="http://libdnet.sourceforge.net/",
      py_modules = [ "dnet" ],
      ext_modules = [ Extension("_dnet", [ "dnet_python.c" ],
                                include_dirs = [ "../include" ],
                                library_dirs = [ "../src/.libs" ],
                                libraries = [ "dnet" ]) ] )


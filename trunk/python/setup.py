#!/usr/bin/env python

from distutils.core import setup, Extension

dnet = Extension('dnet', [ 'dnet.c' ],
                 include_dirs = ['../include'],
                 extra_objects = [ '../src/.libs/libdnet.a' ])

setup(name='dnet',
      version='1.8',
      description='low-level networking library',
      author='Dug Song',
      author_email='dugsong@monkey.org',
      url='http://libdnet.sourceforge.net/',
      ext_modules = [dnet])

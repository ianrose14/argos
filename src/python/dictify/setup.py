#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name = "dictify",
      version = "1.0",
      author="Ian Rose",
      ext_modules=[Extension('dictify', ['dictify.c'], include_dirs=["/usr/local/include/python2.7/"])],
      )

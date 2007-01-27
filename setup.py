#! /usr/bin/env python

import sys

from distutils.core import setup, Extension

setup( name="pyflowtools", 
       version="0.3",
       author="Robin Sommer",
       author_email="rsommer@cs.uni-sb.de",
       license="GPL",
       url="http://www.net.uni-sb.de/~robin/flowtools",
       ext_modules = [ Extension( "flowtools", ["flowtools.c"],
                                  libraries = [ "ft", "z" ],
                                 ) ] )


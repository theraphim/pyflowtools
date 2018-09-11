#! /usr/bin/env python

from __future__ import print_function

import flowtools

set = flowtools.FlowSet( "-" ) # Read from stdin

for flow in set:
    print("%s %s" % ( flow.srcaddr, flow.dstaddr ))
    print(" ", repr( flow.getID() ))
    print(" ", repr( flow.getID( 1 ) ))

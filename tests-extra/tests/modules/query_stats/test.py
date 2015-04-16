#!/usr/bin/env python3

''' Check 'dnstap' query module functionality. '''

import os
import re
from dnstest.test import Test
from dnstest.module import ModQueryStats
from dnstest.utils import *

t = Test()

ModQueryStats.check()

# Initialize server configuration
knot = t.server("knot")
zone = t.zone("flags.")
t.link(zone, knot)

# Configure 'query_stats' module for all queries (default).
dflt_dump = t.out_dir + "/global_queries.dump"
knot.add_module(None, ModQueryStats(dflt_dump))
# Configure 'query_stats' module for flags zone only.
flags_dump = t.out_dir + "/flags_queries.dump"
knot.add_module(zone, ModQueryStats(flags_dump))

t.start()

dflt_qname = "query_stats_default_test"
resp = knot.dig(dflt_qname + ".example", "NS")
flags_qname = "query_stats_flags_test"
resp = knot.dig(flags_qname + ".flags", "NS")

knot.stop()

# Check if query_stats dumps exist.
#isset(os.path.isfile(dflt_dump), "default dump")
#isset(os.path.isfile(flags_dump), "zone dump")

def dump_contains(dump, qname):
    '''Checks the sink if contains QNAME'''

    f = open(sink, "rb")
    s = str(f.read())
    f.close()

    return s.find(qname) != -1

# Check sink contents.
#isset(sink_contains(dflt_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, dflt_sink))
#isset(sink_contains(dflt_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, dflt_sink))
#isset(sink_contains(flags_sink, flags_qname), "qname '%s' in '%s'" % (flags_qname, flags_sink))
#isset(not sink_contains(flags_sink, dflt_qname), "qname '%s' in '%s'" % (dflt_qname, flags_sink))

t.end()

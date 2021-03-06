#!/usr/bin/env python3

"""
Check if DNSKEY lifetime timestamps are proccessed correctly by Knot.
"""

import collections
import os
import shutil
import datetime
import subprocess

from dnstest.utils import *
from dnstest.test import Test

def keymgr(server, args):
    cmd = subprocess.Popen([params.keymgr_bin, "--dir", server.keydir] + args)
    (stdout, stderr) = cmd.communicate()
    return (cmd.returncode, stdout, stderr)

def key_set(server, zone, key_id, **new_values):
    cmd = ["zone", "key", "set", zone, key_id]
    for option, value in new_values.items():
        cmd += [option, value]
    (exitcode, _x, _y) = keymgr(server, cmd)
    if exitcode != 0:
        raise Failed("Unable to modify key timing values.")

# check zone if keys are present and used for signing
def check_zone(server, expect_dnskey, expect_rrsig, msg):
    dnskeys = server.dig("example.com", "DNSKEY")
    soa = server.dig("example.com", "SOA", dnssec=True)

    found_dnskeys = dnskeys.count("DNSKEY")
    found_rrsigs = soa.count("RRSIG")

    expect_dnskeys = 3 if expect_dnskey else 2
    expect_rrsigs = 2 if expect_rrsig else 1

    check_log("DNSKEYs: %d (expected %d) RRSIGs: %d (expected %d)" %
              (found_dnskeys, expect_dnskeys, found_rrsigs, expect_rrsigs));

    if found_dnskeys != expect_dnskeys or found_rrsigs != expect_rrsigs:
        set_err("BAD DNSKEY: " + msg)
        detail_log("!DNSKEYs not published and activated as expected: " + msg)

    detail_log(SEP)

t = Test()

knot = t.server("knot")
knot.dnssec_enable = True
zone = t.zone("example.com.")
t.link(zone, knot)

# install keys (one always enabled, one for testing)
shutil.copytree(os.path.join(t.data_dir, "keys"), knot.keydir)

# parameters
ZONE = "example.com"
KEYID = "712d0d0d57fa0aa006b5e20cd84e23941e5f3ab2"
WAIT_SIGN = 2

#
# Common cases
#

check_log("Common cases")

# key not published, not active
key_set(knot, ZONE, KEYID, publish="+10y", active="+10y")
t.start()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "not published, not active")

# key published, not active
key_set(knot, ZONE, KEYID, publish="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, not active")

# key published, active
key_set(knot, ZONE, KEYID, active="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "published, active")

# key published, inactive
key_set(knot, ZONE, KEYID, retire="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "published, inactive")

# key deleted, inactive
key_set(knot, ZONE, KEYID, remove="-10y")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "deleted, inactive")

# key not published, active (algorithm rotation)
key_set(knot, ZONE, KEYID, publish="+10y", active="-10y", retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, True, "not published, active")

#
# Test DNSSEC key event execution
#

check_log("Planned events")

# key about to be published
event_in = 7
key_set(knot, ZONE, KEYID, publish=("+%d" % event_in), active="+10y", retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, False, False, "to be published - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be published - post")

# key about to be activated
key_set(knot, ZONE, KEYID, publish="-10y", active=("+%d" % event_in), retire="0", remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be activated - pre")
t.sleep(event_in)
check_zone(knot, True, True, "to be activated - post")

#key about to be inactivated
key_set(knot, ZONE, KEYID, publish="-10y", active="-10y", retire=("+%d" % event_in), remove="0")
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, True, "to be inactivated - pre")
t.sleep(event_in)
check_zone(knot, True, False, "to be inactivated - post")

#key about to be deleted
key_set(knot, ZONE, KEYID, publish="-10y", active="-10y", retire="-10y", remove=("+%d" % event_in))
knot.reload()
t.sleep(WAIT_SIGN)
check_zone(knot, True, False, "to be deleted - pre")
t.sleep(event_in)
check_zone(knot, False, False, "to be deleted - post")

t.end()

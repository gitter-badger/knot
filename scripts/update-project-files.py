#!/usr/bin/python -Es
# vim: et:sw=4:ts=4:sts=4
#
# Script regenerates project file list from the list of files tracked by Git.
#

SOURCES = [
    # documentation
    "README", "KNOWN_ISSUES", 
    "Doxyfile*", "Doxy.file.h", "doc/*.rst",

    # build-system
    "*.ac", "*.am",

    # sources
    "src/*.c", "src/*.h", "src/*.rl", "src/*.l",
    "src/*.y", "tests/*.c", "tests/*.h",
    "tests-fuzz/*.c", "tests-fuzz/*.h",
    "libtap/*.c", "libtap/*.h",
]

OUTPUT_FILE = "Knot.files"

# ----------------------------------------------------------------------------

from subprocess import Popen, PIPE
import os
import sys

def run(command):
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    (out, errout) = p.communicate()
    if p.returncode != 0:
        raise Exception("Command %s failed.", command)
    return out

print >>sys.stderr, "Updating %s." % OUTPUT_FILE

git_root = run(["git", "rev-parse", "--show-toplevel"]).strip()
os.chdir(git_root)

command = ["git", "ls-files"] + SOURCES
files = run(command).splitlines()

with open(OUTPUT_FILE, "w") as output:
    output.write("\n".join(sorted(files)))
    output.write("\n")

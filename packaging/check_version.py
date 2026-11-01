#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail unless the source version, the newest CHANGELOG entry and (optionally) a git tag agree.
Usage: check_version.py [vX.Y.Z]"""
import os
import re
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
src = open(os.path.join(root, "inetgateway.py"), encoding="utf-8").read()
version = re.search(r'^__version__ = "([^"]+)"', src, re.M).group(1)
log = open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8").read()
m = re.search(r"^## \[([^\]]+)\]", log, re.M)
problems = []
if not m or m.group(1) != version:
    problems.append("CHANGELOG.md newest entry is %r but inetgateway.py says %r" % (m.group(1) if m else None, version))
if len(sys.argv) > 1 and sys.argv[1].lstrip("v") != version:
    problems.append("tag %r does not match version %r" % (sys.argv[1], version))
if problems:
    print("Version check FAILED:\n  " + "\n  ".join(problems))
    sys.exit(1)
print("Version OK:", version)

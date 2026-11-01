#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Print the CHANGELOG.md section for a version (default: the one in inetgateway.py). Used for GitHub release notes."""
import os
import re
import sys

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
version = sys.argv[1].lstrip("v") if len(sys.argv) > 1 else re.search(
    r'^__version__ = "([^"]+)"', open(os.path.join(root, "inetgateway.py"), encoding="utf-8").read(), re.M).group(1)
log = open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8").read()
m = re.search(r"^## \[%s\][^\n]*\n(.*?)(?=^## \[|\Z)" % re.escape(version), log, re.M | re.S)
print(m.group(1).strip() if m else "See CHANGELOG.md.")

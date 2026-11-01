#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Print the program version (used by the release workflow)."""
import os
import re

src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "inetgateway.py"), encoding="utf-8").read()
print(re.search(r'^__version__ = "([^"]+)"', src, re.M).group(1))

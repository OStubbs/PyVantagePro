# coding: utf8
"""
    pyvantagepro.compat
    -------------------

    Workarounds for compatibility with Python 2 and 3 in the same code base.

    :copyright: Copyright 2012 Salem Harrache and contributors, see AUTHORS.
    :license: GNU GPL v3.

"""

import sys

from logging import NullHandler
from collections import OrderedDict
from io import StringIO

def to_char(string):
    if len(string) == 0:
        return str('')
    return str(string[0])

str = str
bytes = bytes
stdout = sys.stdout.buffer
xrange = range

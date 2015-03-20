# -*- coding: utf-8 -*-
"""
    flask_acl._compat
    ~~~~~~~~~~~~~~~~~

    Python compatability module
"""

import sys

PY2 = sys.version_info[0] == 2

if not PY2:
    string_types = (str,)
else:
    string_types = (str, unicode)

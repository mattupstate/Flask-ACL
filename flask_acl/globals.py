# -*- coding: utf-8 -*-
"""
    flask_acl.globals
    ~~~~~~~~~~~~~~~~~

    Globals module
"""

from flask import current_app
from werkzeug.local import LocalProxy

#: Proxy to the current Flask app's :class:`.ACLManager`.
current_acl_manager = LocalProxy(lambda: current_app.acl_manager)

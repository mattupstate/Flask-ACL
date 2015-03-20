# -*- coding: utf-8 -*-
"""
    flask_acl.extension
    ~~~~~~~~~~~~~~~~~~~

    Extension module
"""

from __future__ import absolute_import

import functools

from flask import abort, url_for, redirect, request, current_app, _request_ctx_stack
from flask.ext.login import current_user

from flask_acl.core import iter_object_acl, get_object_context, check
from flask_acl.permission import default_permission_sets
from flask_acl.predicate import default_predicates


class ACLManager(object):

    """Flask extension for registration and checking of ACLs on routes and other objects."""

    def __init__(self, app=None):
        self._context_processors = []
        self.error_callback = self._default_error_handler
        self.permission_sets = default_permission_sets.copy()
        self.predicates = default_predicates.copy()
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.acl_manager = self
        app.extensions['acl'] = self
        app.config.setdefault('ACL_ROUTE_DEFAULT_STATE', True)
        app.errorhandler(401)(self.error_callback)
        app.errorhandler(403)(self.error_callback)

    def error_handler(self, fn):
        self.error_callback = fn

    def _default_error_handler(self, error):
        if error.code == 401 and current_app.login_manager.login_view:
            return redirect(url_for(current_app.login_manager.login_view))
        return error.get_response()

    def predicate(self, name, predicate=None):
        """Define a new predicate (direclty, or as a decorator).

        E.g.::

            @authz.predicate
            def ROOT(user, **ctx):
                # return True of user is in group "wheel".
        """
        if predicate is None:
            return functools.partial(self.predicate, name)
        self.predicates[name] = predicate
        return predicate

    def permission_set(self, name, permission_set=None):
        """Define a new permission set (directly, or as a decorator)."""
        if permission_set is None:
            return functools.partial(self.permission_set, name)
        self.permission_sets[name] = permission_set
        return permission_set

    def context_processor(self, func):
        """Register a function to build authorization contexts.

        The function is called with no arguments, and must return a dict of new
        context material.

        """
        self._context_processors.append(func)

    def route_acl(self, *acl, **options):
        """Decorator to attach an ACL to a route.

        E.g::

            @app.route('/url/to/view')
            @authz.route_acl('''
                ALLOW WHEEL ALL
                DENY  ANY   ALL
            ''')
            def my_admin_function():
                pass

        """

        def _route_acl(func):

            func.__acl__ = acl

            @functools.wraps(func)
            def wrapped(*args, **kwargs):
                permission = 'http.' + request.method.lower()
                local_opts = options.copy()
                local_opts.setdefault('default', current_app.config['ACL_ROUTE_DEFAULT_STATE'])
                self.assert_can(permission, func, **local_opts)
                return func(*args, **kwargs)

            return wrapped
        return _route_acl

    def can(self, permission, obj, **kwargs):
        """Check if we can do something with an object.

        :param permission: The permission to look for.
        :param obj: The object to check the ACL of.
        :param **kwargs: The context to pass to predicates.

        >>> auth.can('read', some_object)
        >>> auth.can('write', another_object, group=some_group)

        """

        context = {'user': current_user}
        for func in self._context_processors:
            context.update(func())
        context.update(get_object_context(obj))
        context.update(kwargs)
        return check(permission, iter_object_acl(obj), **context)

    def assert_can(self, permission, obj, **kwargs):
        """Make sure we have a permission, or abort the request.

        :param permission: The permission to look for.
        :param obj: The object to check the ACL of.
        :param flash: The message to flask if denied (keyword only).
        :param stealth: Abort with a 404? (keyword only).
        :param **kwargs: The context to pass to predicates.

        """
        stealth = kwargs.pop('stealth', False)
        default = kwargs.pop('default', None)

        res = self.can(permission, obj, **kwargs)
        res = default if res is None else res

        if not res:
            if stealth:
                abort(404)
            elif current_user.is_authenticated():
                abort(403)
            else:
                abort(401)

    def can_route(self, endpoint, method=None, **kwargs):
        """Make sure we can route to the given endpoint or url.

        This checks for `http.get` permission (or other methods) on the ACL of
        route functions, attached via the `ACL` decorator.

        :param endpoint: A URL or endpoint to check for permission to access.
        :param method: The HTTP method to check; defaults to `'GET'`.
        :param **kwargs: The context to pass to predicates.

        """

        view = current_app.view_functions.get(endpoint)
        if not view:
            endpoint, args = _request_ctx_stack.top.match(endpoint)
            view = current_app.view_functions.get(endpoint)
        if not view:
            return False
        return self.can('http.' + (method or 'GET').lower(), view, **kwargs)

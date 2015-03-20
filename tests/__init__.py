from unittest import TestCase

from flask.ext.acl import ACLManager
from flask.ext.login import LoginManager
from flask import Flask


class FlaskTestCase(TestCase):

    def setUp(self):

        self.flask = Flask('tests')
        self.flask.debug = True
        self.flask.testing = True
        self.flask.config['SECRET_KEY'] = 'deadbeef'
        self.authn = LoginManager(self.flask)
        self.authn.login_view = 'login'
        self.authz = ACLManager(self.flask)
        self.client = self.flask.test_client()

        @self.flask.route('/login')
        @self.authz.route_acl('ALLOW ANY ALL')
        def login():
            return 'please login', 401

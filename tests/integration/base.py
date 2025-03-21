"""
Test Base Module.

This module defines a base test class for Flask-based tests by extending
Python’s built-in unittest.TestCase.
"""
import json
import logging
from unittest import TestCase

from flask import Flask, Response
from flask_jwt_extended import JWTManager

from service import app_config, register_error_handlers
from service.common import status
from service.models import Account, db
from tests import create_db_if_not_exists
from tests.utils.constants import JWT_SECRET_KEY


# Dummy route functions for testing the decorator
def dummy_route_success():
    """A dummy route that returns a successful JSON response."""
    response_data = {'success': True}
    return Response(
        json.dumps(response_data),
        status=status.HTTP_200_OK,
        mimetype='application/json'
    )


def dummy_route_failure():
    """A dummy route that simulates failure by raising an exception."""
    raise Exception("Route failure occurred")


######################################################################
#  BASE CLASS FOR INTEGRATION TESTS
######################################################################
class BaseTestCase(TestCase):
    """A base test class for Flask-based tests that sets up the application context."""

    app = None

    @classmethod
    def setUpClass(cls):
        """This runs once before the entire test suite."""
        cls.app = Flask(__name__)
        cls.app.testing = True
        cls.app.config["TESTING"] = True
        cls.app.config["DEBUG"] = False
        cls.app.config["SQLALCHEMY_DATABASE_URI"] = app_config.database_uri
        cls.app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        cls.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        cls.app.logger.setLevel(logging.CRITICAL)
        JWTManager(cls.app)

        # Disable exception propagation so error handlers can catch errors
        cls.app.config['PROPAGATE_EXCEPTIONS'] = False
        register_error_handlers(cls.app)

        cls.app.app_context().push()

        if app_config.database_uri:
            engine = create_db_if_not_exists(app_config.database_uri)
            if engine:
                cls.app.logger.info('Database connection successful.')
            else:
                cls.app.logger.error('Failed to connect to database.')
        else:
            cls.app.logger.error('Database URI not set')

        Account.init_db(cls.app)
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        """This runs once after the entire test suite."""
        db.session.close()
        db.drop_all()

    def setUp(self):
        """This runs before each test."""
        db.session.rollback()
        db.session.query(Account).delete()
        db.session.commit()

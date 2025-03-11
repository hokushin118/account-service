"""
Test Base Module.

This module defines a base test class for Flask-based tests by extending
Python’s built-in unittest.TestCase.
"""
from unittest import TestCase

from flask import Flask
from flask_jwt_extended import JWTManager

from tests.test_constants import JWT_SECRET_KEY


class BaseTestCase(TestCase):
    """A base test class for Flask-based tests that sets up the application context."""

    def setUp(self):
        """It should set up the Flask application context before each test."""
        self.app = Flask(__name__)
        self.app.testing = True
        self.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        JWTManager(self.app)
        self.app_context = self.app.app_context()
        self.app_context.push()  # Push the context so request works

    def tearDown(self):
        """It should tear down the Flask application context after each test."""
        self.app_context.pop()

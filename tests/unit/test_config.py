"""
Configs Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from dataclasses import FrozenInstanceError
from unittest import TestCase
from unittest.mock import patch

from service.configs import (
    AppConfig
)

TEST_DATABASE_URI = 'postgresql://test_user:test_pass@test_host:12345/test_db'
DEFAULT_USER = 'cba'
DEFAULT_PASSWORD = 'pa$$wOrd123!'
DEFAULT_DB_NAME = 'account_db'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = '15432'
TEST_SECRET_KEY = 'test_secret'
TEST_LOG_LEVEL = 'INFO'
API_VERSION = 'v2'


class TestAppConfig(TestCase):
    """AppConfig Class Tests."""

    def setUp(self):
        """Sets up an AppConfig instance for testing."""
        with patch.dict(os.environ, {
            'DATABASE_URI': TEST_DATABASE_URI,
            'SECRET_KEY': TEST_SECRET_KEY,
            'API_VERSION': API_VERSION,
            'LOG_LEVEL': TEST_LOG_LEVEL
        }):
            self.config = AppConfig()

    def test_database_uri_from_env(self):
        """It should use the DATABASE_URI environment variable if provided."""
        self.assertEqual(self.config.database_uri, TEST_DATABASE_URI)
        self.assertEqual(
            self.config.sqlalchemy_database_uri,
            TEST_DATABASE_URI
        )

    def test_construct_database_uri_from_components(self):
        """It should construct a valid database URI from individual environment
        variable components if DATABASE_URI is not provided."""
        env_vars = {
            'DATABASE_USER': 'custom_user',
            'DATABASE_PASSWORD': 'custom_pass',
            'DATABASE_NAME': 'custom_db',
            'DATABASE_HOST': 'custom_host',
            'DATABASE_PORT': '5432',
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = AppConfig()
            expected_uri = (
                'postgresql://custom_user:custom_pass@custom_host:5432/'
                'custom_db'
            )
            self.assertEqual(config.database_uri, expected_uri)
            self.assertEqual(config.sqlalchemy_database_uri, expected_uri)

    def test_api_version_default(self):
        """It should set the API version to 'v1' if API_VERSION is not
        provided."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            self.assertEqual(config.api_version, 'v1')

    def test_api_version_from_env(self):
        """It should use the API version provided in the environment
        variable."""
        self.assertEqual(self.config.api_version, API_VERSION)

    def test_log_level_default(self):
        """It should set the log level to 'INFO' if LOG_LEVEL is not
        provided."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            self.assertEqual(config.log_level, TEST_LOG_LEVEL)

    def test_log_level_from_env(self):
        """It should use the log level provided in the environment variable."""
        self.assertEqual(self.config.log_level, TEST_LOG_LEVEL)

    def test_secret_key_when_provided(self):
        """It should retrieve the provided SECRET_KEY from the environment."""
        self.assertEqual(self.config.secret_key, TEST_SECRET_KEY)

    def test_secret_key_generated_when_missing(self):
        """It should generate a secret key if SECRET_KEY is not set in the
        environment."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            self.assertTrue(isinstance(config.secret_key, str))
            self.assertGreaterEqual(len(config.secret_key), 20)

    def test_database_uri_not_empty(self):
        """It should always have a non-empty database_uri even if DATABASE_URI
        is missing since defaults are provided."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            expected_uri = (
                f"postgresql://{DEFAULT_USER}:{DEFAULT_PASSWORD}@{DEFAULT_HOST}"
                f":{DEFAULT_PORT}/{DEFAULT_DB_NAME}"
            )
            self.assertEqual(config.database_uri, expected_uri)

    def test_immutability(self):
        """It should be immutable."""
        with self.assertRaises(FrozenInstanceError):
            self.config.database_uri = 'new_uri'

        with self.assertRaises(FrozenInstanceError):
            self.config.sqlalchemy_database_uri = 'new_uri'

        with self.assertRaises(FrozenInstanceError):
            self.config.secret_key = 'new_secret'

        with self.assertRaises(FrozenInstanceError):
            self.config.api_version = 'new_api_version'

        with self.assertRaises(FrozenInstanceError):
            self.config.log_level = 'new_log_level'

        with self.assertRaises(FrozenInstanceError):
            self.config.sqlalchemy_track_modifications = True

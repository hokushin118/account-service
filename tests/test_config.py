"""
Configs Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from unittest import TestCase
from unittest.mock import patch

from service.configs import KafkaProducerConfig, AppConfig

TEST_DATABASE_URI = 'postgresql://test_user:test_pass@test_host:12345/test_db'
DEFAULT_USER = 'cba'
DEFAULT_PASSWORD = 'pa$$wOrd123!'
DEFAULT_DB_NAME = 'account_db'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = '15432'
TEST_KAFKA_BROKERS = 'broker1:9093,broker2:9094'


class TestAppConfig(TestCase):
    """AppConfig Class Tests."""

    def tearDown(self):
        keys_to_delete = [
            'DATABASE_URI', 'DATABASE_USER',
            'DATABASE_PASSWORD', 'DATABASE_NAME',
            'DATABASE_HOST', 'DATABASE_PORT',
            'SECRET_KEY', 'API_VERSION'
        ]
        for key in keys_to_delete:
            os.environ.pop(key, None)

    def test_database_uri_from_env(self):
        """It should use the DATABASE_URI environment variable if provided."""
        with patch.dict(os.environ, {'DATABASE_URI': TEST_DATABASE_URI}):
            config = AppConfig()
            self.assertEqual(config.database_uri, TEST_DATABASE_URI)
            self.assertEqual(config.sqlalchemy_database_uri, TEST_DATABASE_URI)

    def test_construct_database_uri_from_components(self):
        """It should construct a valid database URI from individual environment variable
        components if DATABASE_URI is not provided."""
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
                'postgresql://custom_user:custom_pass@custom_host:5432/custom_db'
            )
            self.assertEqual(config.database_uri, expected_uri)
            self.assertEqual(config.sqlalchemy_database_uri, expected_uri)

    def test_api_version_default(self):
        """It should set the API version to 'v1' if API_VERSION is not provided."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            self.assertEqual(config.api_version, 'v1')

    def test_api_version_from_env(self):
        """It should use the API version provided in the environment variable."""
        with patch.dict(os.environ, {'API_VERSION': 'v2'}):
            config = AppConfig()
            self.assertEqual(config.api_version, 'v2')

    def test_secret_key_when_provided(self):
        """It should retrieve the provided SECRET_KEY from the environment."""
        test_secret = 'my_test_secret_key'
        with patch.dict(os.environ, {'SECRET_KEY': test_secret}):
            config = AppConfig()
            self.assertEqual(config.secret_key, test_secret)

    def test_secret_key_generated_when_missing(self):
        """It should generate a secret key if SECRET_KEY is not set in the environment."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            self.assertTrue(isinstance(config.secret_key, str))
            self.assertGreaterEqual(len(config.secret_key), 20)

    def test_database_uri_not_empty(self):
        """It should always have a non-empty database_uri even if DATABASE_URI is missing
        since defaults are provided."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            expected_uri = (
                f"postgresql://{DEFAULT_USER}:{DEFAULT_PASSWORD}@{DEFAULT_HOST}"
                f":{DEFAULT_PORT}/{DEFAULT_DB_NAME}"
            )
            self.assertEqual(config.database_uri, expected_uri)


class TestKafkaProducerConfig(TestCase):
    """The KafkaProducerConfig Class Tests."""

    def test_valid_initialization(self):
        """It should initialize all attributes correctly when provided valid values."""
        config = KafkaProducerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            retries=5,
            acks='all',
            linger_ms=100,
            batch_size=1024,
            health_check_interval=60,
            compression_type='gzip'
        )
        self.assertEqual(config.bootstrap_servers, TEST_KAFKA_BROKERS)
        self.assertEqual(config.retries, 5)
        self.assertEqual(config.acks, 'all')
        self.assertEqual(config.linger_ms, 100)
        self.assertEqual(config.batch_size, 1024)
        self.assertEqual(config.health_check_interval, 60)
        self.assertEqual(config.compression_type, 'gzip')

    def test_default_compression(self):
        """It should default compression_type to None if no value is provided."""
        config = KafkaProducerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            retries=3,
            acks=1,
            linger_ms=50,
            batch_size=512,
            health_check_interval=30  # compression_type omitted intentionally
        )
        self.assertIsNone(config.compression_type)

    def test_attribute_types(self):
        """It should have the correct types for each attribute."""
        config = KafkaProducerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            retries=10,
            acks=1,
            linger_ms=200,
            batch_size=2048,
            health_check_interval=120,
            compression_type='snappy'
        )
        self.assertIsInstance(config.bootstrap_servers, str)
        self.assertIsInstance(config.retries, int)
        self.assertTrue(isinstance(config.acks, (int, str)))
        self.assertIsInstance(config.linger_ms, int)
        self.assertIsInstance(config.batch_size, int)
        self.assertIsInstance(config.health_check_interval, int)
        self.assertIsInstance(config.compression_type, str)

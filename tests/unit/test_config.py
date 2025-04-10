"""
Configs Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from dataclasses import FrozenInstanceError
from enum import Enum
from unittest import TestCase
from unittest.mock import patch

from service.configs import (
    KafkaProducerConfig,
    AppConfig,
    AutoOffsetReset,
    SecurityProtocol,
    KafkaConsumerConfig
)

TEST_DATABASE_URI = 'postgresql://test_user:test_pass@test_host:12345/test_db'
DEFAULT_USER = 'cba'
DEFAULT_PASSWORD = 'pa$$wOrd123!'
DEFAULT_DB_NAME = 'account_db'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = '15432'
TEST_KAFKA_BROKERS = 'broker1:9093,broker2:9094'
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


class TestSecurityProtocol(TestCase):
    """The SecurityProtocol Enum Tests."""

    def test_plaintext(self):
        """It should have the correct value for PLAINTEXT."""
        self.assertEqual(SecurityProtocol.PLAINTEXT, 'PLAINTEXT')

    def test_ssl(self):
        """It should have the correct value for SSL."""
        self.assertEqual(SecurityProtocol.SSL, 'SSL')

    def test_sasl_plaintext(self):
        """It should have the correct value for SASL_PLAINTEXT."""
        self.assertEqual(SecurityProtocol.SASL_PLAINTEXT, 'SASL_PLAINTEXT')

    def test_sasl_ssl(self):
        """It should have the correct value for SASL_SSL."""
        self.assertEqual(SecurityProtocol.SASL_SSL, 'SASL_SSL')

    def test_enum_members(self):
        """It should have the correct members in the enum."""
        expected_members = ['PLAINTEXT', 'SSL', 'SASL_PLAINTEXT', 'SASL_SSL']
        self.assertEqual(
            [member.name for member in SecurityProtocol],
            expected_members
        )

    def test_enum_values(self):
        """It should have the correct values in the enum."""
        expected_values = ['PLAINTEXT', 'SSL', 'SASL_PLAINTEXT', 'SASL_SSL']
        self.assertEqual(
            [member.value for member in SecurityProtocol],
            expected_values
        )

    def test_enum_type(self):
        """It should be an instance of str and Enum."""
        self.assertTrue(issubclass(SecurityProtocol, str))
        self.assertTrue(issubclass(SecurityProtocol, Enum))


class TestAutoOffsetReset(TestCase):
    """The AutoOffsetReset Enum Tests."""

    def test_latest(self):
        """It should have the correct value for LATEST."""
        self.assertEqual(AutoOffsetReset.LATEST, 'latest')

    def test_earliest(self):
        """It should have the correct value for EARLIEST."""
        self.assertEqual(AutoOffsetReset.EARLIEST, 'earliest')

    def test_none(self):
        """It should have the correct value for NONE."""
        self.assertEqual(AutoOffsetReset.NONE, 'none')

    def test_enum_members(self):
        """It should have the correct members in the enum."""
        expected_members = ['LATEST', 'EARLIEST', 'NONE']
        self.assertEqual(
            [member.name for member in AutoOffsetReset],
            expected_members
        )

    def test_enum_values(self):
        """It should have the correct values in the enum."""
        expected_values = ['latest', 'earliest', 'none']
        self.assertEqual(
            [member.value for member in AutoOffsetReset],
            expected_values
        )

    def test_enum_type(self):
        """It should be an instance of str and Enum."""
        self.assertTrue(issubclass(AutoOffsetReset, str))
        self.assertTrue(issubclass(AutoOffsetReset, Enum))


class TestKafkaConsumerConfig(TestCase):
    """The KafkaConsumerConfig Class Tests."""

    def setUp(self):
        """Sets up a KafkaConsumerConfig instance for testing."""
        self.config = KafkaConsumerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            topic='test-topic',
            key_format='str',
            message_format='json',
            auto_offset_reset=AutoOffsetReset.LATEST,
            security_protocol=SecurityProtocol.PLAINTEXT,
            ssl_ca_location=None,
            ssl_certificate_location=None,
            ssl_key_location=None,
            sasl_mechanism=None,
            sasl_username=None,
            sasl_password=None,
            group_id='test-group',
            enable_auto_commit=True,
            auto_commit_interval_ms=5000,
            max_poll_records=500,
            max_poll_interval_ms=300000,
            session_timeout_ms=10000,
            heartbeat_interval_ms=3000,
            retry_attempts=5,
            retry_delay_ms=1000,
            consumer_id='test-consumer',
            service_name='test-service'
        )

    def test_valid_initialization(self):
        """It should initialize all attributes correctly when provided valid values."""
        self.assertEqual(self.config.bootstrap_servers, TEST_KAFKA_BROKERS)
        self.assertEqual(self.config.topic, 'test-topic')
        self.assertEqual(self.config.key_format, 'str')
        self.assertEqual(self.config.message_format, 'json')
        self.assertEqual(self.config.auto_offset_reset, AutoOffsetReset.LATEST)
        self.assertEqual(self.config.security_protocol,
                         SecurityProtocol.PLAINTEXT)
        self.assertIsNone(self.config.ssl_ca_location)
        self.assertIsNone(self.config.ssl_certificate_location)
        self.assertIsNone(self.config.ssl_key_location)
        self.assertIsNone(self.config.sasl_mechanism)
        self.assertIsNone(self.config.sasl_username)
        self.assertIsNone(self.config.sasl_password)
        self.assertEqual(self.config.group_id, 'test-group')
        self.assertTrue(self.config.enable_auto_commit)
        self.assertEqual(self.config.auto_commit_interval_ms, 5000)
        self.assertEqual(self.config.max_poll_records, 500)
        self.assertEqual(self.config.max_poll_interval_ms, 300000)
        self.assertEqual(self.config.session_timeout_ms, 10000)
        self.assertEqual(self.config.heartbeat_interval_ms, 3000)
        self.assertEqual(self.config.retry_attempts, 5)
        self.assertEqual(self.config.retry_delay_ms, 1000)
        self.assertEqual(self.config.consumer_id, 'test-consumer')
        self.assertEqual(self.config.service_name, 'test-service')

    def test_default_group_id_generation(self):
        """It should generate group_id if not provided and service_name and topic are."""
        config = KafkaConsumerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            topic='test-topic',
            key_format='str',
            message_format='jsom',
            auto_offset_reset=AutoOffsetReset.LATEST,
            security_protocol=SecurityProtocol.PLAINTEXT,
            service_name='test-service'
        )
        self.assertIsNotNone(config.group_id)
        self.assertTrue(
            config.group_id.startswith('test-service-test-topic-consumer-'))

    def test_attribute_types(self):
        """It should have the correct types for each attribute."""
        self.assertIsInstance(self.config.bootstrap_servers, str)
        self.assertIsInstance(self.config.topic, str)
        self.assertIsInstance(self.config.key_format, str)
        self.assertIsInstance(self.config.message_format, str)
        self.assertIsInstance(self.config.auto_offset_reset, AutoOffsetReset)
        self.assertIsInstance(self.config.security_protocol, SecurityProtocol)
        self.assertIsInstance(self.config.ssl_ca_location, type(None))
        self.assertIsInstance(self.config.ssl_certificate_location, type(None))
        self.assertIsInstance(self.config.ssl_key_location, type(None))
        self.assertIsInstance(self.config.sasl_mechanism, type(None))
        self.assertIsInstance(self.config.sasl_username, type(None))
        self.assertIsInstance(self.config.sasl_password, type(None))
        self.assertIsInstance(self.config.group_id, str)
        self.assertIsInstance(self.config.enable_auto_commit, bool)
        self.assertIsInstance(self.config.auto_commit_interval_ms, int)
        self.assertIsInstance(self.config.max_poll_records, int)
        self.assertIsInstance(self.config.max_poll_interval_ms, int)
        self.assertIsInstance(self.config.session_timeout_ms, int)
        self.assertIsInstance(self.config.heartbeat_interval_ms, int)
        self.assertIsInstance(self.config.retry_attempts, int)
        self.assertIsInstance(self.config.retry_delay_ms, int)
        self.assertIsInstance(self.config.consumer_id, str)
        self.assertIsInstance(self.config.service_name, str)

    def test_immutability(self):
        """It should be immutable."""
        with self.assertRaises(FrozenInstanceError):
            self.config.bootstrap_servers = 'new_server:9092'
        with self.assertRaises(FrozenInstanceError):
            self.config.topic = 'new_topic'
        with self.assertRaises(FrozenInstanceError):
            self.config.key_format = 'json'
        with self.assertRaises(FrozenInstanceError):
            self.config.message_format = 'json'
        with self.assertRaises(FrozenInstanceError):
            self.config.auto_offset_reset = AutoOffsetReset.EARLIEST
        with self.assertRaises(FrozenInstanceError):
            self.config.security_protocol = SecurityProtocol.SSL
        with self.assertRaises(FrozenInstanceError):
            self.config.group_id = 'new_group'
        with self.assertRaises(FrozenInstanceError):
            self.config.enable_auto_commit = False
        with self.assertRaises(FrozenInstanceError):
            self.config.auto_commit_interval_ms = 1000
        with self.assertRaises(FrozenInstanceError):
            self.config.max_poll_records = 100
        with self.assertRaises(FrozenInstanceError):
            self.config.max_poll_interval_ms = 100000
        with self.assertRaises(FrozenInstanceError):
            self.config.session_timeout_ms = 5000
        with self.assertRaises(FrozenInstanceError):
            self.config.heartbeat_interval_ms = 1000
        with self.assertRaises(FrozenInstanceError):
            self.config.retry_attempts = 1
        with self.assertRaises(FrozenInstanceError):
            self.config.retry_delay_ms = 500
        with self.assertRaises(FrozenInstanceError):
            self.config.consumer_id = 'new_consumer'
        with self.assertRaises(FrozenInstanceError):
            self.config.service_name = 'new_service'


class TestKafkaProducerConfig(TestCase):
    """The KafkaProducerConfig Class Tests."""

    def setUp(self):
        """Sets up a KafkaProducerConfig instance for testing."""
        self.config = KafkaProducerConfig(
            bootstrap_servers=TEST_KAFKA_BROKERS,
            retries=5,
            acks='all',
            linger_ms=100,
            batch_size=1024,
            health_check_interval=60,
            compression_type='gzip'
        )

    def test_valid_initialization(self):
        """It should initialize all attributes correctly when provided valid values."""
        self.assertEqual(self.config.bootstrap_servers, TEST_KAFKA_BROKERS)
        self.assertEqual(self.config.retries, 5)
        self.assertEqual(self.config.acks, 'all')
        self.assertEqual(self.config.linger_ms, 100)
        self.assertEqual(self.config.batch_size, 1024)
        self.assertEqual(self.config.health_check_interval, 60)
        self.assertEqual(self.config.compression_type, 'gzip')

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
        self.assertIsInstance(self.config.bootstrap_servers, str)
        self.assertIsInstance(self.config.retries, int)
        self.assertTrue(isinstance(self.config.acks, (int, str)))
        self.assertIsInstance(self.config.linger_ms, int)
        self.assertIsInstance(self.config.batch_size, int)
        self.assertIsInstance(self.config.health_check_interval, int)
        self.assertIsInstance(self.config.compression_type, str)

    def test_immutability(self):
        """It should be immutable."""
        with self.assertRaises(FrozenInstanceError):
            self.config.retries = 5

        with self.assertRaises(FrozenInstanceError):
            self.config.bootstrap_servers = 'new_server:9092'

        with self.assertRaises(FrozenInstanceError):
            self.config.acks = 1

        with self.assertRaises(FrozenInstanceError):
            self.config.linger_ms = 10

        with self.assertRaises(FrozenInstanceError):
            self.config.batch_size = 2048

        with self.assertRaises(FrozenInstanceError):
            self.config.health_check_interval = 20

        with self.assertRaises(FrozenInstanceError):
            self.config.compression_type = 'snappy'

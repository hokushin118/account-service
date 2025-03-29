"""
Kafka Consumer Manager Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import Mock, patch

from kafka.errors import (
    KafkaConnectionError,
)

from service.configs import (
    KafkaConsumerConfig,
    SecurityProtocol,
    AutoOffsetReset
)
from service.kafka.kafka_consumer import KafkaConsumerManager
from tests.utils.constants import TEST_TOPIC


class TestKafkaConsumerManager(TestCase):
    """The KafkaConsumerManager Tests."""

    def setUp(self):
        """It should set up a dummy configuration and prevent the health check
        thread from starting."""
        self.config = KafkaConsumerConfig(
            bootstrap_servers='localhost:9092',
            topic=TEST_TOPIC,
            group_id='test_group',
            auto_offset_reset=AutoOffsetReset.EARLIEST,
            enable_auto_commit=False,
            security_protocol=SecurityProtocol.PLAINTEXT,
            key_format='str',
            message_format='str',
            max_poll_interval_ms=10000,
        )
        # Patch the _start_health_check_thread method to do nothing to avoid
        # starting an endless loop.
        patcher = patch.object(
            KafkaConsumerManager,
            '_start_health_check_thread',
            lambda self: None
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.message_handler = Mock()
        self.manager = KafkaConsumerManager(self.config, self.message_handler)

    def test_init_failure(self):
        """It should return None when the Kafka broker is unavailable during initialization."""
        with patch('logging.Logger.error'):
            self.assertIsNone(self.manager._consumer)  # pylint: disable=W0212

    def test_close_consumer(self):
        """It should set the consumer to None after closing it."""
        self.manager.close_consumer()
        self.assertIsNone(self.manager._consumer)  # pylint: disable=W0212

    @patch('kafka.KafkaConsumer')
    def test_is_consumer_healthy_failure(self, mock_kafka_consumer):
        """It should return False when the consumer encounters a connection error."""
        mock_consumer = Mock()
        mock_consumer.topics.side_effect = KafkaConnectionError
        mock_kafka_consumer.return_value = mock_consumer
        manager = KafkaConsumerManager(self.config, self.message_handler)
        self.assertFalse(manager.is_consumer_healthy())

    def test_validate_config_success(self):
        """It should not raise any exceptions when the configuration is valid."""
        # pylint: disable=W0212
        KafkaConsumerManager._validate_config(self.config)

    def test_validate_config_failure(self):
        """It should raise ValueError when the configuration is invalid."""
        invalid_config = KafkaConsumerConfig(
            bootstrap_servers=None,
            topic=TEST_TOPIC,
            group_id='test_group',
            auto_offset_reset=AutoOffsetReset.EARLIEST,
            enable_auto_commit=False,
            security_protocol=SecurityProtocol.PLAINTEXT,
            key_format='str',
            message_format='str',
            max_poll_interval_ms=10000,
        )
        with self.assertRaises(ValueError):
            # pylint: disable=W0212
            KafkaConsumerManager._validate_config(invalid_config)

    def test_get_health_check_interval(self):
        """It should return the correct health check interval based on max_poll_interval_ms."""
        self.assertEqual(
            # pylint: disable=W0212
            KafkaConsumerManager._get_health_check_interval(10000),
            10
        )
        self.assertEqual(
            # pylint: disable=W0212
            KafkaConsumerManager._get_health_check_interval(None),
            300
        )

    def test_get_deserializer_json(self):
        """It should return a JSON deserialized object."""
        # pylint: disable=W0212
        deserializer = KafkaConsumerManager._get_deserializer('json')
        self.assertEqual(deserializer(b'{"key": "value"}'), {'key': 'value'})

    def test_get_deserializer_str(self):
        """It should return a string deserialized object."""
        # pylint: disable=W0212
        deserializer = KafkaConsumerManager._get_deserializer('str')
        self.assertEqual(deserializer(b"test"), 'test')

    def test_get_deserializer_none(self):
        """It should return None for an invalid deserializer format."""
        # pylint: disable=W0212
        deserializer = KafkaConsumerManager._get_deserializer('invalid')
        self.assertIsNone(deserializer)

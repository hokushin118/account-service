"""
Kafka Config Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase

from service.configs.kafka_config import KafkaProducerConfig

TEST_KAFKA_BROKERS = 'broker1:9093,broker2:9094'


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

"""
Kafka Producer Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch

from service.common.kafka_producer import KafkaProducerManager
from tests.utils.utils import DummyKafkaProducerConfig, DummyKafkaProducer, \
    DummyKafkaProducerError


class TestKafkaProducerManager(TestCase):
    """The KafkaProducerManager Tests."""

    def setUp(self):
        """It should set up a dummy configuration and prevent the health check
        thread from starting."""
        self.config = DummyKafkaProducerConfig(
            bootstrap_servers='kafka:9093',
            retries=3,
            acks=1,
            linger_ms=5,
            batch_size=100,
            health_check_interval=60
        )
        # Patch the _start_health_check_thread method to do nothing to avoid
        # starting an endless loop.
        patcher = patch.object(
            KafkaProducerManager,
            '_start_health_check_thread',
            lambda self: None
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.manager = KafkaProducerManager(self.config)

    def test_validate_non_negative_valid(self):
        """It should return the same non-negative value when given a valid integer."""
        # pylint: disable=W0212
        self.assertEqual(KafkaProducerManager._validate_non_negative(5), 5)

    def test_validate_non_negative_invalid(self):
        """It should raise ValueError when given a negative integer for non-negative validation."""
        with self.assertRaises(ValueError):
            # pylint: disable=W0212
            KafkaProducerManager._validate_non_negative(-1)

    def test_validate_acks_valid(self):
        """It should return the same value when the acks parameter is one of the allowed options."""
        # pylint: disable=W0212
        self.assertEqual(KafkaProducerManager._validate_acks(1), 1)
        self.assertEqual(KafkaProducerManager._validate_acks("all"), "all")

    def test_validate_acks_invalid(self):
        """It should raise ValueError when an invalid acks value is provided."""
        with self.assertRaises(ValueError):
            # pylint: disable=W0212
            KafkaProducerManager._validate_acks(2)

    @patch(
        'service.common.kafka_producer.KafkaProducerManager',
        new=DummyKafkaProducer
    )
    def test_close_producer(self):
        """It should close the KafkaProducer and unset the producer instance."""
        dummy_producer = DummyKafkaProducer()
        # pylint: disable=W0212
        self.manager._producer = dummy_producer
        self.manager.close_producer()
        self.assertTrue(dummy_producer.closed)
        # pylint: disable=W0212
        self.assertIsNone(self.manager._producer)

    def test_is_producer_healthy_when_none(self):
        """It should return False if no producer has been initialized."""
        # pylint: disable=W0212
        self.manager._producer = None
        self.assertFalse(self.manager.is_producer_healthy())

    @patch(
        'service.common.kafka_producer.KafkaProducerManager',
        new=DummyKafkaProducer
    )
    def test_is_producer_healthy_success(self):
        """It should return True when the producer is healthy."""
        # pylint: disable=W0212
        self.manager._producer = DummyKafkaProducer()
        self.assertTrue(self.manager.is_producer_healthy())

    def test_is_producer_healthy_failure(self):
        """It should return False when the producer raises a connection error
        during health check."""
        # pylint: disable=W0212
        self.manager._producer = DummyKafkaProducerError()
        self.assertFalse(self.manager.is_producer_healthy())

    @patch(
        'service.common.kafka_producer.KafkaProducerManager',
        new=DummyKafkaProducer
    )
    def test_reinitialize_producer(self):
        """It should close the existing producer and create a new one during reinitialization."""
        original_producer = DummyKafkaProducer()
        # pylint: disable=W0212
        self.manager._producer = original_producer
        # Patch get_producer to return a new DummyKafkaProducer instance.
        with patch.object(
                self.manager,
                'get_producer',
                return_value=DummyKafkaProducer()
        ) as mock_get:
            self.manager._reinitialize_producer()
            mock_get.assert_called_once()
            self.assertIsNot(self.manager._producer, original_producer)

    def test_async_init_failure(self):
        """It should catch exceptions during asynchronous initialization and leave
        producer as None."""
        # Patch KafkaProducer to always raise an exception.
        with patch(
                'service.common.kafka_producer.KafkaProducerManager',
                side_effect=Exception('Init error')
        ):
            self.manager._producer = None  # pylint: disable=W0212
            self.manager._async_init()  # pylint: disable=W0212
            self.assertIsNone(self.manager._producer)  # pylint: disable=W0212

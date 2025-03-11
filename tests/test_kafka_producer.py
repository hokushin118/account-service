"""
Kafka Producer Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from typing import Union, Optional
from unittest import TestCase
from unittest.mock import patch

from kafka.errors import KafkaConnectionError  # pylint: disable=E0401

from service.common.kafka_producer import KafkaProducerManager
from service.configs.kafka_config import KafkaProducerConfig


class DummyKafkaProducer:
    """A dummy KafkaProducer that simulates a healthy producer."""

    def __init__(self) -> None:
        """It should initialize a DummyKafkaProducer instance.

        Sets the 'closed' attribute to False indicating that the producer is active.
        """
        self.closed = False

    def close(self) -> None:
        """It should simulate closing the producer.

        Marks the producer as closed by setting the 'closed' attribute to True.
        """
        self.closed = True

    def partitions_for(self, topic: str) -> Optional[set[int]]:
        """It should return a dummy non-empty set for the internal consumer offsets topic,
        and None for any other topic.

        Args:
            topic (str): The topic name for which partitions are requested.

        Returns:
            set[int] or None: A set of partition numbers for the consumer offsets topic, or
            None if the topic is not recognized.
        """
        if topic == KafkaProducerManager.CONSUMER_OFFSETS_TOPIC:
            return {0, 1}
        return None


class DummyKafkaProducerError:
    """A dummy KafkaProducer that simulates failure in health check."""

    def partitions_for(self, topic: str) -> None:
        """It should simulate a failure when attempting to retrieve partition information.

        Args:
            topic (str): The name of the topic for which partition information is requested.

        Raises:
            KafkaConnectionError: Always raised to simulate a Kafka connection error.
        """
        raise KafkaConnectionError('Simulated connection error')


class DummyKafkaProducerConfig(KafkaProducerConfig):
    """A dummy KafkaProducerConfig for testing purposes."""

    def __init__(self,
                 bootstrap_servers: str,
                 retries: int,
                 acks: Union[int, str],
                 linger_ms: int,
                 batch_size: int,
                 health_check_interval: int
                 ) -> None:
        """
        Initialize the KafkaProducer configuration with test-specific settings.

        This constructor calls the base class constructor to initialize the configuration
        parameters such as bootstrap servers, retries, acknowledgments, linger time, batch size,
        and health check interval. Additionally, it sets the compression_type to "gzip" for testing.

        Args:
            bootstrap_servers (str): A comma-separated list of Kafka bootstrap servers.
            retries (int): The number of retry attempts for sending messages.
            acks (Union[int, str]): The acknowledgment level ('all', 0, 1, etc.).
            linger_ms (int): The maximum time (in milliseconds) to buffer data before sending.
            batch_size (int): The maximum size (in bytes) of a batch of messages.
            health_check_interval (int): The interval (in seconds) for performing health checks.
        """
        super().__init__(
            bootstrap_servers,
            retries,
            acks,
            linger_ms,
            batch_size,
            health_check_interval
        )
        self.compression_type = 'gzip'


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

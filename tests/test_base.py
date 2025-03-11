"""
Test Base Module.

This module defines a base test class for Flask-based tests by extending
Python’s built-in unittest.TestCase.
"""
import json
from typing import Optional, Union
from unittest import TestCase

from flask import Flask, Response
from flask_jwt_extended import JWTManager
from kafka.errors import KafkaConnectionError  # pylint: disable=E0401

from service.common import status
from service.common.kafka_producer import KafkaProducerManager
from service.configs.kafka_config import KafkaProducerConfig
from tests.test_constants import JWT_SECRET_KEY, TEST_TOPIC


class DummyRecordMetadata:
    """DummyRecordMetadata is a mock class that simulates the RecordMetadata object returned
    by a KafkaProducer upon successful message send.

    It stores key information about the sent message, such as the topic,
    partition, and offset.
    """

    def __init__(self, topic, partition, offset):
        """Initialize the dummy record metadata with the given topic,
        partition, and offset.

        Args:
            topic: The Kafka topic to which the message was published.
            partition: The partition within the topic.
            offset: The offset of the message within the partition.
        """
        self.topic = topic
        self.partition = partition
        self.offset = offset


class DummyKafkaProducer:
    """A dummy KafkaProducer that simulates a healthy producer."""

    def __init__(self) -> None:
        """It should initialize a DummyKafkaProducer instance.

        Sets the 'closed' attribute to False indicating that the producer is active.
        """
        self.messages = []  # Record the sent messages
        self.closed = False

    def send(self, topic, key, value):
        """Simulate sending a message to Kafka by storing the message details.

        Args:
            topic: The Kafka topic to which the message is sent.
            key: The key of the message.
            value: The payload or content of the message.

        Returns:
            DummyFuture: A dummy future object simulating asynchronous send behavior.
        """
        self.messages.append((topic, key, value))
        return DummyFuture()

    def flush(self):
        """Simulate flushing any buffered messages.

        In this dummy implementation, no action is needed.
        """

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


class DummyFuture:
    """DummyFuture is a mock future object representing the asynchronous result of a send operation.

    It should allow attaching callback and error callback functions that simulate handling of
    success or failure of the send operation.
    """

    def add_callback(self, function):
        """Simulate attaching a callback that is invoked upon a successful
        send.

        Args:
            function: The callback function to be executed, receiving dummy metadata.

        Returns:
            DummyFuture: The current DummyFuture instance (to allow chaining).
        """
        dummy_metadata = DummyRecordMetadata(
            TEST_TOPIC,
            0,
            0
        )
        function(dummy_metadata)
        return self

    def add_errback(self, function):
        """Simulate attaching an error callback that is invoked
        when a send error occurs.

        Args:
            function: The error callback function to be executed.

        Returns:
            DummyFuture: The current DummyFuture instance (to allow chaining).
        """
        function()
        return self


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

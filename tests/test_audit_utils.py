"""
Audit Utils Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import json
from unittest import TestCase
from unittest.mock import patch

from flask import request, Response

from service.common import status
from service.common.audit_utils import (
    get_request_body_or_none,
    on_send_success,
    on_send_error,
    audit_log_kafka
)
from tests.test_base import BaseTestCase
from tests.test_constants import TEST_PATH

TEST_TOPIC = 'test_topic'


######################################################################
#  AUDIT UTILS TEST CASES
######################################################################

# Dummy classes for simulating external components

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
    """DummyKafkaProducer is a mock Kafka producer used for testing purposes.

    It should record messages that would have been sent to Kafka, enabling verification
    of message sending logic during tests.
    """

    def __init__(self):
        """Initialize the dummy Kafka producer with an empty list of messages."""
        self.messages = []  # Record the sent messages

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


class TestGetRequestBodyOrNone(BaseTestCase):
    """The get_request_body_or_none Function Tests."""

    def test_json_body(self):
        """It should return a dictionary when a valid JSON body is provided."""
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                json={'key': 'value'}
        ):
            result = get_request_body_or_none()
            self.assertEqual(result, {'key': 'value'})

    def test_empty_body(self):
        """It should return None when the request body is empty."""
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                data='',
                content_type='application/json'
        ):
            result = get_request_body_or_none()
            self.assertIsNone(result)

    def test_invalid_json_body(self):
        """It should return None and log an error when an invalid JSON body is provided."""
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                data='{invalid: json',
                content_type='application/json'
        ):
            with self.assertLogs(
                    'service.common.audit_utils',
                    level='ERROR'
            ) as common_module:
                result = get_request_body_or_none()
                self.assertIsNone(result)
                # Check that error log includes a message about JSON decode failure.
                self.assertIn(
                    'Unexpected error during JSON processing:',
                    ''.join(common_module.output)
                )

    def test_text_body(self):
        """It should return the text data as-is when a non-JSON plain text body is provided."""
        text_data = 'plain text'
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                data=text_data,
                content_type='text/plain'
        ):
            result = get_request_body_or_none()
            self.assertEqual(result, text_data)


class TestCallbacks(TestCase):
    """Kafka Callback Functions Tests."""

    def test_on_send_success_logs_info(self):
        """It should log an info message with topic, key, partition, and offset o
        n successful send."""
        record_metadata = DummyRecordMetadata(TEST_TOPIC, 1, 42)
        key = b"test_key"
        with self.assertLogs(
                'service.common.audit_utils',
                level='INFO'
        ) as common_module:
            on_send_success(record_metadata, key)
            log_output = "\n".join(common_module.output)
            self.assertIn('Kafka message sent successfully', log_output)
            self.assertIn(TEST_TOPIC, log_output)
            self.assertIn('test_key', log_output)
            self.assertIn('42', log_output)

    def test_on_send_error_logs_error(self):
        """It should log an error message with the provided error details on send failure."""
        error = Exception('Test error')
        with self.assertLogs(
                'service.common.audit_utils',
                level='ERROR'
        ) as common_module:
            on_send_error(error)
            log_output = "\n".join(common_module.output)
            self.assertIn('Error occurred during Kafka send', log_output)
            self.assertIn('Test error', log_output)


class TestAuditLogKafkaDecorator(BaseTestCase):
    """The audit_log_kafka Decorator Tests."""

    def _setup_request_context(
            self,
            method='POST',
            json_data=None,
            data_text=None
    ):
        if json_data is not None:
            return self.app.test_request_context(
                TEST_PATH,
                method=method,
                json=json_data
            )
        return self.app.test_request_context(
            TEST_PATH,
            method=method,
            data=data_text,
            content_type='text/plain'
        )

    def test_decorator_success(self, ):
        """It should apply the audit_log_kafka decorator successfully when JWT is verified."""
        with patch('kafka.KafkaProducer') as mock_producer:
            mock_producer_instance = mock_producer.return_value
            mock_producer_instance.send.return_value.add_callback \
                .return_value.add_errback.return_value = None

            decorated = audit_log_kafka(dummy_route_success)
            with self._setup_request_context(
                    method='POST',
                    json_data={'input': 'data'}
            ):
                request.remote_addr = '127.0.0.1'
                response = decorated()
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                response_data = json.loads(response.get_data(as_text=True))
                self.assertTrue(response_data.get('success'))

    def test_decorator_jwt_failure(self):
        """It should execute the decorated function without audit logging
        when JWT verification fails."""
        decorated = audit_log_kafka(dummy_route_success)
        with self._setup_request_context(method='GET'):
            response = decorated()
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_decorator_route_failure(self):
        """It should propagate the exception when the wrapped route fails."""
        with patch('kafka.KafkaProducer') as mock_producer:
            mock_producer_instance = mock_producer.return_value
            mock_producer_instance.send.return_value.add_callback \
                .return_value.add_errback.return_value = None
            decorated = audit_log_kafka(dummy_route_failure)
            with self._setup_request_context(method='GET'):
                with self.assertRaises(Exception) as context:
                    decorated()
                self.assertIn('Route failure occurred', str(context.exception))

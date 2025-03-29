"""
Audit Utils Integration Test Suite.

Test cases can be run with the following:
  APP_SETTINGS=testing nosetests -v --with-spec --spec-color
  coverage report -m
"""
import json
import os
import unittest
from unittest.mock import patch

from flask import request

from service.common import status
from service.common.audit import AuditLogger
from tests.integration.base import (
    BaseTestCase,
    dummy_route_success,
    dummy_route_failure
)
from tests.utils.constants import TEST_PATH


######################################################################
#  AUDIT UTILS INTEGRATION TEST CASES
######################################################################
@unittest.skipIf(
    os.getenv('RUN_INTEGRATION_TESTS') != 'true',
    'Integration tests skipped'
)
class TestGetRequestBodyOrNone(BaseTestCase):
    """The get_request_body_or_none Function Tests."""

    def test_json_body(self):
        """It should return a dictionary when a valid JSON body is provided."""
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                json={'key': 'value'}
        ):
            result = AuditLogger.get_request_body_or_none()
            self.assertEqual(result, {'key': 'value'})

    def test_empty_body(self):
        """It should return None when the request body is empty."""
        with self.app.test_request_context(
                TEST_PATH,
                method='POST',
                data='',
                content_type='application/json'
        ):
            result = AuditLogger.get_request_body_or_none()
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
                    'service.common.audit',
                    level='ERROR'
            ) as common_module:
                result = AuditLogger.get_request_body_or_none()
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
            result = AuditLogger.get_request_body_or_none()
            self.assertEqual(result, text_data)


@unittest.skipIf(
    os.getenv('RUN_INTEGRATION_TESTS') != 'true',
    'Integration tests skipped'
)
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

            audit_logger = AuditLogger()
            decorated = audit_logger.audit_log_kafka(dummy_route_success)
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
        audit_logger = AuditLogger()
        decorated = audit_logger.audit_log_kafka(dummy_route_success)
        with self._setup_request_context(method='GET'):
            response = decorated()
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_decorator_route_failure(self):
        """It should propagate the exception when the wrapped route fails."""
        with patch('kafka.KafkaProducer') as mock_producer:
            mock_producer_instance = mock_producer.return_value
            mock_producer_instance.send.return_value.add_callback \
                .return_value.add_errback.return_value = None
            audit_logger = AuditLogger()
            decorated = audit_logger.audit_log_kafka(dummy_route_failure)
            with self._setup_request_context(method='GET'):
                with self.assertRaises(Exception) as context:
                    decorated()
                self.assertIn('Route failure occurred', str(context.exception))

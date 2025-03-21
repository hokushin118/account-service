"""
Audit Utils Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase

from service.common.audit_utils import (
    on_send_success,
    on_send_error
)
from tests.utils.constants import TEST_TOPIC
from tests.utils.utils import DummyRecordMetadata


######################################################################
#  AUDIT UTILS TEST CASES
######################################################################
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

"""
Account Routes Unit Test Suite.

Test cases can be run with:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch

from service.routes import (
    audit_log
)

ORIGINAL = 'original'


######################################################################
#  AUDIT LOG DECORATOR TEST CASES
######################################################################
def dummy_function() -> str:
    """A simple dummy function to test the audit_log decorator."""
    return ORIGINAL


class TestAuditLogDecorator(TestCase):
    """Audit Log Decorator Tests."""

    def test_audit_enabled(self):
        """It should apply audit logging when AUDIT_ENABLED is True."""
        with patch('service.routes.AUDIT_ENABLED', True), \
                patch(
                    'service.common.audit.AuditLogger.audit_log_kafka',
                    side_effect=lambda f: f
                ) as mock_audit_log_kafka:
            decorated = audit_log(dummy_function)
            mock_audit_log_kafka.assert_called_once_with(dummy_function)
            self.assertEqual(decorated(), ORIGINAL)

    def test_audit_disabled(self):
        """It should not apply audit logging when AUDIT_ENABLED is False."""
        with patch('service.routes.AUDIT_ENABLED', False):
            result_function = audit_log(dummy_function)
            self.assertIs(result_function, dummy_function)
            self.assertEqual(result_function(), ORIGINAL)

"""
Audit Utils Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
from unittest import TestCase
from unittest.mock import patch

from flask import Flask

from service.common import audit_utils
from service.common.audit_utils import audit_log


class TestAuditLogDecorator(TestCase):
    """The Audit Utils Module Tests."""

    def setUp(self):
        """Set up a basic Flask app for each test."""
        self.app = Flask(__name__)
        self.app.flask_audit_adapter = None
        self.logger = logging.getLogger('service.common.audit_utils')
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        """Clean up any potentially lingering current_app reference."""
        audit_utils.current_app = None

    def test_audit_enabled_adapter_missing(self):
        """It should verify original function runs and warns
        if audit enabled but adapter missing."""
        self.app.config['AUDIT_ENABLED'] = True
        self.app.flask_audit_adapter = None

        expected_result = 'Original Result Missing Adapter'

        @audit_log
        def dummy_route():
            return expected_result

        with self.assertLogs(
                self.logger,
                level='WARNING'
        ) as context_manager:
            with self.app.app_context():
                result = dummy_route()

        self.assertEqual(result, expected_result)
        self.assertIn(
            'AUDIT_ENABLED is True, but FlaskAuditAdapter not found or '
            'incorrectly configured on current_app. Skipping audit for '
            'dummy_route.',
            context_manager.output[0]
        )

    def test_audit_enabled_adapter_wrong_type(self):
        """It should verify original function runs and warns if
        adapter is wrong type."""
        self.app.config['AUDIT_ENABLED'] = True
        self.app.flask_audit_adapter = 'not_an_adapter_instance'

        expected_result = 'Original Result Wrong Type'

        @audit_log
        def dummy_route():
            return expected_result

        with self.assertLogs(
                self.logger,
                level='WARNING'
        ) as context_manager:
            with self.app.app_context():
                result = dummy_route()

        self.assertEqual(result, expected_result)
        self.assertIn(
            'Error accessing current_app.config for AUDIT_ENABLED',
            context_manager.output[0]
        )

    def test_decorating_non_function(self):
        """It should verify TypeError is raised if decorating
        something other than a function."""
        with self.assertRaisesRegex(
                TypeError,
                'Expected a function'
        ):
            @audit_log
            class MyClass:  # pylint: disable=W0612
                """Dummy class."""

        with self.assertRaisesRegex(
                TypeError,
                'Expected a function'
        ):
            _ = audit_log(123)

    @patch('service.common.audit_utils.current_app')
    def test_error_accessing_config(
            self,
            mock_current_app
    ):
        """It should verify original runs and logs error if
        config access fails."""
        mock_current_app.config.get.side_effect = AttributeError(
            'Simulated config error'
        )

        expected_result = 'Original Result Config Error'

        @audit_log
        def dummy_route():
            return expected_result

        with self.assertLogs(
                self.logger,
                level='ERROR'
        ) as context_manager:
            result = dummy_route()

        self.assertEqual(result, expected_result)
        self.assertIn(
            'Error accessing current_app.config',
            context_manager.output[0]
        )
        self.assertIn(
            'Simulated config error',
            context_manager.output[0]
        )
        mock_current_app.config.get.assert_called_once_with(
            'AUDIT_ENABLED',
            False
        )

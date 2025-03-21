"""
Log Handler Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import io
import logging
import sys
from unittest import TestCase

from flask import Flask

from service.common.log_handlers import init_logging, \
    LOG_FORMAT  # Update as needed

TEST_ERROR_OUTPUT = 'Test error output'
TEST_INFO_OUTPUT = 'Test info output'


class TestInitLogging(TestCase):
    """The init_logging Function Tests."""

    def setUp(self):
        """It should set up a Flask application and capture stdout/stderr."""
        self.app = Flask(__name__)
        self.app.testing = True
        # Patch sys.stdout and sys.stderr with StringIO buffers
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        sys.stdout = self.stdout
        sys.stderr = self.stderr

    def tearDown(self):
        """It should restore the original stdout and stderr."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    def test_init_logging_configures_handlers(self):
        """It should configure the Flask logger with two handlers and set proper
        levels and formatters."""
        # Call the logging initialization
        init_logging(self.app)
        handlers = self.app.logger.handlers

        # Verify that exactly two handlers are attached.
        self.assertEqual(
            len(handlers),
            2,
            'There should be exactly 2 handlers attached to the logger.'
        )

        stdout_handler = None
        stderr_handler = None
        # Identify the stdout and stderr handlers by checking their 'stream' attribute.
        for handler in handlers:
            if getattr(handler, 'stream', None) is sys.stdout:
                stdout_handler = handler
            elif getattr(handler, 'stream', None) is sys.stderr:
                stderr_handler = handler

        self.assertIsNotNone(
            stdout_handler,
            'A stdout handler should be configured.'
        )
        self.assertIsNotNone(
            stderr_handler,
            'A stderr handler should be configured.'
        )

        # Check that the stdout handler has the expected level (INFO) and
        # flush set to sys.stdout.flush.
        self.assertEqual(stdout_handler.level, logging.INFO)
        self.assertEqual(stdout_handler.flush, sys.stdout.flush)
        # Check that the stderr handler is set at ERROR level and flush set to sys.stderr.flush.
        self.assertEqual(stderr_handler.level, logging.ERROR)
        self.assertEqual(stderr_handler.flush, sys.stderr.flush)

        # Verify formatter format string is as expected.
        expected_format = LOG_FORMAT
        # pylint: disable=W0212
        self.assertEqual(stdout_handler.formatter._fmt, expected_format)
        # pylint: disable=W0212
        self.assertEqual(stderr_handler.formatter._fmt, expected_format)

        # Verify that the overall app logger level is set correctly.
        self.assertEqual(self.app.logger.level, logging.INFO)

    def test_logging_message_output(self):
        """It should output info messages to stdout and error messages to stderr."""
        # Initialize logging
        init_logging(self.app)
        # Clear buffers
        self.stdout.truncate(0)
        self.stdout.seek(0)
        self.stderr.truncate(0)
        self.stderr.seek(0)

        # Log messages at different levels.
        self.app.logger.info(TEST_INFO_OUTPUT)
        self.app.logger.error(TEST_ERROR_OUTPUT)
        # Flush the handlers to ensure output is written to our buffers.
        for handler in self.app.logger.handlers:
            handler.flush()

        stdout_output = self.stdout.getvalue()
        stderr_output = self.stderr.getvalue()

        # The info message should appear in stdout.
        self.assertIn(TEST_INFO_OUTPUT, stdout_output)
        # The error message should appear in stderr.
        self.assertIn(TEST_ERROR_OUTPUT, stderr_output)

"""
Utils Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import sys
from unittest import TestCase

from service.common.utils import (
    count_requests,
    is_flask_cli_alternative
)


######################################################################
#  UTILS UNIT TEST CASES
######################################################################
class TestUtils(TestCase):
    """The Decorated Function Tests."""

    def test_count_requests_wraps(self):
        """It should preserve function metadata."""

        @count_requests
        def test_route():
            """Test route docstring"""
            return 'Test Route'

        self.assertEqual(
            test_route.__name__,
            'test_route'
        )  # Check if name is preserved
        self.assertEqual(
            test_route.__doc__,
            'Test route docstring'
        )  # Check if docstring is preserved

    def test_count_requests_no_request_context(self):
        """It should raise an error when called outside of context."""

        @count_requests
        def test_route():
            return "Test Route"

        with self.assertRaises(RuntimeError) as context:
            test_route()
        self.assertIn(
            'Working outside of request context',
            str(context.exception)
        )


class TestFlaskCliAlternative(TestCase):
    """The is_flask_cli_alternative Function Tests."""

    def setUp(self):
        self.original_argv = sys.argv.copy()

    def tearDown(self):
        sys.argv = self.original_argv

    def test_with_flask_command(self):
        """# It should return True when sys.argv contains a recognized Flask command."""
        sys.argv = ['flask', 'run']
        self.assertTrue(is_flask_cli_alternative())

    def test_with_flask_command_in_different_position(self):
        """It should return True when sys.argv contains a recognized Flask command in
        a different position."""
        sys.argv = ['some_script.py', 'shell']
        self.assertTrue(is_flask_cli_alternative())

    def test_without_flask_command(self):
        """It should return False when sys.argv does not contain any recognized Flask command."""
        sys.argv = ['python', 'app.py']
        self.assertFalse(is_flask_cli_alternative())

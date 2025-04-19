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
#
#
# class TestGetCurrentUserId(TestCase):
#     @patch('service.common.keycloak_utils.get_jwt_identity')
#     @patch('service.common.keycloak_utils.verify_jwt_in_request')
#     def test_returns_user_id_when_authenticated(self, mock_verify_jwt,
#                                                 mock_get_identity):
#         # Arrange: simulate an authenticated user by having verify_jwt_in_request succeed
#         # and get_jwt_identity return a valid user id.
#         expected_user_id = 'user123'
#         mock_get_identity.return_value = expected_user_id
#
#         # Act: Call the function under test.
#         actual_user_id = get_current_user_id()
#
#         # Assert: The result should be the expected user id.
#         self.assertEqual(actual_user_id, expected_user_id)
#         mock_verify_jwt.assert_called_once()
#         mock_get_identity.assert_called_once()
#
#     @patch('service.common.keycloak_utils.logging.error')
#     @patch('service.common.keycloak_utils.verify_jwt_in_request')
#     def test_returns_none_when_exception_occurs(self, mock_verify_jwt,
#                                                 mock_logging_error):
#         # Arrange: simulate an exception during jwt verification.
#         mock_verify_jwt.side_effect = Exception("Authentication failed")
#
#         # Act: Call the function under test.
#         actual_user_id = get_current_user_id()
#
#         # Assert: The function should return None because of the exception.
#         self.assertIsNone(actual_user_id)
#
#         # Additionally, check that logging.error was called.
#         mock_logging_error.assert_called_once()
#         # Optionally, check if the log message contains part of expected error message.
#         log_call_args = mock_logging_error.call_args[0]
#         self.assertIn("Authentication failed", log_call_args[1])

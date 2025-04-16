"""
Custom Errors Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from uuid import uuid4

from cba_core_lib.utils.enums import UserRole

from service.errors import (
    AccountError,
    AccountNotFoundError,
    AccountAuthorizationError
)


class TestAccountError(TestCase):
    """The AccountError Base Exception Class Tests."""

    def test_account_error_str_and_to_dict(self):
        """It should return the provided error message in __str__ and in the to_dict output."""
        message = 'A test error occurred.'
        error = AccountError(message)
        self.assertEqual(str(error), message)
        self.assertEqual(error.to_dict(), {'error': message})

    def test_account_error_with_no_message(self):
        """It should return an empty string in __str__ and a dict with None if no
        message is provided."""
        error = AccountError()
        self.assertEqual(str(error), '')
        self.assertEqual(error.to_dict(), {'error': None})


class TestAccountNotFoundError(TestCase):
    """The AccountNotFoundError Exception Class Tests."""

    def test_account_not_found_error_default_message(self):
        """It should generate a default error message when no custom message is provided."""
        account_id = uuid4()
        error = AccountNotFoundError(account_id)
        expected_msg = f"Account with id {account_id} could not be found."
        self.assertEqual(str(error), expected_msg)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), expected_msg)
        self.assertEqual(result_dict.get('account_id'), str(account_id))

    def test_account_not_found_error_custom_message(self):
        """It should use the provided custom error message and include the account ID
        in the dictionary."""
        account_id = uuid4()
        custom_message = 'Custom not found message.'
        error = AccountNotFoundError(account_id, custom_message)
        self.assertEqual(str(error), custom_message)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), custom_message)
        self.assertEqual(result_dict.get('account_id'), str(account_id))


class TestAccountAuthorizationError(TestCase):
    """The AccountAuthorizationError Exception Class Tests."""

    def test_account_authorization_error_default_message_no_roles(self):
        """It should generate a default error message and return a dictionary
        without roles when none are provided."""
        user_id = str(uuid4())
        error = AccountAuthorizationError(user_id)
        expected_msg = f"Account with user id {user_id} is not authorized to perform this action."
        self.assertEqual(str(error), expected_msg)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), expected_msg)
        self.assertEqual(result_dict.get('user_id'), str(user_id))
        self.assertNotIn('roles', result_dict)

    def test_account_authorization_error_custom_message_with_roles(self):
        """It should use the provided custom error message and include roles in
        the returned dictionary."""
        user_id = str(uuid4())
        custom_message = 'Custom authorization failure message.'
        roles = [UserRole.USER.value, UserRole.ADMIN.value]
        error = AccountAuthorizationError(user_id, custom_message, roles)
        self.assertEqual(str(error), custom_message)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), custom_message)
        self.assertEqual(result_dict.get('user_id'), str(user_id))
        self.assertEqual(result_dict.get('roles'), roles)

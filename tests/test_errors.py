"""
Custom Errors Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import unittest
from unittest import TestCase
from uuid import uuid4

from service.common.constants import ROLE_USER, ROLE_ADMIN
from service.errors import (
    AccountError,
    AccountNotFound,
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


class TestAccountNotFound(TestCase):
    """The AccountNotFound Exception Class Tests."""

    def test_account_not_found_default_message(self):
        """It should generate a default error message when no custom message is provided."""
        account_id = uuid4()
        error = AccountNotFound(account_id)
        expected_msg = f"Account with id {account_id} could not be found."
        self.assertEqual(str(error), expected_msg)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), expected_msg)
        self.assertEqual(result_dict.get('account_id'), str(account_id))

    def test_account_not_found_custom_message(self):
        """It should use the provided custom error message and include the account ID
        in the dictionary."""
        account_id = uuid4()
        custom_message = 'Custom not found message.'
        error = AccountNotFound(account_id, custom_message)
        self.assertEqual(str(error), custom_message)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), custom_message)
        self.assertEqual(result_dict.get('account_id'), str(account_id))


class TestAccountAuthorizationError(unittest.TestCase):
    """The AccountAuthorizationError Exception Class Tests."""

    def test_account_authorization_error_default_message_no_roles(self):
        """It should generate a default error message and return a dictionary
        without roles when none are provided."""
        account_id = uuid4()
        error = AccountAuthorizationError(account_id)
        expected_msg = f"Account with id {account_id} is not authorized to perform this action."
        self.assertEqual(str(error), expected_msg)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), expected_msg)
        self.assertEqual(result_dict.get('account_id'), str(account_id))
        self.assertNotIn('roles', result_dict)

    def test_account_authorization_error_custom_message_with_roles(self):
        """It should use the provided custom error message and include roles in
        the returned dictionary."""
        account_id = uuid4()
        custom_message = 'Custom authorization failure message.'
        roles = [ROLE_USER, ROLE_ADMIN]
        error = AccountAuthorizationError(account_id, custom_message, roles)
        self.assertEqual(str(error), custom_message)
        result_dict = error.to_dict()
        self.assertEqual(result_dict.get('error'), custom_message)
        self.assertEqual(result_dict.get('account_id'), str(account_id))
        self.assertEqual(result_dict.get('roles'), roles)

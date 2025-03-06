"""
Account Service Schemas Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase

from pydantic import ValidationError

from service.schemas import AccountDTO
from tests.factories import AccountFactory


######################################################################
#  ACCOUNT SCHEMA TEST CASES
######################################################################
class TestAccountDTO(TestCase):
    """Account Schema Tests."""

    def test_valid_account_dto(self):
        """It should return valid AccountDTO."""
        data = {
            'id': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274',
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26'
        }
        account_dto = AccountDTO(**data)
        self.assertEqual(account_dto.name, 'John Doe')
        self.assertEqual(account_dto.email, 'john.doe@example.com')
        self.assertEqual(account_dto.gender, 'Male')
        self.assertEqual(account_dto.address, '123 Main St')
        self.assertEqual(account_dto.phone_number, '123-456-7890')
        self.assertEqual(account_dto.date_joined.isoformat(), '2024-07-26')

    def test_invalid_email(self):
        """It should raise ValidationError, invalid email."""
        data = {
            'name': 'John Doe',
            'email': 'invalid_email',  # Invalid email
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26'
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'email',
            str(context.exception)
        )  # Check if email error is present

    def test_invalid_date_format(self):
        """It should raise ValidationError, invalid date format."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '26-07-2024'  # Invalid date format
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'date_joined',
            str(context.exception)
        )  # Check if date error is present

    def test_missing_required_field(self):
        """It should raise ValidationError, missing required field."""
        data = {
            'email': 'john.doe@example.com',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26'
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'name',
            str(context.exception)
        )  # Check if name error is present

    def test_empty_name(self):
        """It should raise ValidationError, missing required value."""
        data = {
            'name': '',  # Empty name
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26'
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'name',
            str(context.exception)
        )  # Check if name error is present

    def test_from_orm(self):
        """It should return valid AccountDTO."""
        account = AccountFactory()
        account_dto = AccountDTO.from_orm(account)
        self.assertEqual(account_dto.id, account.id)
        self.assertEqual(account_dto.name, account.name)
        self.assertEqual(account_dto.email, account.email)
        self.assertEqual(account_dto.gender, account.gender)
        self.assertEqual(account_dto.address, account.address)
        self.assertEqual(account_dto.phone_number, account.phone_number)
        self.assertEqual(account_dto.date_joined, account.date_joined)

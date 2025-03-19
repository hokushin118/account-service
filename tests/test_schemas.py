"""
Account Service Schemas Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase

from pydantic import ValidationError

from service import NAME_MIN_LENGTH, NAME_MAX_LENGTH
from service.schemas import AccountDTO, PartialUpdateAccountDTO, \
    UpdateAccountDTO
from tests.factories import AccountFactory


######################################################################
#  ACCOUNT SCHEMA TEST CASES
######################################################################
class TestAccountDTO(TestCase):
    """AccountDTO Tests."""

    def test_valid_account_dto(self):
        """It should return valid AccountDTO."""
        data = {
            'id': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274',
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26',
            'user_id': '77cb6dfd-c8fc-4ef0-b35c-8c76a216d274',
        }
        account_dto = AccountDTO(**data)
        self.assertEqual(account_dto.name, 'John Doe')
        self.assertEqual(account_dto.email, 'john.doe@example.com')
        self.assertEqual(account_dto.gender, 'Male')
        self.assertEqual(account_dto.address, '123 Main St')
        self.assertEqual(account_dto.phone_number, '123-456-7890')
        self.assertEqual(account_dto.date_joined.isoformat(), '2024-07-26')
        self.assertEqual(
            str(account_dto.user_id),
            '77cb6dfd-c8fc-4ef0-b35c-8c76a216d274'
        )

    def test_invalid_email(self):
        """It should raise ValidationError, invalid email."""
        data = {
            'name': 'John Doe',
            'email': 'invalid_email',  # Invalid email
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26',
            'user_id': '77cb6dfd-c8fc-4ef0-b35c-8c76a216d274',
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
            'date_joined': '26-07-2024',  # Invalid date format
            'user_id': '77cb6dfd-c8fc-4ef0-b35c-8c76a216d274',
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'date_joined',
            str(context.exception)
        )  # Check if date error is present

    def test_invalid_uuid_format(self):
        """It should raise ValidationError, invalid uuid format."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26',
            'user_id': '77cb6dfd-c',  # Invalid uuid format
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'user_id',
            str(context.exception)
        )  # Check if user_id error is present

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
        self.assertIn(
            'user_id',
            str(context.exception)
        )  # Check if user_id error is present

    def test_empty_field(self):
        """It should raise ValidationError, missing required value."""
        data = {
            'name': '',  # Empty name
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26',
            'user_id': '',  # Empty user_id
        }
        with self.assertRaises(ValidationError) as context:
            AccountDTO(**data)
        self.assertIn(
            'name',
            str(context.exception)
        )  # Check if name error is present
        self.assertIn(
            'user_id',
            str(context.exception)
        )  # Check if user_id error is present

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
        self.assertEqual(account_dto.user_id, account.user_id)


class TestUpdateAccountDTO(TestCase):
    """UpdateAccountDTO Tests."""

    def test_valid_update_account_dto(self):
        """It should create a valid UpdateAccountDTO when all required fields are
        provided correctly."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',  # Optional field
            'address': '123 Main St',  # Optional field
            'phone_number': '123-456-7890'  # Optional field
        }
        update_account_dto = UpdateAccountDTO(**data)
        self.assertEqual(update_account_dto.name, data['name'])
        self.assertEqual(update_account_dto.email, data['email'])
        self.assertEqual(update_account_dto.gender, data['gender'])
        self.assertEqual(update_account_dto.address, data['address'])
        self.assertEqual(update_account_dto.phone_number, data['phone_number'])

    def test_blank_name(self):
        """It should raise a ValidationError when the name is blank (empty string)."""
        data = {
            'name': '',
            'email': 'john.doe@example.com'
        }
        with self.assertRaises(ValidationError) as context:
            UpdateAccountDTO(**data)
        self.assertIn(
            f"String should have at least {NAME_MIN_LENGTH} characters",
            str(context.exception)
        )

    def test_invalid_email(self):
        """It should raise a ValidationError when an invalid email is provided."""
        data = {
            'name': 'John Doe',
            'email': 'invalid_email'  # Invalid email
        }
        with self.assertRaises(ValidationError) as context:
            UpdateAccountDTO(**data)
        self.assertIn(
            'value is not a valid email address',
            str(context.exception)
        )

    def test_missing_required_field(self):
        """It should raise a ValidationError when a required field (name or email) is missing."""
        # Missing name and email required field; at least one test case per missing required field.
        data1 = {
            'email': 'john.doe@example.com'
        }
        with self.assertRaises(ValidationError) as context:
            UpdateAccountDTO(**data1)
        self.assertIn('Field required', str(context.exception))

        data2 = {
            'name': 'John Doe'
        }
        with self.assertRaises(ValidationError) as context:
            UpdateAccountDTO(**data2)
        self.assertIn('Field required', str(context.exception))

    def test_to_dict_serialization(self):
        """It should serialize the DTO to a dictionary using to_dict()."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890'
        }
        update_account_dto = UpdateAccountDTO(**data)
        update_account_dto_dict = update_account_dto.to_dict()
        self.assertIsInstance(update_account_dto_dict, dict)
        self.assertEqual(update_account_dto_dict['name'], data['name'])
        self.assertEqual(update_account_dto_dict['email'], data['email'])
        self.assertEqual(update_account_dto_dict.get('gender'), data['gender'])
        self.assertEqual(
            update_account_dto_dict.get('address'),
            data['address']
        )
        self.assertEqual(
            update_account_dto_dict.get('phone_number'),
            data['phone_number']
        )


class TestPartialUpdateAccountDTO(TestCase):
    """PartialUpdateAccountDTO Tests."""

    def test_valid_partial_update_account_dto(self):
        """It should create a valid PartialUpdateAccountDTO when all fields
        are provided correctly."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890'
        }
        partial_update_account_dto = PartialUpdateAccountDTO(**data)
        self.assertEqual(
            partial_update_account_dto.name, 'John Doe'
        )
        self.assertEqual(
            partial_update_account_dto.email,
            'john.doe@example.com'
        )
        self.assertEqual(partial_update_account_dto.gender, 'Male')
        self.assertEqual(
            partial_update_account_dto.address,
            '123 Main St'
        )
        self.assertEqual(
            partial_update_account_dto.phone_number,
            '123-456-7890'
        )

    def test_partial_update_account_dto_some_fields(self):
        """It should create a valid PartialUpdateAccountDTO when only some fields are provided."""
        data = {
            'email': 'john.doe@example.com'
        }
        partial_update_account_dto = PartialUpdateAccountDTO(**data)
        self.assertIsNone(partial_update_account_dto.name)
        self.assertEqual(
            partial_update_account_dto.email,
            'john.doe@example.com'
        )
        self.assertIsNone(partial_update_account_dto.gender)
        self.assertIsNone(partial_update_account_dto.address)
        self.assertIsNone(partial_update_account_dto.phone_number)

    def test_invalid_email(self):
        """It should raise a ValidationError when an invalid email is provided."""
        with self.assertRaises(ValidationError) as context:
            PartialUpdateAccountDTO(email='invalid_email')
        self.assertIn(
            'value is not a valid email address',
            str(context.exception)
        )

    def test_name_too_short(self):
        """It should raise a ValidationError when the name is shorter than the minimum length."""
        with self.assertRaises(ValidationError) as context:
            PartialUpdateAccountDTO(name='A')
        self.assertIn(
            f"String should have at least {NAME_MIN_LENGTH} characters",
            str(context.exception)
        )

    def test_name_too_long(self):
        """It should raise a ValidationError when the name is longer than the maximum length."""
        with self.assertRaises(ValidationError) as context:
            long_name = 'A' * (NAME_MAX_LENGTH + 1)
            PartialUpdateAccountDTO(name=long_name)
        self.assertIn(
            f"String should have at most {NAME_MAX_LENGTH} characters",
            str(context.exception)
        )

    def test_to_dict_serialization(self):
        """It should serialize the DTO to a dictionary using to_dict()."""
        data = {
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'gender': 'Male',
            'address': '123 Main St',
            'phone_number': '123-456-7890'
        }
        partial_update_account_dto = PartialUpdateAccountDTO(**data)
        partial_update_account_dto_dict = partial_update_account_dto.to_dict()
        self.assertIsInstance(partial_update_account_dto_dict, dict)
        self.assertEqual(partial_update_account_dto_dict['name'], data['name'])
        self.assertEqual(
            partial_update_account_dto_dict['email'],
            data['email']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('gender'),
            data['gender']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('address'),
            data['address']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('phone_number'),
            data['phone_number']
        )

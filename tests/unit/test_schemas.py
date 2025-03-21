"""
Account Schemas Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase

from pydantic import ValidationError

from service import NAME_MIN_LENGTH, NAME_MAX_LENGTH
from service.schemas import AccountDTO, PartialUpdateAccountDTO, \
    UpdateAccountDTO, CreateAccountDTO, validate_gender_value, ALLOWED_GENDERS, \
    validate_name_value, AccountPagedListDTO
from tests.utils.constants import ACCOUNT_DATA
from tests.utils.factories import AccountFactory
from tests.utils.utils import create_account_paged_list_dto


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


class TestCreateAccountDTO(TestCase):
    """CreateAccountDTO Tests."""

    def test_valid_create_account_dto(self):
        """It should create a valid CreateAccountDTO when all required fields are
        provided correctly."""
        create_account_dto = CreateAccountDTO(**ACCOUNT_DATA)
        self.assertEqual(create_account_dto.name, ACCOUNT_DATA['name'])
        self.assertEqual(create_account_dto.email, ACCOUNT_DATA['email'])
        self.assertEqual(create_account_dto.gender, ACCOUNT_DATA['gender'])
        self.assertEqual(create_account_dto.address, ACCOUNT_DATA['address'])
        self.assertEqual(create_account_dto.phone_number,
                         ACCOUNT_DATA['phone_number'])

    def test_blank_name(self):
        """It should raise a ValidationError when the name is blank (empty string)."""
        data = {
            'name': '',
            'email': 'john.doe@example.com'
        }
        with self.assertRaises(ValidationError) as context:
            CreateAccountDTO(**data)
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
            CreateAccountDTO(**data)
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
            CreateAccountDTO(**data1)
        self.assertIn('Field required', str(context.exception))

        data2 = {
            'name': 'John Doe'
        }
        with self.assertRaises(ValidationError) as context:
            CreateAccountDTO(**data2)
        self.assertIn('Field required', str(context.exception))

    def test_to_dict_serialization(self):
        """It should serialize the DTO to a dictionary using to_dict()."""
        create_account_dto = CreateAccountDTO(**ACCOUNT_DATA)
        create_account_dto_dict = create_account_dto.to_dict()
        self.assertIsInstance(create_account_dto_dict, dict)
        self.assertEqual(create_account_dto_dict['name'], ACCOUNT_DATA['name'])
        self.assertEqual(
            create_account_dto_dict['email'],
            ACCOUNT_DATA['email']
        )
        self.assertEqual(
            create_account_dto_dict.get('gender'),
            ACCOUNT_DATA['gender']
        )
        self.assertEqual(
            create_account_dto_dict.get('address'),
            ACCOUNT_DATA['address']
        )
        self.assertEqual(
            create_account_dto_dict.get('phone_number'),
            ACCOUNT_DATA['phone_number']
        )


class TestUpdateAccountDTO(TestCase):
    """UpdateAccountDTO Tests."""

    def test_valid_update_account_dto(self):
        """It should create a valid UpdateAccountDTO when all required fields are
        provided correctly."""
        update_account_dto = UpdateAccountDTO(**ACCOUNT_DATA)
        self.assertEqual(update_account_dto.name, ACCOUNT_DATA['name'])
        self.assertEqual(update_account_dto.email, ACCOUNT_DATA['email'])
        self.assertEqual(update_account_dto.gender, ACCOUNT_DATA['gender'])
        self.assertEqual(update_account_dto.address, ACCOUNT_DATA['address'])
        self.assertEqual(update_account_dto.phone_number,
                         ACCOUNT_DATA['phone_number'])

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
        update_account_dto = UpdateAccountDTO(**ACCOUNT_DATA)
        update_account_dto_dict = update_account_dto.to_dict()
        self.assertIsInstance(update_account_dto_dict, dict)
        self.assertEqual(
            update_account_dto_dict['name'], ACCOUNT_DATA['name']
        )
        self.assertEqual(
            update_account_dto_dict['email'], ACCOUNT_DATA['email']
        )
        self.assertEqual(
            update_account_dto_dict.get('gender'), ACCOUNT_DATA['gender']
        )
        self.assertEqual(
            update_account_dto_dict.get('address'),
            ACCOUNT_DATA['address']
        )
        self.assertEqual(
            update_account_dto_dict.get('phone_number'),
            ACCOUNT_DATA['phone_number']
        )


class TestPartialUpdateAccountDTO(TestCase):
    """PartialUpdateAccountDTO Tests."""

    def test_valid_partial_update_account_dto(self):
        """It should create a valid PartialUpdateAccountDTO when all fields
        are provided correctly."""
        partial_update_account_dto = PartialUpdateAccountDTO(**ACCOUNT_DATA)
        self.assertEqual(
            partial_update_account_dto.name, ACCOUNT_DATA['name']
        )
        self.assertEqual(
            partial_update_account_dto.email,
            ACCOUNT_DATA['email']
        )
        self.assertEqual(
            partial_update_account_dto.gender,
            ACCOUNT_DATA['gender']
        )
        self.assertEqual(
            partial_update_account_dto.address,
            ACCOUNT_DATA['address']
        )
        self.assertEqual(
            partial_update_account_dto.phone_number,
            ACCOUNT_DATA['phone_number']
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
        partial_update_account_dto = PartialUpdateAccountDTO(**ACCOUNT_DATA)
        partial_update_account_dto_dict = partial_update_account_dto.to_dict()
        self.assertIsInstance(partial_update_account_dto_dict, dict)
        self.assertEqual(
            partial_update_account_dto_dict['name'],
            ACCOUNT_DATA['name']
        )
        self.assertEqual(
            partial_update_account_dto_dict['email'],
            ACCOUNT_DATA['email']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('gender'),
            ACCOUNT_DATA['gender']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('address'),
            ACCOUNT_DATA['address']
        )
        self.assertEqual(
            partial_update_account_dto_dict.get('phone_number'),
            ACCOUNT_DATA['phone_number']
        )


class TestAccountPagedListDTO(TestCase):
    """AccountPagedListDTO Tests."""

    def test_default_values(self):
        """It should test that the default values are correctly assigned."""
        dto = AccountPagedListDTO(items=[])
        self.assertEqual(dto.page, 1)
        self.assertEqual(dto.per_page, 1)
        self.assertEqual(dto.total, 0)
        self.assertEqual(dto.items, [])

    def test_valid_data(self):
        """It should test that given values are correctly assigned."""
        # Create a list of dummy AccountDTO objects
        account_paged_list_dto = create_account_paged_list_dto()
        self.assertEqual(account_paged_list_dto.page, 1)
        self.assertEqual(account_paged_list_dto.per_page, 10)
        self.assertEqual(account_paged_list_dto.total, 2)
        self.assertEqual(len(account_paged_list_dto.items), 2)

    def test_invalid_negative_page(self):
        """It should test that ge validation for page works."""
        with self.assertRaises(ValidationError) as context:
            AccountPagedListDTO(items=[], page=0)
        self.assertIn(
            'Input should be greater than or equal to 1',
            str(context.exception)
        )

    def test_invalid_negative_per_page(self):
        """It should test that ge validation for per_page works."""
        with self.assertRaises(ValidationError) as context:
            AccountPagedListDTO(items=[], per_page=0)
        self.assertIn(
            'Input should be greater than or equal to 1',
            str(context.exception)
        )

    def test_invalid_negative_total(self):
        """It should test that ge validation for total works."""
        with self.assertRaises(ValidationError) as context:
            AccountPagedListDTO(items=[], total=-5)
        self.assertIn(
            'Input should be greater than or equal to 0',
            str(context.exception)
        )


######################################################################
# VALIDATION METHODS TEST CASES
######################################################################
class TestValidateNameValue(TestCase):
    """The validate_name_value Function Tests."""

    def test_valid_name_returns_input(self):
        """It should return the name if a valid non-empty name is provided."""
        valid_name = 'John Doe'
        result = validate_name_value(valid_name)
        self.assertEqual(result, valid_name)

    def test_blank_name_raises_value_error(self):
        """It should raise ValueError if a blank name is provided."""
        with self.assertRaises(ValueError) as context:
            validate_name_value('')
        self.assertIn('Name can not be blank', str(context.exception))


class TestValidateGenderValue(TestCase):
    """The validate_gender_value Function Tests."""

    def test_none_value_returns_none(self):
        """It should return None when passed None."""
        self.assertIsNone(validate_gender_value(None))

    def test_valid_gender_lower(self):
        """It should return the input if a valid gender in lower case is provided."""
        # Assume ALLOWED_GENDERS includes "Male", "Female", "Other"
        valid_input = 'male'
        self.assertEqual(validate_gender_value(valid_input), valid_input)

    def test_valid_gender_upper(self):
        """It should return the input if a valid gender in upper case is provided."""
        valid_input = 'FEMALE'
        self.assertEqual(validate_gender_value(valid_input), valid_input)

    def test_valid_gender_mixed_case(self):
        """It should return the input if a valid gender in mixed case is provided."""
        valid_input = 'Other'
        self.assertEqual(validate_gender_value(valid_input), valid_input)

    def test_invalid_gender_raises_value_error(self):
        """It should raise a ValueError when an invalid gender is provided."""
        invalid_input = 'nonbinary'  # Assuming this value is not in ALLOWED_GENDERS.
        with self.assertRaises(ValueError) as context:
            validate_gender_value(invalid_input)
        error_message = str(context.exception)
        self.assertIn('Invalid gender value', error_message)
        self.assertIn(str(ALLOWED_GENDERS), error_message)

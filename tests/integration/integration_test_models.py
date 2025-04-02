"""
Account Model Integration Test Suite.

Test cases can be run with the following:
  RUN_INTEGRATION_TESTS=true nosetests -v --with-spec --spec-color tests/integration
  coverage report -m
"""
import os
import unittest
from uuid import UUID

from sqlalchemy.sql.expression import desc
from testcontainers.postgres import PostgresContainer

from service.models import Account, DataValidationError
from tests.integration.base import BaseTestCase
from tests.utils.constants import TEST_USER_ID
from tests.utils.factories import AccountFactory
from tests.utils.utils import apply_migrations


######################################################################
#  ACCOUNT MODEL TEST CASES
######################################################################
@unittest.skipIf(
    os.getenv('RUN_INTEGRATION_TESTS') != 'true',
    'Integration tests skipped'
)
class TestAccount(BaseTestCase):  # pylint:disable=R0904
    """Test Cases for Account Model."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Start Testcontainers
        cls.postgres_container = PostgresContainer('postgres:14')
        cls.postgres_container.start()

        # Update app config with container connection details
        cls.app.config[
            'DATABASE_URI'] = cls.postgres_container.get_connection_url()
        cls.app.config[
            'SQLALCHEMY_DATABASE_URI'] = cls.postgres_container.get_connection_url()

        # Apply migrations
        apply_migrations(cls.app, cls.engine)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Stop Testcontainers
        cls.postgres_container.stop()

    ######################################################################
    #  TEST CASES
    ######################################################################
    def test_create_an_account(self):
        """It should create an Account and assert that it exists."""
        fake_account = AccountFactory()
        # pylint: disable=unexpected-keyword-arg
        account = Account(
            name=fake_account.name,
            email=fake_account.email,
            gender=fake_account.gender,
            address=fake_account.address,
            phone_number=fake_account.phone_number,
            date_joined=fake_account.date_joined,
            user_id=fake_account.user_id,
        )
        self.assertIsNotNone(account)
        self.assertEqual(account.id, None)
        self.assertEqual(account.name, fake_account.name)
        self.assertEqual(account.email, fake_account.email)
        self.assertEqual(account.gender, fake_account.gender)
        self.assertEqual(account.address, fake_account.address)
        self.assertEqual(account.phone_number, fake_account.phone_number)
        self.assertEqual(account.date_joined, fake_account.date_joined)
        self.assertEqual(account.user_id, fake_account.user_id)

    def test_add_a_account(self):
        """It should create an account and add it to the database."""
        accounts = Account.all()
        self.assertEqual(accounts, [])
        account = AccountFactory()
        account.create()
        # Assert that it was assigned an id and shows up in the database
        self.assertIsNotNone(account.id)
        accounts = Account.all()
        self.assertEqual(len(accounts), 1)

    def test_read_account(self):
        """It should read an account."""
        account = AccountFactory()
        account.create()

        # Read it back
        found_account = Account.find(account.id)
        self.assertEqual(found_account.id, account.id)
        self.assertEqual(found_account.name, account.name)
        self.assertEqual(found_account.email, account.email)
        self.assertEqual(found_account.gender, account.gender)
        self.assertEqual(found_account.address, account.address)
        self.assertEqual(found_account.phone_number, account.phone_number)
        self.assertEqual(found_account.date_joined, account.date_joined)
        self.assertEqual(found_account.user_id, account.user_id)

    def test_update_account(self):
        """It should update an account."""
        account = AccountFactory(email='advent@change.me')
        account.create()
        # Assert that it was assigned an id and shows up in the database
        self.assertIsNotNone(account.id)
        self.assertEqual(account.email, 'advent@change.me')

        # Fetch it back
        account = Account.find(account.id)
        account.email = 'testY@example.com'
        account.update()

        # Fetch it back again
        account = Account.find(account.id)
        self.assertEqual(account.email, 'testY@example.com')

    def test_delete_an_account(self):
        """It should delete an account from the database."""
        accounts = Account.all()
        self.assertEqual(accounts, [])
        account = AccountFactory()
        account.create()
        # Assert that it was assigned an id and shows up in the database
        self.assertIsNotNone(account.id)
        accounts = Account.all()
        self.assertEqual(len(accounts), 1)
        account = accounts[0]
        account.delete()
        accounts = Account.all()
        self.assertEqual(len(accounts), 0)

    def test_all_accounts(self):
        """It should list all Accounts in the database."""
        accounts = Account.all()
        self.assertEqual(accounts, [])
        for account in AccountFactory.create_batch(5):
            account.create()
        # Assert that there are now 5 accounts in the database
        accounts = Account.all()
        self.assertEqual(len(accounts), 5)

    def test_all_paginated_empty(self):
        """It should return an empty list when no accounts exist."""
        accounts = Account.all_paginated(page=1, per_page=10)
        self.assertEqual(accounts, [])

    def test_all_paginated_first_page(self):
        """It should return the first page of accounts."""
        for account in AccountFactory.create_batch(15):
            account.create()

        accounts = Account.all_paginated(page=1, per_page=10)
        self.assertEqual(len(accounts), 10)
        # Verify ordering
        self.assertEqual(accounts[0].id, Account.query.order_by(
            desc(Account.created_at)).first().id)

    def test_all_paginated_second_page(self):
        """It should return the second page of accounts."""
        for account in AccountFactory.create_batch(15):
            account.create()

        accounts = Account.all_paginated(page=2, per_page=10)
        self.assertEqual(len(accounts), 5)

    def test_all_paginated_custom_per_page(self):
        """It should return the correct number of accounts per page."""
        for account in AccountFactory.create_batch(20):
            account.create()

        accounts = Account.all_paginated(page=1, per_page=5)
        self.assertEqual(len(accounts), 5)
        accounts = Account.all_paginated(page=2, per_page=5)
        self.assertEqual(len(accounts), 5)
        accounts = Account.all_paginated(page=4, per_page=5)
        self.assertEqual(len(accounts), 5)

    def test_find_by_name(self):
        """It should find an Account by name."""
        account = AccountFactory()
        account.create()

        # Fetch it back by name
        same_account = Account.find_by_name(account.name)[0]
        self.assertEqual(same_account.id, account.id)
        self.assertEqual(same_account.name, account.name)

    def test_to_dict_an_account(self):
        """It should serialize an account."""
        account = AccountFactory()
        serial_account = account.to_dict()
        self.assertEqual(serial_account['id'], account.id)
        self.assertEqual(serial_account['name'], account.name)
        self.assertEqual(serial_account['email'], account.email)
        self.assertEqual(serial_account['gender'], account.gender)
        self.assertEqual(serial_account['address'], account.address)
        self.assertEqual(serial_account['phone_number'], account.phone_number)
        self.assertEqual(serial_account['date_joined'],
                         str(account.date_joined))
        self.assertEqual(serial_account['user_id'], account.user_id)

    def test_deserialize_an_account(self):
        """It should deserialize an account."""
        account = AccountFactory()
        account.create()
        serial_account = account.to_dict()
        new_account = Account()
        new_account.deserialize(serial_account)
        self.assertEqual(new_account.name, account.name)
        self.assertEqual(new_account.email, account.email)
        self.assertEqual(new_account.gender, account.gender)
        self.assertEqual(new_account.address, account.address)
        self.assertEqual(new_account.phone_number, account.phone_number)

    def test_deserialize_with_key_error(self):
        """It should not deserialize an account with a KeyError."""
        account = Account()
        self.assertRaises(DataValidationError, account.deserialize, {})

    def test_deserialize_with_type_error(self):
        """It should not deserialize an account with a TypeError."""
        account = Account()
        self.assertRaises(DataValidationError, account.deserialize, [])

    def test_create_success(self):
        """It should create a new account."""
        with self.app.app_context():
            account = AccountFactory()
            # Call the create method, which should add and commit the record.
            returned_record = account.create()
            self.assertIs(account, returned_record)

            # Query the database to ensure the record has been persisted.
            persisted = Account.query.filter_by(name=account.name).first()
            self.assertIsNotNone(persisted)
            self.assertEqual(persisted.name, account.name)

    def test_create_integrity_error_with_email(self):
        """It should raise a DataValidationError when creating a duplicate record,
        due to an integrity error."""
        with self.app.app_context():
            # Create the first account
            account1 = AccountFactory()
            account1.create()

            # Attempt to create a second account with the same email,
            # triggering the unique constraint.
            account2 = AccountFactory()
            account2.email = account1.email  # Ensure the email is the same.
            with self.assertRaises(DataValidationError) as context:
                account2.create()
            self.assertIn(
                'Integrity error creating record',
                str(context.exception)
            )

    def test_partial_update_valid_data(self):
        """It should partially update an account."""
        account = AccountFactory()
        account.create()
        data = {'name': 'Updated Name', 'email': 'updated@example.com'}
        account.partial_update(data)
        self.assertEqual(account.name, 'Updated Name')
        self.assertEqual(account.email, 'updated@example.com')

    def test_partial_update_invalid_attribute(self):
        """It should not partially update an account with invalid attribute."""
        account = AccountFactory()
        account.create()
        data = {'non_existent_attribute': 'some_value'}
        with self.assertRaises(DataValidationError) as context:
            account.partial_update(data)
        self.assertIn(
            "Attribute 'non_existent_attribute' is not valid",
            str(context.exception)
        )

    def test_partial_update_primary_key(self):
        """It should not partially update an account with data containing primary key."""
        account = AccountFactory()
        account.create()
        data = {'id': 456}
        with self.assertRaises(DataValidationError) as context:
            account.partial_update(data)
        self.assertIn("Cannot update primary key 'id'", str(context.exception))

    def test_partial_update_empty_data(self):
        """It should not raise error while updating an account with empty data."""
        account = AccountFactory()
        account.create()
        account.name = 'Test Account'
        account.email = 'test@example.com'
        data = {}
        account.partial_update(data)  # Should not raise error
        self.assertEqual(account.name, 'Test Account')
        self.assertEqual(account.email, 'test@example.com')

    def test_find_by_user_id_success(self):
        """It should find an Account by user id."""
        account = AccountFactory()
        account.create()
        test_uuid = account.user_id

        # Fetch it back by user id
        actual = Account.find_by_user_id(test_uuid)
        self.assertEqual(actual.id, account.id)
        self.assertEqual(actual.user_id, account.user_id)
        self.assertEqual(actual.name, account.name)
        self.assertEqual(actual.email, account.email)
        self.assertEqual(actual.address, account.address)

    def test_find_by_user_id_not_exist(self):
        """It should return None when no account is found for a given user_id."""
        test_uuid = UUID(TEST_USER_ID)

        # Attempt to fetch an account using a user_id that doesn't exist.
        actual = Account.find_by_user_id(test_uuid)
        self.assertIsNone(
            actual,
            'Expected None when no account is found.'
        )

    def test_find_by_user_id_none(self):
        """It should return None when None is provided as a user_id."""
        # Pass None to the find_by_user_id method.
        actual = Account.find_by_user_id(None)
        self.assertIsNone(
            actual,
            'Expected None when None is provided as user_id.'
        )

"""
Test cases for Account Model

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
import os
import unittest

from service import app
from service.models import Account, DataValidationError, db
from tests.factories import AccountFactory

DATABASE_URI = os.getenv(
    'DATABASE_URI', 'postgresql://postgres:postgres@localhost:15432/postgres'
)


######################################################################
#  Account   M O D E L   T E S T   C A S E S
######################################################################
class TestAccount(unittest.TestCase):
    """Test Cases for Account Model."""

    @classmethod
    def setUpClass(cls):
        """This runs once before the entire test suite."""
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
        app.logger.setLevel(logging.CRITICAL)
        Account.init_db(app)

    @classmethod
    def tearDownClass(cls):
        """This runs once after the entire test suite."""

    def setUp(self):
        """This runs before each test."""
        db.session.query(Account).delete()  # clean up the last tests
        db.session.commit()

    def tearDown(self):
        """This runs after each test."""
        db.session.remove()

    ######################################################################
    #  T E S T   C A S E S
    ######################################################################

    def test_create_an_account(self):
        """It should Create an Account and assert that it exists."""
        fake_account = AccountFactory()
        # pylint: disable=unexpected-keyword-arg
        account = Account(
            name=fake_account.name,
            email=fake_account.email,
            address=fake_account.address,
            phone_number=fake_account.phone_number,
            date_joined=fake_account.date_joined,
        )
        self.assertIsNotNone(account)
        self.assertEqual(account.id, None)
        self.assertEqual(account.name, fake_account.name)
        self.assertEqual(account.email, fake_account.email)
        self.assertEqual(account.address, fake_account.address)
        self.assertEqual(account.phone_number, fake_account.phone_number)
        self.assertEqual(account.date_joined, fake_account.date_joined)

    def test_add_a_account(self):
        """It should Create an account and add it to the database."""
        accounts = Account.all()
        self.assertEqual(accounts, [])
        account = AccountFactory()
        account.create()
        # Assert that it was assigned an id and shows up in the database
        self.assertIsNotNone(account.id)
        accounts = Account.all()
        self.assertEqual(len(accounts), 1)

    def test_read_account(self):
        """It should Read an account."""
        account = AccountFactory()
        account.create()

        # Read it back
        found_account = Account.find(account.id)
        self.assertEqual(found_account.id, account.id)
        self.assertEqual(found_account.name, account.name)
        self.assertEqual(found_account.email, account.email)
        self.assertEqual(found_account.address, account.address)
        self.assertEqual(found_account.phone_number, account.phone_number)
        self.assertEqual(found_account.date_joined, account.date_joined)

    def test_update_account(self):
        """It should Update an account."""
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
        """It should Delete an account from the database."""
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

    def test_list_all_accounts(self):
        """It should List all Accounts in the database."""
        accounts = Account.all()
        self.assertEqual(accounts, [])
        for account in AccountFactory.create_batch(5):
            account.create()
        # Assert that there are not 5 accounts in the database
        accounts = Account.all()
        self.assertEqual(len(accounts), 5)

    def test_find_by_name(self):
        """It should Find an Account by name."""
        account = AccountFactory()
        account.create()

        # Fetch it back by name
        same_account = Account.find_by_name(account.name)[0]
        self.assertEqual(same_account.id, account.id)
        self.assertEqual(same_account.name, account.name)

    def test_serialize_an_account(self):
        """It should Serialize an account."""
        account = AccountFactory()
        serial_account = account.serialize()
        self.assertEqual(serial_account['id'], account.id)
        self.assertEqual(serial_account['name'], account.name)
        self.assertEqual(serial_account['email'], account.email)
        self.assertEqual(serial_account['address'], account.address)
        self.assertEqual(serial_account['phone_number'], account.phone_number)
        self.assertEqual(serial_account['date_joined'],
                         str(account.date_joined))

    def test_deserialize_an_account(self):
        """It should Deserialize an account."""
        account = AccountFactory()
        account.create()
        serial_account = account.serialize()
        new_account = Account()
        new_account.deserialize(serial_account)
        self.assertEqual(new_account.name, account.name)
        self.assertEqual(new_account.email, account.email)
        self.assertEqual(new_account.address, account.address)
        self.assertEqual(new_account.phone_number, account.phone_number)
        self.assertEqual(new_account.date_joined, account.date_joined)

    def test_deserialize_with_key_error(self):
        """It should not Deserialize an account with a KeyError."""
        account = Account()
        self.assertRaises(DataValidationError, account.deserialize, {})

    def test_deserialize_with_type_error(self):
        """It should not Deserialize an account with a TypeError."""
        account = Account()
        self.assertRaises(DataValidationError, account.deserialize, [])

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

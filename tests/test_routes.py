"""
Account API Service Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
import os
from unittest import TestCase

from service.common import status  # HTTP Status Codes
from service.models import Account, init_db, db
from service.routes import app, HEALTH_ENDPOINT, ROOT_ENDPOINT, \
    ACCOUNT_ENDPOINT
from tests.factories import AccountFactory

DATABASE_URI = os.getenv(
    'DATABASE_URI', 'postgresql://postgres:postgres@localhost:15432/postgres'
)

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


######################################################################
#  T E S T   C A S E S
######################################################################
class TestAccountService(TestCase):
    """Account Service Tests."""

    @classmethod
    def setUpClass(cls):
        """Run once before all tests."""
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
        app.logger.setLevel(logging.CRITICAL)
        init_db(app)

    @classmethod
    def tearDownClass(cls):
        """Runs once before test suite."""

    def setUp(self):
        """Runs before each test."""
        db.session.query(Account).delete()  # clean up the last tests
        db.session.commit()

        self.client = app.test_client()

    def tearDown(self):
        """Runs once after each test case."""
        db.session.remove()

    ######################################################################
    #  H E L P E R   M E T H O D S
    ######################################################################

    def _create_accounts(self, count):
        """Factory method to create accounts in bulk."""
        accounts = []
        for _ in range(count):
            account = AccountFactory()
            response = self.client.post(
                ACCOUNT_ENDPOINT,
                json=account.serialize()
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_201_CREATED,
                'Could not create test Account',
            )
            new_account = response.get_json()
            account.id = new_account['id']  # pylint: disable=invalid-name
            accounts.append(account)
        return accounts

    ######################################################################
    #  A C C O U N T   T E S T   C A S E S
    ######################################################################

    def test_index(self):
        """It should get 200_OK from the Home Page."""
        response = self.client.get(ROOT_ENDPOINT)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_health(self):
        """It should be healthy."""
        resp = self.client.get(HEALTH_ENDPOINT)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'UP')

    def test_create_account(self):
        """It should Create a new Account."""
        account = AccountFactory()
        response = self.client.post(
            ACCOUNT_ENDPOINT,
            json=account.serialize(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Make sure location header is set
        location = response.headers.get('Location', None)
        self.assertIsNotNone(location)

        # Check the data is correct
        new_account = response.get_json()
        self.assertEqual(new_account['name'], account.name)
        self.assertEqual(new_account['email'], account.email)
        self.assertEqual(new_account['address'], account.address)
        self.assertEqual(new_account['phone_number'], account.phone_number)
        self.assertEqual(new_account['date_joined'], str(account.date_joined))

    def test_unsupported_media_type(self):
        """
        It should not Create an Account when sending the wrong media
        type.
        """
        account = AccountFactory()
        response = self.client.post(
            ACCOUNT_ENDPOINT,
            json=account.serialize(),
            content_type='test/html'
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )

    def test_get_account_list(self):
        """It should Get a list of Accounts."""
        self._create_accounts(5)
        resp = self.client.get(ACCOUNT_ENDPOINT)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.get_json()
        self.assertEqual(len(data), 5)

    def test_get_account_by_id(self):
        """It should Read a single Account."""
        account = self._create_accounts(1)[0]
        resp = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.get_json()
        self.assertEqual(data['name'], account.name)

    def test_get_account_by_id_not_found(self):
        """It should not Read an Account that is not found."""
        resp = self.client.get(f"{ACCOUNT_ENDPOINT}/0")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_account_by_id(self):
        """It should Update an existing Account."""
        # create an Account to update
        test_account = AccountFactory()
        resp = self.client.post(
            ACCOUNT_ENDPOINT,
            json=test_account.serialize()
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        # update the account
        new_account = resp.get_json()
        new_account['name'] = 'Something Known'
        resp = self.client.put(
            f"{ACCOUNT_ENDPOINT}/{new_account['id']}",
            json=new_account
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        updated_account = resp.get_json()
        self.assertEqual(updated_account['name'], 'Something Known')

    def test_update_account_by_id_not_found(self):
        """It should not Read an Account that is not found."""
        resp = self.client.put(f"{ACCOUNT_ENDPOINT}/0")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

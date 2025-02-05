"""
Account API Service Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
from unittest import TestCase

from service.common import status  # HTTP Status Codes
from service.routes import app, HEALTH_ENDPOINT, ROOT_ENDPOINT, \
    ACCOUNT_ENDPOINT
from tests.factories import AccountFactory

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


######################################################################
#  T E S T   C A S E S
######################################################################
class TestAccountService(TestCase):
    """Account Service Tests."""

    @classmethod
    def setUpClass(cls):
        """Run once before all tests."""
        app.config["TESTING"] = True
        app.config["DEBUG"] = False
        app.logger.setLevel(logging.CRITICAL)

    @classmethod
    def tearDownClass(cls):
        """Runs once before test suite."""

    def setUp(self):
        """Runs before each test."""
        self.client = app.test_client()

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

    def test_get_account_list(self):
        """It should Get a list of Accounts."""
        self._create_accounts(5)
        resp = self.client.get(ACCOUNT_ENDPOINT)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.get_json()
        self.assertEqual(len(data), 5)

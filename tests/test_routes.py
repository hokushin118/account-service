"""
Account API Service Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
import os
from unittest import TestCase

from service import talisman
from service.common import status  # HTTP Status Codes
from service.models import Account, init_db, db
from service.routes import app, HEALTH_ENDPOINT, ROOT_ENDPOINT, \
    ACCOUNT_ENDPOINT
from service.schemas import AccountDTO
from tests.factories import AccountFactory

DATABASE_URI = os.getenv(
    'DATABASE_URI', 'postgresql://postgres:postgres@localhost:15432/postgres'
)

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


######################################################################
#  T E S T   C A S E S
######################################################################
class TestAccountService(TestCase):  # pylint: disable=too-many-public-methods
    """Account Service Tests."""

    @classmethod
    def setUpClass(cls):
        """Run once before all tests."""
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
        app.logger.setLevel(logging.CRITICAL)
        init_db(app)
        talisman.force_https = False

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
                json=account.to_dict()
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

    def test_create(self):
        """It should Create a new Account."""
        account = AccountFactory()
        response = self.client.post(
            ACCOUNT_ENDPOINT,
            json=account.to_dict(),
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
        # self.assertEqual(new_account['date_joined'],
        #                  str(account.date_joined))

    def test_unsupported_media_type(self):
        """
        It should not Create an Account when sending the wrong media
        type.
        """
        account = AccountFactory()
        response = self.client.post(
            ACCOUNT_ENDPOINT,
            json=account.to_dict(),
            content_type='test/html'
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )

    def test_list_accounts(self):
        """It should Get a list of Accounts."""
        self._create_accounts(5)
        resp = self.client.get(
            ACCOUNT_ENDPOINT,
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.get_json()
        self.assertEqual(len(data), 5)

    def test_list_accounts_with_matching_if_none_match(self):
        """It should return a 304 Not Modified if the ETag matches in list."""
        self._create_accounts(5)
        resp = self.client.get(
            ACCOUNT_ENDPOINT,
            content_type='application/json'
        )
        etag = resp.headers.get('ETag').replace('"', '')  # Extract ETag

        # Make a second request with If-None-Match header
        resp2 = self.client.get(
            ACCOUNT_ENDPOINT,
            content_type='application/json',
            headers={'If-None-Match': etag}
        )
        self.assertEqual(resp2.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(resp2.data, b'')  # Check for empty body

    def test_list_accounts_with_non_matching_if_none_match(self):
        """It should return a 200 OK if the ETag does not match in list."""
        self._create_accounts(5)
        resp = self.client.get(
            ACCOUNT_ENDPOINT,
            content_type='application/json'
        )
        _ = resp.headers.get('ETag').replace('"', '')

        # Make a second request with a different If-None-Match header
        resp2 = self.client.get(
            ACCOUNT_ENDPOINT,
            content_type='application/json',
            headers={'If-None-Match': 'some-other-etag'}  # Different ETag
        )
        self.assertEqual(
            resp2.status_code,
            status.HTTP_200_OK
        )  # Should return 200 OK

    def test_find_by_id(self):
        """It should Read a single Account."""
        account = self._create_accounts(1)[0]
        resp = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json'
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        data = resp.get_json()
        self.assertEqual(data['name'], account.name)

    def test_find_by_id_with_matching_if_none_match(self):
        """It should return a 304 Not Modified if the ETag matches."""
        account = self._create_accounts(1)[0]
        resp = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json'
        )
        etag = resp.headers.get('ETag').replace('"', '')  # Extract ETag

        # Make a second request with If-None-Match header
        resp2 = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json',
            headers={'If-None-Match': etag}
        )
        self.assertEqual(resp2.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(resp2.data, b'')  # Check for empty body

    def test_find_by_id_with_non_matching_if_none_match(self):
        """It should return a 200 OK if the ETag does not match."""
        account = self._create_accounts(1)[0]
        resp = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json'
        )
        _ = resp.headers.get('ETag').replace('"', '')

        # Make a second request with a different If-None-Match header
        resp2 = self.client.get(
            f"{ACCOUNT_ENDPOINT}/{account.id}",
            content_type='application/json',
            headers={'If-None-Match': 'some-other-etag'}  # Different ETag
        )
        self.assertEqual(
            resp2.status_code,
            status.HTTP_200_OK
        )  # Should return 200 OK

    def test_find_by_id_not_found(self):
        """It should not Read an Account that is not found."""
        resp = self.client.get(f"{ACCOUNT_ENDPOINT}/0")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_update_by_id(self):
        """It should Update an existing Account."""
        # create an Account to update
        test_account = AccountFactory()

        test_account_dto = AccountDTO.from_orm(test_account)

        resp = self.client.post(
            ACCOUNT_ENDPOINT,
            json=test_account_dto.dict()
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

    def test_update_by_id_not_found(self):
        """It should not Read an Account that is not found."""
        resp = self.client.put(f"{ACCOUNT_ENDPOINT}/0")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_partial_update_by_id(self):
        """It should Partially Update an existing Account."""
        # create an Account to update
        test_account = AccountFactory()
        resp = self.client.post(
            ACCOUNT_ENDPOINT,
            json=test_account.to_dict()
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        # partially update the account
        new_account = resp.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        resp = self.client.patch(
            f"{ACCOUNT_ENDPOINT}/{updated_account_id}",
            json=update_data
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        updated_account = resp.get_json()
        self.assertEqual(updated_account['name'], 'Test Account')
        self.assertEqual(updated_account['email'], 'test@example.com')

    def test_partial_update_by_id_not_found(self):
        """It should not Read an Account that is not found."""
        resp = self.client.patch(f"{ACCOUNT_ENDPOINT}/0")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)

    def test_delete_by_id(self):
        """It should Delete an Account."""
        account = self._create_accounts(1)[0]
        resp = self.client.delete(f"{ACCOUNT_ENDPOINT}/{account.id}")
        self.assertEqual(resp.status_code, status.HTTP_204_NO_CONTENT)

    def test_security_headers(self):
        """It should return security headers."""
        response = self.client.get(
            ROOT_ENDPOINT,
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'default-src \'self\'; object-src \'none\'',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        for key, value in headers.items():
            if key != 'Content-Security-Policy':
                self.assertEqual(response.headers.get(key), value)

    def test_cors_security(self):
        """It should return a CORS header."""
        response = self.client.get(
            ROOT_ENDPOINT,
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check for the CORS header
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'),
            '*'
        )

# pylint:disable=C0302
"""
Account API Service Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from flask import Flask
from flask_jwt_extended import (
    get_jwt_identity,
    verify_jwt_in_request,
    JWTManager
)
from jose import jwt

from service import AUTHORIZATION_HEADER, BEARER_HEADER
from service.common import status  # HTTP Status Codes
from service.common.constants import ROLE_USER, ROLE_ADMIN
from service.common.keycloak_utils import KEYS, REALM_ACCESS_CLAIM, ROLES_CLAIM
from service.models import db, Account
from service.routes import (
    app,
    ACCOUNTS_PATH_V1,
    ROOT_PATH,
    HEALTH_PATH,
    IF_NONE_MATCH_HEADER, CACHE_CONTROL_HEADER, audit_log
)
from service.schemas import AccountDTO
from tests.factories import AccountFactory
from tests.test_constants import (
    TEST_USER,
    TEST_ROLE
)

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}
JWT_ALGORITHM = 'RS256'
PRIVATE_KEY_PATH = './tests/keys/private.pem'
PUBLIC_KEY_PATH = './tests/keys/public.pem'
INVALID_ETAG = 'invalid-etag'
ORIGINAL = 'original'


######################################################################
#  ROUTE TEST CASES
######################################################################
class TestAccountRoute(TestCase):  # pylint:disable=R0904
    """Account Route Tests."""

    def setUp(self):
        """Runs before each test."""
        self.app = Flask(__name__)
        self.app.testing = True
        self.app_context = app.app_context()
        self.app_context.push()  # Push the context so request works

        db.session.query(Account).delete()  # clean up the last tests
        db.session.commit()

        self.client = app.test_client()

        # Generating a private/public key pair
        # openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
        # openssl rsa -pubout -in private.pem -out public.pem

        # Load private key
        with open(PRIVATE_KEY_PATH, 'rb') as private_key_file:
            private_key_object = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )
            self.private_key = private_key_object.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

        # Load public key
        with open(PUBLIC_KEY_PATH, 'rb') as public_key_file:
            self.public_key = serialization.load_pem_public_key(
                public_key_file.read()
            )

        # Mock Keycloak public key retrieval
        self.mock_certs = {
            KEYS: [{
                'kty': 'RSA',
                'kid': 'test-kid',
                'use': 'sig',
                'n': self.public_key.public_numbers().n,
                'e': self.public_key.public_numbers().e
            }]
        }

        # Generate test JWT using RS256
        self.test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [TEST_ROLE]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        with open(PUBLIC_KEY_PATH, 'rb') as public_key_file:
            app.config['JWT_PUBLIC_KEY'] = serialization.load_pem_public_key(
                public_key_file.read()
            )

        app.config['JWT_ALGORITHM'] = JWT_ALGORITHM
        app.config['JWT_TOKEN_LOCATION'] = ['headers']
        app.config['JWT_HEADER_NAME'] = AUTHORIZATION_HEADER
        app.config['JWT_HEADER_TYPE'] = BEARER_HEADER

        # Initialize JWTManager
        JWTManager(app)

    def tearDown(self):
        """Runs once after each test case."""
        db.session.remove()  # Remove the session

        self.app_context.pop()  # Pop the application context
        self.app_context = None  # Reset the app context

    ######################################################################
    #  HELPER METHODS
    ######################################################################
    def _create_accounts(self, count):
        """Factory method to create accounts in bulk."""
        accounts = []
        for _ in range(count):
            account = AccountFactory()
            response = self.client.post(
                ACCOUNTS_PATH_V1,
                json=account.to_dict()
            )
            self.assertEqual(
                response.status_code,
                status.HTTP_201_CREATED,
                'Could not create test Account',
            )
            new_account = response.get_json()
            account.id = new_account['id']  # pylint: disable=C0103
            accounts.append(account)
        return accounts

    ######################################################################
    #  GENERAL TEST CASES
    ######################################################################
    def test_index(self):
        """It should get 200_OK from the Home Page."""
        response = self.client.get(ROOT_PATH)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_health(self):
        """It should be healthy."""
        response = self.client.get(HEALTH_PATH)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = response.get_json()
        self.assertEqual(data['status'], 'UP')

    def test_unsupported_media_type(self):
        """
        It should not create an Account when sending the wrong media type.
        """
        account = AccountFactory()
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=account.to_dict(),
            content_type='test/html'
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )

    def test_security_headers(self):
        """It should return security headers."""
        response = self.client.get(
            ROOT_PATH,
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
            ROOT_PATH,
            environ_overrides=HTTPS_ENVIRON
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check for the CORS header
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'),
            '*'
        )

    ######################################################################
    #  CREATE ACCOUNTS TEST CASES
    ######################################################################
    def test_create_accounts_success(self):
        """It should create a new Account."""
        account = AccountFactory()
        response = self.client.post(
            ACCOUNTS_PATH_V1,
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

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('requests.get')
    def test_list_accounts_success(self, mock_get):
        """It should return a list of accounts with a valid JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(3)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(len(data['items']), 3)

    @patch('requests.get')
    def test_list_accounts_paginated(self, mock_get):
        """It should return paginated accounts with a valid JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(15)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}?page=2&per_page=5",
            content_type='application/json',
            headers=headers,
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(len(data['items']), 5)
        self.assertEqual(data['page'], 2)
        self.assertEqual(data['per_page'], 5)
        self.assertEqual(data['total'], 15)

    @patch('requests.get')
    def test_list_accounts_cache(self, mock_get):
        """It should retrieve data from the cache on subsequent requests."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(3)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        # First request (populates cache)
        response1 = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers,
        )

        self.assertEqual(response1.status_code, status.HTTP_200_OK)

        # Second request (retrieves from cache)
        with patch(
                'service.routes.Account.all_paginated') as mock_all_paginated:
            response2 = self.client.get(
                ACCOUNTS_PATH_V1,
                content_type='application/json',
                headers=headers,
            )
            self.assertEqual(response2.status_code, status.HTTP_200_OK)
            mock_all_paginated.assert_not_called()

    def test_list_accounts_unauthorized(self):
        """It should return 401 if no JWT is provided."""
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_list_accounts_etag_match(self, mock_get):
        """It should return 304 if ETag matches If-None-Match."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(2)

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
        etag = response.headers.get('ETag').replace('"', '')  # Extract ETag
        headers[IF_NONE_MATCH_HEADER] = etag

        # Make a second request with If-None-Match header
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(response.data, b'')  # Check for empty body

    @patch('requests.get')
    def test_list_accounts_etag_mismatch(self, mock_get):
        """It should return 200 if ETag does not match If-None-Match."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(2)

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        headers[IF_NONE_MATCH_HEADER] = INVALID_ETAG

        # Make a second request with If-None-Match header
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch('requests.get')
    def test_list_accounts_user_identity(self, mock_get):
        """It should return correct user identity."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        self._create_accounts(2)

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        with app.test_request_context(headers=headers):
            verify_jwt_in_request()
            user_identity = get_jwt_identity()
            self.assertEqual(user_identity, TEST_USER)

    ######################################################################
    #  READ AN ACCOUNTS TEST CASES
    ######################################################################
    @patch('requests.get')
    def test_find_by_id_success(self, mock_get):
        """It should return a single account with a valid JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        account = self._create_accounts(1)[0]
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(data['name'], account.name)

    def test_find_by_id_unauthorized(self):
        """It should return 401 if no JWT is provided."""
        account = self._create_accounts(1)[0]

        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_find_by_id_etag_match(self, mock_get):
        """It should return 304 if ETag matches If-None-Match."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        account = self._create_accounts(1)[0]

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
        etag = response.headers.get('ETag').replace('"', '')  # Extract ETag
        headers[IF_NONE_MATCH_HEADER] = etag

        # Make a second request with If-None-Match header
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(response.data, b'')  # Check for empty body

    @patch('requests.get')
    def test_find_by_id_etag_mismatch(self, mock_get):
        """It should return 200 if ETag does not match If-None-Match."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        account = self._create_accounts(1)[0]

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        headers[IF_NONE_MATCH_HEADER] = INVALID_ETAG

        # Make a second request with a different If-None-Match header
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_find_by_id_not_found(self):
        """It should not read an Account that is not found."""
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  UPDATE AN EXISTING ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    def test_update_by_id_success(self, mock_get):
        """It should update an existing Account."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        test_account_dto = AccountDTO.from_orm(test_account)

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 with right account id and role
        test_jwt = jwt.encode(
            {
                'sub': test_account.name,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # update the account
        new_account = response.get_json()
        new_account['name'] = 'Something Known'
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=new_account,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['name'], 'Something Known')

    @patch('requests.get')
    def test_update_by_id_unauthorized(self, mock_get):
        """It should return 401 if no JWT is provided."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_update_by_id_wrong_role(self, mock_get):
        """It should not update an existing Account with a JWT belonging to a different role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        test_account_dto = AccountDTO.from_orm(test_account)

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        # update the account
        new_account = response.get_json()
        new_account['name'] = 'Something Known'
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=new_account,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_update_by_id_wrong_account_id(self, mock_get):
        """It should not update an existing Account with a JWT belonging to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        test_account_dto = AccountDTO.from_orm(test_account)

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 (different account name)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # update the account
        new_account = response.get_json()
        new_account['name'] = 'Something Known'
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=new_account,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_update_by_id_wrong_account_id_admin_role(self, mock_get):
        """It should update an existing Account with a JWT belonging to a
        different user if an admin role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        test_account_dto = AccountDTO.from_orm(test_account)

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 (different account name)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_ADMIN]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # update the account
        new_account = response.get_json()
        new_account['name'] = 'Something Known'
        new_account['email'] = 'test@example.com'
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=new_account,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['name'], 'Something Known')
        self.assertEqual(updated_account['email'], 'test@example.com')

    def test_update_by_id_not_found(self):
        """It should not update an Account that is not found."""
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  PARTIALLY UPDATE AN EXISTING ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    def test_partial_update_by_id_success(self, mock_get):
        """It should partially update an existing Account."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 with right account id and role
        test_jwt = jwt.encode(
            {
                'sub': test_account.name,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['name'], 'Test Account')
        self.assertEqual(updated_account['email'], 'test@example.com')

    @patch('requests.get')
    def test_partial_update_by_id_unauthorized(self, mock_get):
        """It should return 401 if no JWT is provided."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_role(self, mock_get):
        """It should not partially update an existing Account with a JWT
        belonging to a different role.
        """
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_account_id(self, mock_get):
        """It should not partially update an existing Account with a JWT
        belonging to a different user.
        """
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 (different account name)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Test Account',
            'email': 'test@example.com'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_account_id_admin_role(self, mock_get):
        """It should partially update an existing Account with a JWT
        belonging to a different user if an admin role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to update
        test_account = AccountFactory()

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account.to_dict(),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Generate test JWT using RS256 (different account name)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_ADMIN]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        # partially update the account
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'name': 'Something Known',
            'email': 'test@example.com'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['name'], 'Something Known')
        self.assertEqual(updated_account['email'], 'test@example.com')

    def test_partial_update_by_id_not_found(self):
        """It should not partially update an Account that is not found."""
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  DELETE AN ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    def test_delete_by_id_success(self, mock_get):
        """It should delete an Account."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to delete
        account = self._create_accounts(1)[0]

        # Generate test JWT using RS256 with right account id and role
        test_jwt = jwt.encode(
            {
                'sub': account.name,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data, b'')  # Check for empty body

    def test_delete_by_id_unauthorized(self):
        """It should return 401 if no JWT is provided."""
        # create an Account to delete
        account = self._create_accounts(1)[0]

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}"
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_delete_by_id_wrong_role(self, mock_get):
        """It should not delete an Account with a JWT belonging to a different
        role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to delete
        account = self._create_accounts(1)[0]

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_delete_by_id__wrong_account_id(self, mock_get):
        """It not should not delete an Account with a JWT belonging to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to delete
        account = self._create_accounts(1)[0]

        # Generate test JWT using RS256 with right account id and role
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_USER]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_delete_by_id__wrong_account_id_admin_role(self, mock_get):
        """It not should not delete an Account with a JWT belonging to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs

        # create an Account to delete
        account = self._create_accounts(1)[0]

        # Generate test JWT using RS256 with right account id and role
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER,
                REALM_ACCESS_CLAIM: {
                    ROLES_CLAIM: [ROLE_ADMIN]
                }
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.data, b'')  # Check for empty body


def dummy_function() -> str:
    """A simple dummy function to test the audit_log decorator."""
    return ORIGINAL


class TestAuditLogDecorator(TestCase):
    """Audit Log Decorator Tests."""

    def test_audit_enabled(self):
        """It should apply audit logging when AUDIT_ENABLED is True."""
        with patch("service.routes.AUDIT_ENABLED", True), \
                patch("service.common.audit_utils.audit_log_kafka",
                      side_effect=lambda f: f) as mock_audit_log_kafka:
            decorated = audit_log(dummy_function)
            mock_audit_log_kafka.assert_called_once_with(dummy_function)
            self.assertEqual(decorated(), ORIGINAL)

    def test_audit_disabled(self):
        """It should not apply audit logging when AUDIT_ENABLED is False."""
        with patch("service.routes.AUDIT_ENABLED", False):
            result_function = audit_log(dummy_function)
            self.assertIs(result_function, dummy_function)
            self.assertEqual(result_function(), ORIGINAL)

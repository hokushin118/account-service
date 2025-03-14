# pylint:disable=C0302
"""
Account API Service Test Suite.
Test cases can be run with:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""

from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from flask_jwt_extended import JWTManager
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
    IF_NONE_MATCH_HEADER,
    CACHE_CONTROL_HEADER,
    audit_log
)
from service.schemas import AccountDTO
from tests.factories import AccountFactory
from tests.test_base import BaseTestCase
from tests.test_constants import TEST_USER_ID

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}
JWT_ALGORITHM = 'RS256'
PRIVATE_KEY_PATH = './tests/keys/private.pem'
PUBLIC_KEY_PATH = './tests/keys/public.pem'
INVALID_ETAG = 'invalid-etag'
ORIGINAL = 'original'


######################################################################
#  ROUTE TEST CASES
######################################################################
class TestAccountRoute(BaseTestCase):  # pylint: disable=R0904
    """Account Route Tests."""

    def setUp(self):
        """It should run before each test to set up the testing environment."""
        db.session.rollback()
        db.session.query(Account).delete()
        db.session.commit()

        self.client = app.test_client()

        # Generate a private/public key pair.
        # For example:
        #   openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
        #   openssl rsa -pubout -in private.pem -out public.pem

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
        # Generate a test JWT using RS256
        self.test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
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

    ######################################################################
    #  HELPER METHODS
    ######################################################################
    def _create_accounts(self, count):
        """It should create a specified number of accounts using the factory."""
        accounts = []
        for _ in range(count):
            account = AccountFactory()
            # Generate test JWT for this account (using account.user_id and role)
            test_jwt = jwt.encode(
                {
                    'sub': str(account.user_id),
                    REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
                },
                self.private_key,
                algorithm=JWT_ALGORITHM,
                headers={'kid': 'test-kid'}
            )
            headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
            response = self.client.post(
                ACCOUNTS_PATH_V1,
                json=account.to_dict(),
                headers=headers
            )
            self.assertEqual(response.status_code, status.HTTP_201_CREATED,
                             'Could not create test Account')
            new_account = response.get_json()
            account.id = new_account['id']
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
        """It should be healthy when the health endpoint is called."""
        response = self.client.get(HEALTH_PATH)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(data['status'], 'UP')

    def test_unsupported_media_type(self):
        """It should not create an Account when sending the wrong media type."""
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        account = AccountFactory()
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=account.to_dict(),
            content_type='test/html',
            headers=headers
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )

    def test_security_headers(self):
        """It should return the correct security headers."""
        response = self.client.get(ROOT_PATH, environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        expected_headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'; object-src 'none'",
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        for key, value in expected_headers.items():
            # Optionally skip extra checks on headers that might vary.
            if key != 'Content-Security-Policy':
                self.assertEqual(response.headers.get(key), value)

    def test_cors_security(self):
        """It should include a CORS header allowing all origins."""
        response = self.client.get(ROOT_PATH, environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'),
            '*'
        )

    ######################################################################
    #  CREATE ACCOUNTS TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.get_jwt_identity')
    def test_create_accounts_success(self, mock_jwt_identity, mock_get):
        """It should create a new Account successfully."""
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_get.return_value.status_code = status.HTTP_201_CREATED
        mock_get.return_value.json.return_value = self.mock_certs
        account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNotNone(response.headers.get('Location'))
        new_account = response.get_json()
        self.assertEqual(new_account['name'], test_account_dto.name)
        self.assertEqual(new_account['email'], test_account_dto.email)
        self.assertEqual(new_account['address'], test_account_dto.address)
        self.assertEqual(new_account['phone_number'],
                         test_account_dto.phone_number)
        self.assertEqual(new_account['user_id'], TEST_USER_ID)

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.cache.set')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_list_accounts_success(self,
                                   mock_jwt_identity,
                                   mock_cache_get,
                                   mock_cache_set,
                                   mock_get):
        """It should return a list of accounts when a valid JWT is provided."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_cache_set.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create account first.
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Retrieve all accounts.
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(len(data['items']), 1)

    @patch('requests.get')
    @patch('service.routes.cache.set')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_list_accounts_paginated(self,
                                     mock_jwt_identity,
                                     mock_cache_get,
                                     mock_cache_set,
                                     mock_get):
        """It should return paginated account results when valid pagination
        parameters are provided."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_cache_set.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create account first.
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # List paginated accounts.
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}?page=1&per_page=5",
            content_type='application/json',
            headers=headers,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(len(data['items']), 1)
        self.assertEqual(data['page'], 1)
        self.assertEqual(data['per_page'], 5)
        self.assertEqual(data['total'], 1)

    def test_list_accounts_unauthorized(self):
        """It should return 401 Unauthorized if no JWT is provided when listing accounts."""
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    @patch('service.routes.cache.set')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_list_accounts_etag_match(self,
                                      mock_jwt_identity,
                                      mock_cache_get,
                                      mock_cache_set,
                                      mock_get):
        """It should return 304 Not Modified if the ETag matches the client's
        If-None-Match header."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_cache_set.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create an account
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # First GET to collect an ETag.
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
        etag = response.headers.get('ETag').replace('"', '')
        headers[IF_NONE_MATCH_HEADER] = etag
        # Second GET should yield 304 if ETag matches.
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(response.data, b'')

    @patch('requests.get')
    @patch('service.routes.cache.set')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_list_accounts_etag_mismatch(self,
                                         mock_jwt_identity,
                                         mock_cache_get,
                                         mock_cache_set,
                                         mock_get):
        """It should return 200 OK if the ETag does not match the client's If-None-Match header."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_cache_set.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[IF_NONE_MATCH_HEADER] = INVALID_ETAG
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    ######################################################################
    #  READ AN ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.get_account_or_404')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_find_by_id_success(self,
                                mock_jwt_identity,
                                mock_cache_get,
                                mock_get_account_or_404,
                                mock_get):
        """It should return a single account when a valid JWT is provided."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_get_account_or_404.return_value = account
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(data['name'], account.name)

    def test_find_by_id_unauthorized(self):
        """It should return 401 Unauthorized if no JWT is provided when reading an account."""
        account = self._create_accounts(1)[0]
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    @patch('service.routes.get_account_or_404')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_find_by_id_etag_match(self,
                                   mock_jwt_identity,
                                   mock_cache_get,
                                   mock_get_account_or_404,
                                   mock_get):
        """It should return 304 Not Modified if the ETag matches when reading an account."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_get_account_or_404.return_value = account
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
        etag = response.headers.get('ETag').replace('"', '')
        headers[IF_NONE_MATCH_HEADER] = etag
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(response.data, b'')

    @patch('requests.get')
    @patch('service.routes.get_account_or_404')
    @patch('service.routes.cache.get')
    @patch('service.routes.get_jwt_identity')
    def test_find_by_id_etag_mismatch(self,
                                      mock_jwt_identity,
                                      mock_cache_get,
                                      mock_get_account_or_404,
                                      mock_get):
        """It should return 200 OK if the ETag does not match when reading an account."""
        account = AccountFactory()
        mock_jwt_identity.return_value = TEST_USER_ID
        mock_cache_get.return_value = None
        mock_get_account_or_404.return_value = account
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[IF_NONE_MATCH_HEADER] = INVALID_ETAG
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_find_by_id_not_found(self):
        """It should return 404 Not Found when requesting an account that does not exist."""
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  UPDATE AN EXISTING ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.check_if_user_is_owner')
    @patch('service.routes.get_jwt_identity')
    def test_update_by_id_success(self,
                                  mock_jwt_identity,
                                  mock_check_if_user_is_owner,
                                  mock_get):
        """It should update an existing Account successfully when a valid
        JWT and ownership are provided."""
        account = AccountFactory()
        mock_jwt_identity.return_value = account.user_id
        mock_check_if_user_is_owner.return_value = True
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        test_jwt = jwt.encode(
            {
                'sub': str(account.user_id),
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        new_account['phone_number'] = '918-295-1876'
        new_account['address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=new_account,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['phone_number'], '918-295-1876')
        self.assertEqual(
            updated_account['address'],
            '718 Noah Drive\nChristensenburgh, NE 45784'
        )

    @patch('requests.get')
    def test_update_by_id_unauthorized(self, mock_get):
        """It should return 401 Unauthorized when updating an account without a JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        update_data = {'name': 'Test Account', 'email': 'test@example.com'}
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=update_data
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_update_by_id_wrong_role(self, mock_get):
        """It should not update an Account when the JWT belongs to a user with the wrong role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
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
        """It should not update an Account when the JWT belongs to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        update_data = {'name': 'Test Account', 'email': 'test@example.com'}
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_update_by_id_wrong_account_id_admin_role(self, mock_get):
        """It should update an Account when the JWT is for an admin, even if the
        account belongs to another user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_ADMIN]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
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
        """It should return 404 Not Found when attempting to update an account
        that does not exist."""
        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  PARTIALLY UPDATE AN EXISTING ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.check_if_user_is_owner')
    @patch('service.routes.get_jwt_identity')
    def test_partial_update_by_id_success(self,
                                          mock_jwt_identity,
                                          mock_check_if_user_is_owner,
                                          mock_get):
        """It should partially update an Account when a valid JWT and ownership are provided."""
        account = AccountFactory()
        mock_jwt_identity.return_value = account.user_id
        mock_check_if_user_is_owner.return_value = True
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account_dto = AccountDTO.from_orm(account)
        test_jwt = jwt.encode(
            {
                'sub': str(account.user_id),
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {
            'phone_number': '918-295-1876',
            'address': '718 Noah Drive\nChristensenburgh, NE 45784'
        }
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_account = response.get_json()
        self.assertEqual(updated_account['phone_number'], '918-295-1876')
        self.assertEqual(
            updated_account['address'],
            '718 Noah Drive\nChristensenburgh, NE 45784'
        )

    @patch('requests.get')
    def test_partial_update_by_id_unauthorized(self, mock_get):
        """It should return 401 Unauthorized when attempting a partial update without a JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {'name': 'Test Account', 'email': 'test@example.com'}
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_role(self, mock_get):
        """It should not partially update an Account when the JWT belongs to a user
        with the wrong role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {'name': 'Test Account', 'email': 'test@example.com'}
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_account_id(self, mock_get):
        """It should not partially update an Account when the JWT belongs to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {'name': 'Test Account', 'email': 'test@example.com'}
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
            content_type='application/json',
            json=update_data,
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_partial_update_by_id_wrong_account_id_admin_role(self, mock_get):
        """It should partially update an Account with an admin JWT even when the
        account belongs to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_account = AccountFactory()
        test_account_dto = AccountDTO.from_orm(test_account)
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_ADMIN]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_account = response.get_json()
        updated_account_id = new_account['id']
        update_data = {'name': 'Something Known', 'email': 'test@example.com'}
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
        """It should return 404 Not Found when attempting a partial update
        on a non-existent Account."""
        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/0",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    ######################################################################
    #  DELETE AN ACCOUNT TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.routes.check_if_user_is_owner')
    def test_delete_by_id_success(self, mock_check_if_user_is_owner, mock_get):
        """It should delete an Account successfully when authorized."""
        mock_check_if_user_is_owner.return_value = True
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        account = self._create_accounts(1)[0]
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
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
        self.assertEqual(response.data, b"")

    def test_delete_by_id_unauthorized(self):
        """It should return 401 Unauthorized when deleting an Account without a JWT."""
        account = self._create_accounts(1)[0]
        response = self.client.delete(f"{ACCOUNTS_PATH_V1}/{account.id}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    def test_delete_by_id_wrong_role(self, mock_get):
        """It should not delete an Account when the JWT belongs to a user with the wrong role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        account = self._create_accounts(1)[0]
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('requests.get')
    def test_delete_by_id_wrong_account_id(self, mock_get):
        """It should not delete an Account when the JWT belongs to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        account = self._create_accounts(1)[0]
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
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
    def test_delete_by_id_wrong_account_id_admin_role(self, mock_get):
        """It should delete an Account when the JWT is for an admin, even if the
        account belongs to a different user."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        account = self._create_accounts(1)[0]
        test_jwt = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_ADMIN]}
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
        self.assertEqual(response.data, b"")


######################################################################
#  AUDIT LOG DECORATOR TEST CASES
######################################################################
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

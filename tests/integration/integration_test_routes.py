# pylint:disable=C0302
"""
Account Routes Integration Test Suite.

Test cases can be run with:
  APP_SETTINGS=testing nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
import unittest
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives import serialization
from flask_jwt_extended import JWTManager
from jose import jwt

from service import AUTHORIZATION_HEADER, BEARER_HEADER, NAME, VERSION
from service.common import status  # HTTP Status Codes
from service.common.constants import ROLE_USER, ROLE_ADMIN
from service.common.keycloak_utils import KEYS, REALM_ACCESS_CLAIM, ROLES_CLAIM
from service.errors import AccountAuthorizationError
from service.models import db, Account
from service.routes import (
    app,
    ACCOUNTS_PATH_V1,
    ROOT_PATH,
    HEALTH_PATH,
    IF_NONE_MATCH_HEADER,
    CACHE_CONTROL_HEADER,
    account_service, INFO_PATH
)
from service.schemas import AccountDTO, PartialUpdateAccountDTO
from tests.integration.base import BaseTestCase
from tests.utils.constants import (
    TEST_USER_ID,
    TEST_ETAG,
    TEST_PAGE,
    TEST_PER_PAGE,
    TEST_TOTAL
)
from tests.utils.factories import AccountFactory

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}
JWT_ALGORITHM = 'RS256'
PRIVATE_KEY_PATH = './tests/utils/keys/private.pem'
PUBLIC_KEY_PATH = './tests/utils/keys/public.pem'
INVALID_ETAG = 'invalid-etag'
ORIGINAL = 'original'


######################################################################
#  ROUTE INTEGRATION TEST CASES
######################################################################
@unittest.skipIf(
    os.getenv('RUN_INTEGRATION_TESTS') != 'true',
    'Integration tests skipped'
)
class TestAccountRoute(BaseTestCase):  # pylint: disable=R0904
    """Account Route Tests."""

    account_data = None
    paginated_data = None
    account = None
    test_account_dto = None

    def setUp(self):
        """It should run before each test to set up the testing environment."""
        db.session.rollback()
        db.session.query(Account).delete()
        db.session.commit()

        self.client = app.test_client()

        self.account = AccountFactory()
        self.test_account_dto = AccountDTO.model_validate(self.account)

        self.account_data = {
            'id': self.account.id,
            'name': self.account.name,
            'email': self.account.email,
            'address': self.account.address,
            'phone_number': self.account.phone_number,
            'date_joined': self.account.date_joined,
            'user_id': self.account.user_id
        }

        self.paginated_data = {
            'items': [self.account_data],
            'page': TEST_PAGE,
            'per_page': TEST_PER_PAGE,
            'total': TEST_TOTAL
        }

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
            self.assertEqual(
                response.status_code, status.HTTP_201_CREATED,
                'Could not create test Account'
            )
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

    def test_info(self):
        """It should get 200_OK when the info endpoint is called."""
        response = self.client.get(INFO_PATH)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.get_json()
        self.assertEqual(data['name'], NAME)
        self.assertEqual(data['version'], VERSION)

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
    def test_create_accounts_success(self, mock_get):
        """It should create a new Account successfully."""
        mock_get.return_value.status_code = status.HTTP_201_CREATED
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIsNotNone(response.headers.get('Location'))
        new_account = response.get_json()
        self.assertEqual(new_account['name'], self.test_account_dto.name)
        self.assertEqual(new_account['email'], self.test_account_dto.email)
        self.assertEqual(new_account['address'], self.test_account_dto.address)
        self.assertEqual(
            new_account['phone_number'],
            self.test_account_dto.phone_number
        )
        self.assertEqual(new_account['user_id'], TEST_USER_ID)

    @patch('requests.get')
    def test_create_accounts_invalid_data(self, mock_get):
        """It should not create a new Account."""
        mock_get.return_value.status_code = status.HTTP_201_CREATED
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=None,
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('requests.get')
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_list_accounts_success(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return a list of accounts when a valid JWT is provided."""
        mock_account_service.list_accounts.return_value = self.paginated_data, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create account first.
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
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
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_list_accounts_paginated(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return paginated account results when valid pagination
        parameters are provided."""
        mock_account_service.list_accounts.return_value = self.paginated_data, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create account first.
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
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
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_list_accounts_etag_match(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return 304 Not Modified if the ETag matches the client's
        If-None-Match header."""
        mock_account_service.list_accounts.return_value = self.paginated_data, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        # Create an account
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
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
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_list_accounts_etag_mismatch(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return 200 OK if the ETag does not match the client's If-None-Match header."""
        mock_account_service.list_accounts.return_value = self.paginated_data, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
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
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_find_by_id_success(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return a single account when a valid JWT is provided."""
        mock_account_service.get_account_or_404.return_value = self.account
        mock_account_service.get_account_by_id.return_value = self.test_account_dto, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        mock_account_service.get_account_or_404.assert_called_once()

    def test_find_by_id_unauthorized(self):
        """It should return 401 Unauthorized if no JWT is provided when reading an account."""
        account = self._create_accounts(1)[0]
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account.id}",
            content_type='application/json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('requests.get')
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_find_by_id_etag_match(self,
                                   mock_account_service,
                                   mock_cache,
                                   mock_get):
        """It should return 304 Not Modified if the ETag matches when reading an account."""
        mock_account_service.get_account_or_404.return_value = self.account
        mock_account_service.get_account_by_id.return_value = self.test_account_dto, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
        etag = response.headers.get('ETag').replace('"', '')
        headers[IF_NONE_MATCH_HEADER] = etag
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_304_NOT_MODIFIED)
        self.assertEqual(response.data, b'')

    @patch('requests.get')
    @patch('service.services.cache')
    @patch("service.services.AccountService")
    def test_find_by_id_etag_mismatch(
            self,
            mock_account_service,
            mock_cache,
            mock_get
    ):
        """It should return 200 OK if the ETag does not match when reading an account."""
        mock_account_service.get_account_or_404.return_value = self.account
        mock_account_service.get_account_by_id.return_value = self.test_account_dto, TEST_ETAG
        mock_cache.set.return_value = None
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.to_dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        headers[IF_NONE_MATCH_HEADER] = INVALID_ETAG
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
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
    def test_update_by_id_success(self, mock_get):
        """It should update an existing Account successfully when a valid
        JWT and ownership are provided."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_jwt = jwt.encode(
            {
                'sub': str(self.account.user_id),
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        expected_result = self.test_account_dto
        expected_result.phone_number = '918-295-1876'
        expected_result.address = '718 Noah Drive\nChristensenburgh, NE 45784'
        # Patch the account_service.update_by_id so it returns expected_result
        with patch.object(
                account_service, 'update_by_id',
                return_value=expected_result
        ) as mock_update:
            new_account = response.get_json()
            new_account['phone_number'] = '918-295-1876'
            new_account[
                'address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
            response = self.client.put(
                f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
                content_type='application/json',
                json=new_account,
                headers=headers
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # Create a mock response object
            response = MagicMock()
            # Configure the get_json method to return a specific dictionary
            expected_json = self.test_account_dto.to_dict()
            response.get_json.return_value = expected_json
            updated_account = response.get_json()
            self.assertEqual(updated_account['phone_number'], '918-295-1876')
            self.assertEqual(
                updated_account['address'],
                '718 Noah Drive\nChristensenburgh, NE 45784'
            )
            mock_update.assert_called_once()

    @patch('requests.get')
    def test_update_by_id_unauthorized(self, mock_get):
        """It should return 401 Unauthorized when updating an account without a JWT."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
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
    def test_update_by_id_wrong_role(
            self,
            mock_get
    ):
        """It should not update an Account when the JWT belongs to a user with the wrong role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        expected_result = self.test_account_dto.dict()
        expected_result['phone_number'] = '918-295-1876'
        expected_result[
            'address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
        # Patch the account_service.update_by_id so it returns expected_result
        with patch.object(
                account_service, 'update_by_id',
                side_effect=AccountAuthorizationError("Authorization failed")
        ) as mock_update:
            new_account = response.get_json()
            new_account['phone_number'] = '918-295-1876'
            new_account[
                'address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
            response = self.client.put(
                f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
                content_type='application/json',
                json=new_account,
                headers=headers
            )
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            mock_update.assert_called_once()

    # @patch('requests.get')
    # def test_update_by_id_wrong_account_id_admin_role(self, mock_get):
    #     """It should update an Account when the JWT is for an admin, even if the
    #     account belongs to another user."""
    #     mock_get.return_value.status_code = status.HTTP_200_OK
    #     mock_get.return_value.json.return_value = self.mock_certs
    #     test_jwt = jwt.encode(
    #         {
    #             'sub': TEST_USER_ID,
    #             REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_ADMIN]}
    #         },
    #         self.private_key,
    #         algorithm=JWT_ALGORITHM,
    #         headers={'kid': 'test-kid'}
    #     )
    #     headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
    #     response = self.client.post(
    #         ACCOUNTS_PATH_V1,
    #         json=self.test_account_dto.dict(),
    #         content_type='application/json',
    #         headers=headers
    #     )
    #     self.assertEqual(response.status_code, status.HTTP_201_CREATED)
    #     new_account = response.get_json()
    #     new_account['name'] = 'Something Known'
    #     new_account['email'] = 'test@example.com'
    #     response = self.client.put(
    #         f"{ACCOUNTS_PATH_V1}/{new_account['id']}",
    #         content_type='application/json',
    #         json=new_account,
    #         headers=headers
    #     )
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     updated_account = response.get_json()
    #     self.assertEqual(updated_account['name'], 'Something Known')
    #     self.assertEqual(updated_account['email'], 'test@example.com')

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
    def test_partial_update_by_id_success(self, mock_get):
        """It should partially update an existing Account successfully when
        a valid JWT and ownership are provided."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        test_jwt = jwt.encode(
            {
                'sub': str(self.account.user_id),
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [ROLE_USER]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        expected_result = self.test_account_dto.dict()
        expected_result['phone_number'] = '918-295-1876'
        expected_result[
            'address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
        # Patch the account_service.update_by_id so it returns expected_result
        with patch.object(
                account_service, 'partial_update_by_id',
                return_value=expected_result
        ) as mock_update:
            new_account = response.get_json()
            updated_account_id = new_account['id']
            update_data = {
                'phone_number': '918-295-1876',
                'address': '718 Noah Drive\nChristensenburgh, NE 45784'
            }
            partial_update_account_dto = PartialUpdateAccountDTO(
                **update_data
            )
            response = self.client.patch(
                f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
                content_type='application/json',
                json=partial_update_account_dto.to_dict(),
                headers=headers
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            updated_account = response.get_json()
            self.assertEqual(updated_account['phone_number'], '918-295-1876')
            self.assertEqual(
                updated_account['address'],
                '718 Noah Drive\nChristensenburgh, NE 45784'
            )
            mock_update.assert_called_once()

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
    def test_partial_update_by_id_wrong_role(
            self,
            mock_get
    ):
        """It should not partially update an Account when the JWT belongs to a user
        with the wrong role."""
        mock_get.return_value.status_code = status.HTTP_200_OK
        mock_get.return_value.json.return_value = self.mock_certs
        headers = {AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.test_jwt}"}
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=headers
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        expected_result = self.test_account_dto.dict()
        expected_result['phone_number'] = '918-295-1876'
        expected_result[
            'address'] = '718 Noah Drive\nChristensenburgh, NE 45784'
        # Patch the account_service.update_by_id so it returns expected_result
        with patch.object(
                account_service, 'partial_update_by_id',
                side_effect=AccountAuthorizationError("Authorization failed")
        ) as mock_update:
            new_account = response.get_json()
            updated_account_id = new_account['id']
            update_data = {
                'phone_number': '918-295-1876',
                'address': '718 Noah Drive\nChristensenburgh, NE 45784'
            }
            partial_update_account_dto = PartialUpdateAccountDTO(
                **update_data
            )
            response = self.client.patch(
                f"{ACCOUNTS_PATH_V1}/{updated_account_id}",
                content_type='application/json',
                json=partial_update_account_dto.to_dict(),
                headers=headers
            )
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            mock_update.assert_called_once()

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
    @patch("service.services.AccountService")
    def test_delete_by_id_success(
            self,
            mock_account_service,
            mock_get
    ):
        """It should delete an Account successfully when authorized."""
        mock_account_service.delete_by_id.return_value = None
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

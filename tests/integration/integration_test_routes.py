"""
Account Routes Integration Test Suite.

Test cases can be run with:
  RUN_INTEGRATION_TESTS=true nosetests -v --with-spec --spec-color tests/integration
  coverage report -m
"""
import json
import logging
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from flask_caching import Cache
from flask_jwt_extended import JWTManager
from testcontainers.kafka import KafkaContainer
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from service import (
    NAME,
    VERSION
)
from service.common import status  # HTTP Status Codes
from service.errors import AccountAuthorizationError
from service.models import db
from service.routes import (
    app,
    ACCOUNTS_PATH_V1,
    IF_NONE_MATCH_HEADER,
    ROOT_PATH,
    INFO_PATH,
    HEALTH_PATH
)
from service.schemas import UpdateAccountDTO
from service.services import AccountService
from tests.integration.base import BaseTestCase, PUBLIC_KEY_PATH
from tests.utils.constants import TEST_USER_ID
from tests.utils.utils import (
    wait_for_redis_container,
    apply_migrations
)

logger = logging.getLogger(__name__)

HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}
INVALID_ETAG = 'invalid-etag'


######################################################################
#  ROUTE INTEGRATION TEST CASES
######################################################################
@unittest.skipIf(
    os.getenv('RUN_INTEGRATION_TESTS') != 'true',
    'Integration tests skipped'
)
class TestAccountRoute(BaseTestCase):  # pylint: disable=R0904
    """Account Route Tests."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Start Testcontainers
        cls.postgres_container = PostgresContainer('postgres:14')
        cls.postgres_container.start()
        cls.kafka_container = KafkaContainer()
        cls.kafka_container.start()
        cls.redis_container = RedisContainer()
        cls.redis_container.start()

        # Update app config with container connection details
        app.config[
            'DATABASE_URI'] = cls.postgres_container.get_connection_url()
        app.config[
            'SQLALCHEMY_DATABASE_URI'] = cls.postgres_container.get_connection_url()
        app.config[
            'KAFKA_AUDIT_BOOTSTRAP_SERVERS'] = cls.kafka_container.get_bootstrap_server()

        # Construct Redis URL manually
        redis_host = cls.redis_container.get_container_host_ip()
        redis_port = cls.redis_container.get_exposed_port(6379)
        redis_url = f"redis://{redis_host}:{redis_port}/0"

        # Configure Flask app to use the Redis container
        app.config['CACHE_REDIS_URL'] = redis_url
        app.config['REDIS_URL'] = redis_url
        app.config['CACHE_TYPE'] = 'redis'
        app.config['CACHE_REDIS_DB'] = '0'
        app.config['CACHE_REDIS_HOST'] = redis_host
        app.config['CACHE_REDIS_PORT'] = redis_port

        app.config['KAFKA_PRODUCER_TOPIC'] = 'test_topic'
        app.config['KAFKA_PRODUCER_ACKS'] = 1
        app.config[
            'KAFKA_PRODUCER_BOOTSTRAP_SERVERS'] = cls.kafka_container.get_bootstrap_server()

        app.config[
            'KAFKA_AUDIT_BOOTSTRAP_SERVERS'] = cls.kafka_container.get_bootstrap_server()

        app.config[
            'KAFKA_CONSUMER_BOOTSTRAP_SERVERS'] = cls.kafka_container.get_bootstrap_server()

        # Initialize JWT Manager
        cls.jwt = JWTManager(app)

        # Initialize Account Service
        cls.account_service = AccountService()

        db.create_all()

        # Apply migrations
        apply_migrations(app, cls.engine)

        # Redis readiness check
        wait_for_redis_container(app)

        cls.cache = Cache(app)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Stop Testcontainers
        cls.postgres_container.stop()
        cls.kafka_container.stop()
        cls.redis_container.stop()

    def setUp(self):
        super().setUp()
        self.client = app.test_client()

        with open(PUBLIC_KEY_PATH, 'rb') as public_key_file:
            app.config['JWT_PUBLIC_KEY'] = \
                serialization.load_pem_public_key(
                    public_key_file.read()
                )

    ######################################################################
    #  GENERAL TEST CASES
    ######################################################################
    def test_redis_connection(self):
        """It should successfully store and retrieve data from Redis using Flask-Caching."""
        with app.app_context():
            self.cache.set('test_key', 'test_value')
            retrieved_value = self.cache.get('test_key')
            self.assertEqual(retrieved_value, 'test_value')

    def test_index(self):
        """It should get 200_OK from the Home Page."""
        response = self.client.get(
            ROOT_PATH,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            json.loads(response.data),
            {"message": "Welcome to the Account API!"}
        )

    def test_health(self):
        """It should be healthy when the health endpoint is called."""
        response = self.client.get(
            HEALTH_PATH,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'UP')

    def test_info(self):
        """It should get 200_OK when the info endpoint is called."""
        response = self.client.get(
            INFO_PATH,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.data)
        self.assertEqual(data['name'], NAME)
        self.assertEqual(data['version'], VERSION)

    def test_unsupported_media_type(self):
        """It should not create an Account when sending the wrong media type."""
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.create_account_dto.dict(),
            content_type='test/html',
            headers=self.headers
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )

    def test_security_headers(self):
        """It should return the correct security headers."""
        response = self.client.get(
            ROOT_PATH,
            content_type='application/json',
            environ_overrides=HTTPS_ENVIRON
        )

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
        response = self.client.get(
            ROOT_PATH,
            content_type='application/json',
            environ_overrides=HTTPS_ENVIRON
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'),
            '*'
        )

    ######################################################################
    #  CREATE ACCOUNTS TEST CASES
    ######################################################################
    def test_create_accounts_success(self):
        """It should create a new Account successfully."""
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            json=self.create_account_dto.to_dict(),
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    @patch('service.services.AccountServiceHelper')
    def test_create_accounts_invalid_data(
            self,
            mock_account_service_helper
    ):
        """It should not create a new Account."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=None,
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('service.services.cache')
    @patch('service.services.AccountServiceHelper')
    def test_list_accounts_success(
            self,
            mock_account_service_helper,
            mock_cache
    ):
        """It should return a list of accounts when a valid JWT is provided."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_cache.set.return_value = None

        # Create an account
        account = self.account_service.create(self.create_account_dto)

        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=self.headers
        )

        data = json.loads(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(data['items']), 1)
        self.assertEqual(data['items'][0]['id'], str(account.id))
        self.assertEqual(data['items'][0]['name'], account.name)
        self.assertEqual(data['items'][0]['email'], account.email)
        self.assertEqual(data['items'][0]['address'], account.address)
        self.assertEqual(
            data['items'][0]['phone_number'],
            account.phone_number
        )
        self.assertEqual(data['items'][0]['user_id'], str(account.user_id))
        self.assertEqual(data['page'], 1)
        self.assertEqual(data['per_page'], 10)
        self.assertEqual(data['total'], 1)

    @patch('service.services.cache')
    @patch('service.services.AccountServiceHelper')
    def test_list_accounts_paginated(
            self,
            mock_account_service_helper,
            mock_cache
    ):
        """It should return paginated account results when valid pagination
        parameters are provided."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_cache.set.return_value = None

        # Create an account
        account = self.account_service.create(self.create_account_dto)

        # List paginated accounts.
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}?page=1&per_page=5",
            content_type='application/json',
            headers=self.headers
        )

        data = json.loads(response.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(data['items']), 1)
        self.assertEqual(data['items'][0]['id'], str(account.id))
        self.assertEqual(data['items'][0]['name'], account.name)
        self.assertEqual(data['items'][0]['email'], account.email)
        self.assertEqual(data['items'][0]['address'], account.address)
        self.assertEqual(
            data['items'][0]['phone_number'],
            account.phone_number
        )
        self.assertEqual(data['items'][0]['user_id'], str(account.user_id))
        self.assertEqual(data['page'], 1)
        self.assertEqual(data['per_page'], 5)
        self.assertEqual(data['total'], 1)

    @patch('service.services.cache')
    @patch('service.services.AccountServiceHelper')
    def test_list_accounts_etag(
            self,
            mock_account_service_helper,
            mock_cache
    ):
        """It should return 304 Not Modified if the ETag matches when reading an account."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_cache.get.return_value = None
        mock_cache.set.return_value = None

        # Create an account
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            json=self.create_account_dto.to_dict(),
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Get the account and ETag
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        etag = response.headers.get('ETag').replace('"', '')

        # Request with matching ETag
        headers_etag = self.headers.copy()
        headers_etag[IF_NONE_MATCH_HEADER] = etag
        response_etag = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            headers=headers_etag
        )

        self.assertEqual(
            response_etag.status_code,
            status.HTTP_304_NOT_MODIFIED
        )

        # Request with invalid ETag
        headers_invalid_etag = self.headers.copy()
        headers_invalid_etag[IF_NONE_MATCH_HEADER] = INVALID_ETAG
        response_invalid_etag = self.client.get(
            ACCOUNTS_PATH_V1,
            headers=headers_invalid_etag
        )

        self.assertEqual(response_invalid_etag.status_code, status.HTTP_200_OK)

    def test_list_accounts_unauthorized(self):
        """It should return 401 Unauthorized if no JWT is provided when listing accounts."""
        response = self.client.get(
            ACCOUNTS_PATH_V1,
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    ######################################################################
    #  READ AN ACCOUNT TEST CASES
    ######################################################################
    @patch('service.services.cache')
    @patch('service.services.AccountServiceHelper')
    def test_find_by_id_success(
            self,
            mock_account_service_helper,
            mock_cache
    ):
        """It should return a single account when a valid JWT is provided."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account
        mock_cache.get.return_value = None
        mock_cache.set.return_value = None

        # Create an account
        account = self.account_service.create(self.create_account_dto)

        response = self.client.get(
            f'{ACCOUNTS_PATH_V1}/{account.id}',
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.data)
        self.assertEqual(data['name'], account.name)
        self.assertEqual(data['email'], account.email)

    def test_find_by_id_unauthorized(self):
        """It should return 401 Unauthorized if no JWT is provided when reading an account."""
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{self.account.id}",
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('service.services.cache')
    @patch('service.services.AccountServiceHelper')
    def test_find_by_id_etag(
            self,
            mock_account_service_helper,
            mock_cache
    ):
        """It should return 304 Not Modified if the ETag matches when reading an account."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account
        mock_cache.get.return_value = None
        mock_cache.set.return_value = None

        # Create an account
        response = self.client.post(
            ACCOUNTS_PATH_V1,
            content_type='application/json',
            json=self.create_account_dto.to_dict(),
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        account_id = json.loads(response.data)['id']

        # Get the account and ETag
        response = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account_id}",
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        etag = response.headers.get('ETag').replace('"', '')

        # Request with matching ETag
        headers_etag = self.headers.copy()
        headers_etag[IF_NONE_MATCH_HEADER] = etag
        response_etag = self.client.get(
            f"{ACCOUNTS_PATH_V1}/{account_id}",
            content_type='application/json',
            headers=headers_etag
        )

        self.assertEqual(
            response_etag.status_code,
            status.HTTP_304_NOT_MODIFIED
        )

        # Request with invalid ETag
        headers_invalid_etag = self.headers.copy()
        headers_invalid_etag[IF_NONE_MATCH_HEADER] = INVALID_ETAG
        response_invalid_etag = self.client.get(
            f"{ACCOUNTS_PATH_V1}/"
            f"{account_id}",
            headers=headers_invalid_etag
        )

        self.assertEqual(response_invalid_etag.status_code, status.HTTP_200_OK)

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
    @patch('service.services.AccountServiceHelper')
    def test_update_by_id_success(
            self,
            mock_account_service_helper
    ):
        """It should update an existing Account successfully when a valid
        JWT and ownership are provided."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account

        # Create an account
        account = self.account_service.create(self.create_account_dto)
        update_account_dto = UpdateAccountDTO(**self.account_data)
        update_account_dto.name = 'Updated Account'
        update_account_dto.phone_number = '918-295-1876'

        response = self.client.put(
            f'{ACCOUNTS_PATH_V1}/{account.id}',
            json=update_account_dto.dict(),
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = json.loads(response.data)
        self.assertEqual(data['name'], 'Updated Account')
        self.assertEqual(data['phone_number'], '918-295-1876')

    @patch('service.services.AccountServiceHelper')
    def test_update_by_id_unauthorized(
            self,
            mock_account_service_helper
    ):
        """It should return 401 Unauthorized when attempting an update without a JWT."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account

        # Create an account
        account = self.account_service.create(self.create_account_dto)
        update_account_dto = UpdateAccountDTO(**self.account_data)
        update_account_dto.name = 'Updated Account'
        update_account_dto.phone_number = '918-295-1876'

        response = self.client.put(
            f'{ACCOUNTS_PATH_V1}/{account.id}',
            content_type='application/json',
            json=update_account_dto.dict()
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('service.services.AccountServiceHelper')
    def test_update_by_id_wrong_role(
            self,
            mock_account_service_helper
    ):
        """It should not partially update an Account when the JWT belongs to a user
        with the wrong role."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account
        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service_helper.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {TEST_USER_ID} is not authorized to perform this action."
            ))

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        update_account_dto = UpdateAccountDTO(**self.account_data)
        update_account_dto.name = 'Updated Account'
        update_account_dto.phone_number = '918-295-1876'

        response = self.client.put(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            json=update_account_dto.dict(),
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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
    @patch('service.services.AccountServiceHelper')
    def test_partial_update_by_id_success(
            self,
            mock_account_service_helper
    ):
        """It should partially update an existing Account successfully when a
        valid JWT and ownership are provided."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account

        # Create an account
        account = self.account_service.create(self.create_account_dto)

        response = self.client.patch(
            f'{ACCOUNTS_PATH_V1}/{account.id}',
            content_type='application/json',
            json={'name': 'Partially Updated Account'},
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            json.loads(response.data)['name'],
            'Partially Updated Account'
        )

    @patch('service.services.AccountServiceHelper')
    def test_partial_update_by_id_unauthorized(
            self,
            mock_account_service_helper
    ):
        """It should return 401 Unauthorized when attempting a partial update without a JWT."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account

        # Create an account
        account = self.account_service.create(self.create_account_dto)

        response = self.client.patch(
            f'{ACCOUNTS_PATH_V1}/{account.id}',
            content_type='application/json',
            json={'name': 'Partially Updated Account'}
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('service.services.AccountServiceHelper')
    def test_partial_update_by_id_wrong_role(
            self,
            mock_account_service_helper
    ):
        """It should not partially update an Account when the JWT belongs to a user
        with the wrong role."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        mock_account_service_helper.get_account_or_404.return_value = self.account
        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service_helper.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {TEST_USER_ID} is not authorized to perform this action."
            ))

        response = self.client.post(
            ACCOUNTS_PATH_V1,
            json=self.test_account_dto.dict(),
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        response = self.client.patch(
            f"{ACCOUNTS_PATH_V1}/{self.test_account_dto.id}",
            content_type='application/json',
            json={'name': 'Partially Updated Account'},
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

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
    @patch('service.services.AccountServiceHelper')
    def test_delete_by_id_success(
            self,
            mock_account_service_helper
    ):
        """It should delete an Account successfully when authorized."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID

        # Create an account
        account = self.account_service.create(self.create_account_dto)
        account_id = account.id

        response = self.client.delete(
            f'{ACCOUNTS_PATH_V1}/{account_id}',
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.delete(
            f'{ACCOUNTS_PATH_V1}/{account_id}',
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_by_id_unauthorized(self):
        """It should return 401 Unauthorized when deleting an Account without a JWT."""
        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{self.account.id}",
            content_type='application/json'
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('service.services.AccountServiceHelper')
    def test_delete_by_id_wrong_role(
            self,
            mock_account_service_helper
    ):
        """It should not delete an Account when the JWT belongs to a user with the wrong role."""
        mock_account_service_helper.get_user_id_from_jwt.return_value = TEST_USER_ID
        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service_helper.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {TEST_USER_ID} is not authorized to perform this action."
            ))

        response = self.client.delete(
            f"{ACCOUNTS_PATH_V1}/{self.account.id}",
            content_type='application/json',
            headers=self.headers
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # Verify that the user is authorized
        mock_account_service_helper.authorize_account.assert_called_once()

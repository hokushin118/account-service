"""
Account API Keycloak Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch, Mock

import requests
from cba_core_lib.utils import status
from cba_core_lib.utils.constants import (
    AUTHORIZATION_HEADER,
    BEARER_HEADER,
)
from cba_core_lib.utils.enums import UserRole
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, create_access_token

from service.common.keycloak_utils import (
    has_roles,
    KEYCLOAK_CLIENT_ID,
    REALM_ACCESS_CLAIM,
    ROLES_CLAIM,
    RESOURCE_ACCESS,
    INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE,
    KEYS,
    X5C_KID,
    JWT_KID,
    get_keycloak_certificate,
    get_keycloak_certificate_with_retry, has_roles_and
)
from tests.utils.constants import (
    TEST_PATH,
    TEST_USER,
    TEST_ROLE,
    TEST_OTHER_ROLE, JWT_SECRET_KEY
)

TEST_CERTIFICATE = 'test_certificate'
TEST_NO_JWT_PATH = '/test_no_jwt'


######################################################################
#  KEYCLOAK UTILS TEST CASES
######################################################################
class TestGetKeycloakCertificate(TestCase):
    """Tests for the get_keycloak_certificate function."""

    @patch('requests.get')
    def test_successful_retrieval(self, mock_get):
        """It should successfully retrieve the Keycloak certificate."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = status.HTTP_200_OK
        mock_response.json.return_value = {
            KEYS: [
                {
                    JWT_KID: 'test_kid',
                    'kty': 'RSA',
                    'n': 'some_n',
                    'e': 'some_e',
                }
            ]
        }
        mock_get.return_value = mock_response

        certificate = get_keycloak_certificate()
        self.assertIsNotNone(certificate)

    @patch('requests.get')
    def test_http_error(self, mock_get):
        """It should handle HTTP error during certificate retrieval."""
        # Mock HTTP error
        mock_get.side_effect = requests.exceptions.HTTPError('HTTP Error')

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)

    @patch('requests.get')
    def test_connection_error(self, mock_get):
        """It should handle connection error during certificate retrieval."""
        # Mock connection error
        mock_get.side_effect = requests.exceptions.ConnectionError(
            'Connection Error'
        )

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)

    @patch('requests.get')
    def test_timeout_error(self, mock_get):
        """It should handle timeout error during certificate retrieval."""
        # Mock timeout error
        mock_get.side_effect = requests.exceptions.Timeout('Timeout Error')

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)

    @patch('requests.get')
    def test_invalid_json(self, mock_get):
        """It should handle invalid JSON response from Keycloak."""
        # Mock invalid JSON response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_get.return_value = mock_response

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)

    @patch('requests.get')
    def test_empty_keys(self, mock_get):
        """It should handle empty 'keys' array in JWKS response."""
        # Mock empty keys array
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {KEYS: []}
        mock_get.return_value = mock_response

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)

    @patch('requests.get')
    def test_empty_x5c(self, mock_get):
        """It should handle empty 'x5c' list for a key in JWKS response."""
        # Mock empty x5c list
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            KEYS: [
                {
                    JWT_KID: 'test_kid',
                    X5C_KID: []
                }
            ]
        }
        mock_get.return_value = mock_response

        certificate = get_keycloak_certificate()
        self.assertIsNone(certificate)


class TestGetKeycloakCertificateWithRetry(TestCase):
    """Tests for the get_keycloak_certificate_with_retry function."""

    @patch('service.common.keycloak_utils.get_keycloak_certificate')
    @patch('time.sleep')
    def test_successful_retrieval_first_attempt(
            self,
            mock_sleep,
            mock_get_certificate
    ):
        """It should return the certificate on the first attempt if successful."""
        mock_get_certificate.return_value = TEST_CERTIFICATE

        certificate = get_keycloak_certificate_with_retry()
        self.assertEqual(certificate, TEST_CERTIFICATE)
        mock_sleep.assert_not_called()  # Ensure sleep is not called on first success

    @patch('service.common.keycloak_utils.get_keycloak_certificate')
    @patch('time.sleep')
    def test_successful_retrieval_after_retry(
            self,
            mock_sleep,
            mock_get_certificate
    ):
        """Should return the certificate after retrying if initially fails."""
        mock_get_certificate.side_effect = [None, TEST_CERTIFICATE]

        certificate = get_keycloak_certificate_with_retry()
        self.assertEqual(certificate, TEST_CERTIFICATE)
        mock_sleep.assert_called_once()  # Ensure sleep is called once

    @patch('service.common.keycloak_utils.get_keycloak_certificate')
    @patch('time.sleep')
    def test_max_retries_reached(self, mock_sleep, mock_get_certificate):
        """Should return None when max retries are reached."""
        mock_get_certificate.return_value = None

        certificate = get_keycloak_certificate_with_retry(max_retries=2)
        self.assertIsNone(certificate)
        self.assertEqual(
            mock_sleep.call_count,
            2
        )  # Ensure sleep is called max_retries times.

    @patch('service.common.keycloak_utils.get_keycloak_certificate')
    @patch('time.sleep')
    def test_indefinite_retries(self, mock_sleep, mock_get_certificate):
        """Should retry indefinitely if max_retries is None."""
        mock_get_certificate.side_effect = [None, None, TEST_CERTIFICATE]

        certificate = get_keycloak_certificate_with_retry()
        self.assertEqual(certificate, TEST_CERTIFICATE)
        self.assertEqual(
            mock_sleep.call_count,
            2
        )  # check sleep is called twice before success.

    @patch('service.common.keycloak_utils.get_keycloak_certificate')
    @patch('time.sleep')
    def test_no_retries_needed(self, mock_sleep, mock_get_certificate):
        """Should not retry if the certificate is retrieved immediately."""
        mock_get_certificate.return_value = TEST_CERTIFICATE

        certificate = get_keycloak_certificate_with_retry()
        self.assertEqual(certificate, TEST_CERTIFICATE)
        mock_sleep.assert_not_called()


class TestHasRolesDecorator(TestCase):
    """Tests for the has_roles function."""

    def setUp(self):
        """This runs before each test."""
        self.app = Flask(__name__)
        self.app.testing = True
        self.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        self.jwt = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route(TEST_PATH)
        @has_roles([TEST_ROLE, UserRole.USER.value])
        def test_route():
            """Test route with has_roles decorator."""
            return jsonify({'message': 'success'}), status.HTTP_200_OK

        @self.app.route(TEST_NO_JWT_PATH)
        @has_roles([TEST_ROLE])
        def test_route_no_jwt():
            """Test route without JWT token."""
            return jsonify({'message': 'success'}), status.HTTP_200_OK

    def test_has_required_role(self):
        """It should return 200 OK when user has the required role."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {
                            ROLES_CLAIM: [
                                TEST_ROLE]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK
            )
            self.assertEqual(response.json, {'message': 'success'})

    def test_missing_required_role(self):
        """It should return 403 Forbidden when user does not have the required role."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {
                            ROLES_CLAIM: [
                                TEST_OTHER_ROLE]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(response.status_code,
                             status.HTTP_403_FORBIDDEN)
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_resource_access(self):
        """It should return 403 Forbidden when resource_access claim is missing."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={}
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_client_id(self):
        """It should return 403 Forbidden when client ID is missing in resource_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        'other_client_id': {
                            ROLES_CLAIM: [
                                TEST_ROLE]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_roles_claim(self):
        """It should return 403 Forbidden when roles claim is missing in resource_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {}
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_no_jwt_token(self):
        """It should return 401 Unauthorized when no JWT token is provided."""
        response = self.client.get(TEST_NO_JWT_PATH)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED
        )

    def test_realm_access_fallback(self):
        """It should return 200 OK when user has the required role in realm_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    REALM_ACCESS_CLAIM: {
                        ROLES_CLAIM: [TEST_ROLE]
                    }
                }
            )
            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json, {'message': 'success'})


class TestHasRolesAndDecorator(TestCase):
    """Tests for the has_roles_and function."""

    def setUp(self):
        """This runs before each test."""
        self.app = Flask(__name__)
        self.app.testing = True
        self.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        self.jwt = JWTManager(self.app)
        self.client = self.app.test_client()

        @self.app.route(TEST_PATH, methods=['GET'])
        @has_roles_and([UserRole.USER.value, UserRole.ADMIN.value])
        def test_route():
            """Test route with has_roles decorator."""
            return jsonify({'message': 'success'}), status.HTTP_200_OK

        @self.app.route(TEST_NO_JWT_PATH, methods=['GET'])
        @has_roles_and([UserRole.USER.value, UserRole.ADMIN.value])
        def test_route_no_jwt():
            """Test route without JWT token."""
            return jsonify({'message': 'success'}), status.HTTP_200_OK

    def test_has_required_role(self):
        """It should return 200 OK when user has the required role."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {
                            ROLES_CLAIM: [
                                UserRole.USER.value,
                                UserRole.ADMIN.value
                            ]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_200_OK
            )
            self.assertEqual(response.json, {'message': 'success'})

    def test_missing_required_role(self):
        """It should return 403 Forbidden when user does not have the both required roles."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {
                            ROLES_CLAIM: [
                                UserRole.USER.value
                            ]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(response.status_code,
                             status.HTTP_403_FORBIDDEN)
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_resource_access(self):
        """It should return 403 Forbidden when resource_access claim is missing."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={}
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_client_id(self):
        """It should return 403 Forbidden when client ID is missing in resource_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        'other_client_id': {
                            ROLES_CLAIM: [
                                TEST_ROLE]
                        }
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_missing_roles_claim(self):
        """It should return 403 Forbidden when roles claim is missing in resource_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    RESOURCE_ACCESS: {
                        KEYCLOAK_CLIENT_ID: {}
                    }
                }
            )

            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(
                response.status_code,
                status.HTTP_403_FORBIDDEN
            )
            self.assertEqual(
                response.json,
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            )

    def test_no_jwt_token(self):
        """It should return 401 Unauthorized when no JWT token is provided."""
        response = self.client.get(TEST_NO_JWT_PATH)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED
        )

    def test_realm_access_fallback(self):
        """It should return 200 OK when user has the required roles in
        realm_access."""
        with self.app.test_request_context():
            access_token = create_access_token(
                identity=TEST_USER,
                additional_claims={
                    REALM_ACCESS_CLAIM: {
                        ROLES_CLAIM: [
                            UserRole.USER.value,
                            UserRole.ADMIN.value
                        ]
                    }
                }
            )
            headers = {AUTHORIZATION_HEADER: f'{BEARER_HEADER} {access_token}'}
            response = self.client.get(TEST_PATH, headers=headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json, {'message': 'success'})

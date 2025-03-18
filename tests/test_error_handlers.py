"""
Error Handlers Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import json
from unittest import TestCase

from flask import Flask, request
from werkzeug.exceptions import UnsupportedMediaType

from service.common import status
from service.common.error_handlers import register_error_handlers
from service.errors import (
    AccountError,
    AccountNotFoundError,
    AccountAuthorizationError
)
from service.models import DataValidationError
from tests.test_constants import TEST_ACCOUNT_ID, TEST_USER_ID


class RegisterErrorHandlersTests(TestCase):
    """The error handler Module Tests."""

    def setUp(self):
        self.app = Flask(__name__)
        self.app.testing = True
        # Disable exception propagation so error handlers can catch errors
        self.app.config['PROPAGATE_EXCEPTIONS'] = False

        register_error_handlers(self.app)

        # Define routes that trigger the various errors.
        @self.app.route('/test/data-validation')
        def data_validation_error():
            raise DataValidationError('Data validation error occurred')

        @self.app.route('/test/account-error')
        def account_error():
            raise AccountError('Account error occurred')

        @self.app.route('/test/account-not-found')
        def account_not_found_error():
            raise AccountNotFoundError(
                TEST_ACCOUNT_ID,
                'Account not found error occurred'
            )

        @self.app.route('/test/account-authorization')
        def account_authorization_error():
            raise AccountAuthorizationError(
                TEST_USER_ID,
                'Account authorization error occurred'
            )

        @self.app.route('/test/internal-server')
        def internal_server_error():
            # Any generic exception will be interpreted and handled as a 500
            raise Exception('Internal server error occurred')

        # For 405 Method Not Allowed, define a route that supports only GET.
        @self.app.route('/test/method-not-allowed', methods=['GET'])
        def method_not_allowed():
            return 'success', status.HTTP_200_OK

        # For 415 Unsupported Media Type, define a route that only accepts JSON.
        @self.app.route('/test/unsupported-media', methods=['POST'])
        def unsupported_media():
            if request.content_type != 'application/json':
                raise UnsupportedMediaType('Media type not supported')
            return 'success', status.HTTP_200_OK

        self.client = self.app.test_client()

    def tearDown(self):
        self.app = None

    def test_data_validation_error_handler(self):
        """It should return a 400 Bad Request JSON response when a DataValidationError is raised."""
        response = self.client.get('/test/data-validation')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = json.loads(response.get_data(as_text=True))
        # Expecting "Bad Request" as error description.
        self.assertEqual(data.get('status'), status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data.get('error'), 'Bad Request')
        self.assertIn('Data validation error occurred', data.get('message'))

    def test_account_error_handler(self):
        """It should return a 400 Bad Request JSON response when an AccountError is raised."""
        response = self.client.get('/test/account-error')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(data.get('status'), status.HTTP_400_BAD_REQUEST)
        self.assertEqual(data.get('error'), 'Bad Request')
        self.assertIn('Account error occurred', data.get('message'))

    def test_account_not_found_error_handler(self):
        """It should return a 404 Not Found JSON response when an AccountNotFoundError is raised."""
        response = self.client.get('/test/account-not-found')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(data.get('status'), status.HTTP_404_NOT_FOUND)
        self.assertEqual(data.get('error'), 'Not Found')
        self.assertIn('Account not found error occurred', data.get('message'))

    def test_account_authorization_error_handler(self):
        """It should return a 403 Forbidden JSON response when an AccountAuthorizationError
        is raised."""
        response = self.client.get('/test/account-authorization')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(data.get('status'), status.HTTP_403_FORBIDDEN)
        self.assertEqual(data.get('error'), 'Forbidden')
        self.assertIn(
            'Account authorization error occurred',
            data.get('message')
        )

    def test_internal_server_error_handler(self):
        """It should return a 500 Internal Server Error JSON response when an unexpected
        exception is raised."""
        response = self.client.get('/test/internal-server')
        self.assertEqual(
            response.status_code,
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(
            data.get('status'),
            status.HTTP_500_INTERNAL_SERVER_ERROR
        )
        self.assertEqual(data.get('error'), 'Internal Server Error')
        self.assertIn('Internal Server Error', data.get('message'))

    def test_method_not_allowed_error_handler(self):
        """It should return a 405 Method Not Allowed JSON response when an invalid method
         is used."""
        # The route /test/method-not-allowed only allows GET.
        response = self.client.post('/test/method-not-allowed')
        self.assertEqual(
            response.status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED
        )
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(
            data.get('status'),
            status.HTTP_405_METHOD_NOT_ALLOWED
        )
        self.assertEqual(data.get('error'), 'Method not Allowed')
        self.assertIn('Method Not Allowed', data.get('message'))

    def test_unsupported_media_type_error_handler(self):
        """It should return a 415 Unsupported Media Type JSON response when an unsupported media
        type is used."""
        # Call the endpoint with an unsupported content type.
        response = self.client.post(
            '/test/unsupported-media',
            data='test',
            content_type='text/plain'
        )
        self.assertEqual(
            response.status_code,
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )
        data = json.loads(response.get_data(as_text=True))
        self.assertEqual(
            data.get('status'),
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
        )
        self.assertEqual(data.get('error'), 'Unsupported media type')
        self.assertIn('Media type not supported', data.get('message'))

"""
Test Base Module.

This module defines a base test class for Flask-based tests by extending
Python’s built-in unittest.TestCase.
"""
import json
import logging
from unittest import TestCase

from cba_core_lib.utils import status
from cba_core_lib.utils.constants import (
    AUTHORIZATION_HEADER,
    BEARER_HEADER,
)
from cba_core_lib.utils.enums import UserRole
from cryptography.hazmat.primitives import serialization
from flask import Flask, Response
from jose import jwt

from service import (
    app_config,
    register_error_handlers,
    app
)
from service.common.keycloak_utils import (
    REALM_ACCESS_CLAIM,
    ROLES_CLAIM,
    KEYS
)
from service.models import Account, db
from service.schemas import CreateAccountDTO, AccountDTO
from tests import create_db_if_not_exists
from tests.utils.constants import (
    JWT_SECRET_KEY,
    TEST_ADMIN_USER_ID,
    TEST_USER_ID,
    TEST_PAGE,
    TEST_PER_PAGE,
    TEST_TOTAL
)
from tests.utils.factories import AccountFactory

JWT_ALGORITHM = 'RS256'
PRIVATE_KEY_PATH = './tests/utils/keys/private.pem'
PUBLIC_KEY_PATH = './tests/utils/keys/public.pem'

# Mock environment variables for testing
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['AUDIT_ENABLED'] = True
app.config['JWT_ALGORITHM'] = JWT_ALGORITHM
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = AUTHORIZATION_HEADER
app.config['JWT_HEADER_TYPE'] = BEARER_HEADER


# Dummy route functions for testing the decorator
def dummy_route_success():
    """A dummy route that returns a successful JSON response."""
    response_data = {'success': True}
    return Response(
        json.dumps(response_data),
        status=status.HTTP_200_OK,
        mimetype='application/json'
    )


def dummy_route_failure():
    """A dummy route that simulates failure by raising an exception."""
    raise Exception("Route failure occurred")


######################################################################
#  BASE CLASS FOR INTEGRATION TESTS
######################################################################
class BaseTestCase(TestCase):
    """A base test class for Flask-based tests that sets up the application context."""

    app = None

    @classmethod
    def setUpClass(cls):
        """This runs once before the entire test suite."""
        cls.app = Flask(__name__)
        cls.app.testing = True
        cls.app.config['TESTING'] = True
        cls.app.config['DEBUG'] = False
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = app_config.database_uri
        cls.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        cls.app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
        cls.app.logger.setLevel(logging.CRITICAL)

        # Disable exception propagation so error handlers can catch errors
        cls.app.config['PROPAGATE_EXCEPTIONS'] = False
        register_error_handlers(cls.app)

        cls.app.app_context().push()

        if app_config.database_uri:
            cls.engine = create_db_if_not_exists(app_config.database_uri)
            if cls.engine:
                cls.app.logger.info('Database connection successful.')
            else:
                cls.app.logger.error('Failed to connect to database.')
        else:
            cls.app.logger.error('Database URI not set')

        Account.init_db(cls.app)
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        """This runs once after the entire test suite."""
        db.session.close()
        db.drop_all()

    def setUp(self):
        super().setUp()

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

        self.create_account_dto = CreateAccountDTO(**self.account_data)

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
        self.jwt_token = jwt.encode(
            {
                'sub': TEST_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [UserRole.USER.value]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )
        self.headers = {
            AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.jwt_token}"
        }

        # Generate a test JWT for admin user using RS256
        self.jwt_token_admin = jwt.encode(
            {
                'sub': TEST_ADMIN_USER_ID,
                REALM_ACCESS_CLAIM: {ROLES_CLAIM: [UserRole.ADMIN.value]}
            },
            self.private_key,
            algorithm=JWT_ALGORITHM,
            headers={'kid': 'test-kid'}
        )

        self.headers_admin = {
            AUTHORIZATION_HEADER: f"{BEARER_HEADER} {self.jwt_token_admin}"
        }

    def tearDown(self):
        # Clear database before each test
        db.session.rollback()
        db.session.query(Account).delete()
        db.session.commit()

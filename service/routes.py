"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime
import os
from typing import Dict, Tuple, Any, List
from uuid import UUID

import redis
from flasgger import swag_from
# pylint: disable=unused-import
from flask import jsonify, request, make_response, abort, url_for  # noqa; F401
from flask_jwt_extended import jwt_required, get_jwt_identity

from service import (
    app,
    cache,
    VERSION,
    NAME,
    CACHE_REDIS_HOST,
    CACHE_REDIS_PORT,
    CACHE_REDIS_DB
)
from service.common import status
from service.common.constants import ROLE_USER, ROLE_ADMIN, ACCOUNTS_CACHE_KEY
from service.common.keycloak_utils import has_roles, get_user_roles
from service.common.utils import (
    check_content_type,
    generate_etag_hash,
    count_requests
)
from service.models import Account
from service.schemas import AccountDTO

FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE = 'You are not authorized to update this resource.'
ACCOUNT_NOT_FOUND_MESSAGE = "Account with id [{account_id}] could not be found."
IF_NONE_MATCH_HEADER = 'If-None-Match'
CACHE_CONTROL_HEADER = 'Cache-Control'
ROOT_PATH = '/api'
HEALTH_PATH = f"{ROOT_PATH}/health"
INFO_PATH = f"{ROOT_PATH}/info"
ACCOUNTS_PATH_V1 = f"{ROOT_PATH}/v1/accounts"
CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 3600))

# Initialize Redis client
redis_client = redis.Redis(
    host=CACHE_REDIS_HOST,
    port=CACHE_REDIS_PORT,
    db=CACHE_REDIS_DB
)


######################################################################
# HELPER METHODS
######################################################################
def get_account_or_404(account_id: UUID) -> Account:
    """Helper function to find an account or return a 404 error.

        Args:
            account_id: The UUID of the account to check.

        Returns:
            Found user profile.
    """
    account = Account.find(account_id)
    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            ACCOUNT_NOT_FOUND_MESSAGE.format(account_id=account_id)
        )
    return account


def check_if_user_is_owner(user: str, account_id: UUID) -> bool:
    """Checks if the logged-in user is the owner of the specified account.

    Args:
        user: The username of the logged-in user.
        account_id: The UUID of the account to check.

    Returns:
        True if the user is the owner, False otherwise.
    """
    users = Account.find_by_name(user)
    return bool(users and str(users[0].id) == str(account_id))


######################################################################
# GET INDEX
######################################################################
@swag_from({
    'operationId': 'getIndex',
    'tags': ['General'],
    'summary': 'Returns a welcome message for the Account API',
    'description': 'Provides a basic welcome message for the Account API.',
    'responses': {
        200: {'description': 'OK'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(ROOT_PATH, methods=['GET'])
@count_requests
def index() -> Tuple[Dict[str, Any], int]:
    """Returns a welcome message for the Account API"""
    return jsonify(
        {'message': 'Welcome to the Account API!'}
    ), status.HTTP_200_OK


############################################################
# GET HEALTH
############################################################
@swag_from({
    'operationId': 'getHealth',
    'tags': ['General'],
    'summary': 'Returns the health status of the service',
    'description': 'Checks the overall health of the service. Currently, '
                   'it always returns a 200 OK status with a "status: UP" message.',
    'responses': {
        200: {'description': 'OK',
              'content': {
                  'application/json': {
                      'schema': {
                          '$ref': '#/components/schemas/HealthDTO'}
                  }
              }
              },
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(HEALTH_PATH, methods=['GET'])
@count_requests
def health() -> Tuple[Dict[str, Any], int]:
    """Returns the health status of the service"""
    return jsonify({'status': 'UP'}), status.HTTP_200_OK


############################################################
# GET INFO
############################################################
@swag_from({
    'operationId': 'getInfo',
    'tags': ['General'],
    'summary': 'Returns information about the service',
    'description': 'Provides information about the service, including its '
                   'name, version, and uptime.',
    'responses': {
        200: {'description': 'OK'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(INFO_PATH, methods=['GET'])
@count_requests
def info() -> Tuple[Dict[str, Any], int]:
    """Returns information about the service"""
    uptime = 'Not yet started'
    if hasattr(app, 'start_time'):
        uptime = str(datetime.datetime.now() - app.start_time)

    info_data = {
        'name': NAME,
        'version': VERSION,
        'uptime': uptime,
    }
    return jsonify(info_data), status.HTTP_200_OK


######################################################################
# CREATE A NEW ACCOUNT
######################################################################
@swag_from({
    'operationId': 'createAccountV1',
    'tags': ['Accounts V1'],
    'summary': 'Create a New Account',
    'description': 'Creates a new account based on the provided JSON data.',
    'security': [{"bearerAuth": []}],
    'requestBody': {
        'content': {
            'application/json': {
                'schema': {
                    '$ref': '#/components/schemas/CreateUpdateAccountDTO'}
            }
        }
    },
    'responses': {
        201: {
            'description': 'Created',
            'content': {
                'application/json': {
                    'schema': {'$ref': '#/components/schemas/AccountDTO'}
                }
            },
            'headers': {
                'Location': {
                    'type': 'string',
                    'description': 'URL of the newly created account'
                }
            }
        },
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For UnsupportedMediaType
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(ACCOUNTS_PATH_V1, methods=['POST'])
@count_requests
def create() -> Tuple[Dict[str, Any], int, Dict[str, str]]:
    """Create a New Account"""
    app.logger.info('Request to create an Account...')

    check_content_type('application/json')

    account = Account()
    account.deserialize(request.get_json())
    account.create()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)
    message = account_dto.dict()

    location_url = url_for(
        'find_by_id',
        account_id=account.id,
        _external=True
    )

    # Invalidate specific cache key(s)
    cache.delete(ACCOUNTS_CACHE_KEY)  # Invalidate the list
    app.logger.debug("Cache key %s invalidated.", ACCOUNTS_CACHE_KEY)

    return make_response(
        jsonify(message), status.HTTP_201_CREATED, {'Location': location_url}
    )


######################################################################
# LIST ALL ACCOUNTS
######################################################################
@swag_from({
    'operationId': 'getAccountsV1',
    'tags': ['Accounts V1'],
    'summary': 'Lists all Accounts',
    'description': 'Retrieves a list of all Account objects from the '
                   'database and returns them as a JSON array.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{"bearerAuth": []}],
    'responses': {
        200: {'description': 'OK',
              'content': {
                  'application/json': {
                      'schema': {
                          '$ref': '#/components/schemas/ListOfAccountDTO'}
                  }
              }
              },
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For unauthorized requests
        401: {'description': 'Unauthorized'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(ACCOUNTS_PATH_V1, methods=['GET'])
@jwt_required()
@count_requests
def list_accounts() -> Tuple[List[Dict[str, Any]], int]:
    """Lists all Accounts."""
    app.logger.info('Request to list Accounts')

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    # Attempt to retrieve cached data
    cached_data = cache.get(ACCOUNTS_CACHE_KEY)

    if cached_data:
        app.logger.debug('Retrieving Accounts from cache')
        account_list, etag_hash = cached_data
    else:
        app.logger.debug('Fetching Accounts from database')
        accounts = Account.all()
        account_list = [
            AccountDTO.from_orm(account).dict() for account in accounts
        ]
        # 1. Generate the ETag:
        etag_hash = generate_etag_hash(account_list)
        cache.set(
            ACCOUNTS_CACHE_KEY, (account_list, etag_hash),
            timeout=CACHE_DEFAULT_TIMEOUT
        )

    app.logger.debug("Returning %d accounts", len(account_list))

    if account_list:
        app.logger.debug(
            f"Accounts returned: {account_list}"
        )

    # 2. Check If-None-Match:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # 3. Create the response with the ETag:
    response = make_response(jsonify(account_list), status.HTTP_200_OK)
    response.headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
    response.set_etag(etag_hash)  # Set the ETag header
    return response


######################################################################
# READ AN ACCOUNT
######################################################################
@swag_from({
    'operationId': 'getAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Retrieve Account by ID',
    'description': 'Retrieves an account based on its unique identifier.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{"bearerAuth": []}],
    'responses': {
        200: {'description': 'OK',
              'content': {
                  'application/json': {
                      'schema': {'$ref': '#/components/schemas/AccountDTO'}
                  }
              }
              },
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For unauthorized requests
        401: {'description': 'Unauthorized'},
        # Account not found
        404: {'description': 'Not Found'},
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    },
    'parameters': [
        {
            'in': 'path',
            'name': 'account_id',
            'type': 'string',
            'format': 'uuid',
            'required': True,
            'description': 'ID of the account to retrieve',
            'example': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274'
        }
    ]
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['GET'])
@jwt_required()
@count_requests
def find_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Retrieve Account by ID."""
    app.logger.info("Request to read an Account with id: %s", account_id)

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    account = get_account_or_404(account_id)

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)
    data = account_dto.dict()

    app.logger.debug(f"Account returned: {data}")

    # 1. Generate the ETag:
    etag_hash = generate_etag_hash(data)

    # 2. Check for If-None-Match header:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # 3. Create the response with the ETag:
    response = make_response(jsonify(data), status.HTTP_200_OK)
    response.headers[CACHE_CONTROL_HEADER] = 'public, max-age=3600'
    response.set_etag(etag_hash)  # Set the ETag header
    return response


######################################################################
# UPDATE AN EXISTING ACCOUNT
######################################################################
@swag_from({
    'operationId': 'updateAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Update Account by ID',
    'description': 'Updates an existing account with the provided JSON data.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{"bearerAuth": []}],
    'parameters': [
        {
            'in': 'path',
            'name': 'account_id',
            'type': 'string',
            'format': 'uuid',
            'required': True,
            'description': 'ID of the account to update',
            'example': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274'
        }
    ],
    'requestBody': {
        'content': {
            'application/json': {
                'schema': {
                    '$ref': '#/components/schemas/CreateUpdateAccountDTO'}
            }
        }
    },
    'responses': {
        200: {'description': 'OK',
              'content': {
                  'application/json': {
                      'schema': {'$ref': '#/components/schemas/AccountDTO'}
                  }
              }
              },
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For unauthorized requests
        401: {'description': 'Unauthorized'},
        403: {'description': 'Forbidden'},
        # 404 Not Found
        404: {'description': 'Not Found'},
        # For UnsupportedMediaType
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['PUT'])
@has_roles([ROLE_USER, ROLE_ADMIN])
@count_requests
def update_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Update Account by ID."""
    app.logger.info("Request to update an Account with id: %s", account_id)

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    roles = get_user_roles()

    app.logger.debug('Roles: %s', roles)

    if ROLE_ADMIN not in roles:
        # If not ROLE_ADMIN, check ownership шf admin, then skip ownership check.
        # Check if the logged-in user is the owner of the resource
        if not check_if_user_is_owner(current_user, account_id):
            abort(
                status.HTTP_403_FORBIDDEN,
                FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE
            )

    account = get_account_or_404(account_id)
    account.deserialize(request.get_json())
    account.update()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)

    # Invalidate specific cache key
    cache.delete(ACCOUNTS_CACHE_KEY)  # Invalidate the list
    app.logger.debug("Cache key %s invalidated.", ACCOUNTS_CACHE_KEY)

    return account_dto.dict(), status.HTTP_200_OK


######################################################################
# PARTIAL UPDATE AN EXISTING ACCOUNT
######################################################################
@swag_from({
    'operationId': 'partialUpdateAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Partial Update Account by ID',
    'description': 'Partially updates an existing account with the provided JSON data.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{"bearerAuth": []}],
    'parameters': [
        {
            'in': 'path',
            'name': 'account_id',
            'type': 'string',
            'format': 'uuid',
            'required': True,
            'description': 'ID of the account to update',
            'example': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274'
        }
    ],
    'requestBody': {
        'content': {
            'application/json': {
                'schema': {
                    '$ref': '#/components/schemas/CreateUpdateAccountDTO'}
            }
        }
    },
    'responses': {
        200: {'description': 'OK',
              'content': {
                  'application/json': {
                      'schema': {'$ref': '#/components/schemas/AccountDTO'}
                  }
              }
              },
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For unauthorized requests
        401: {'description': 'Unauthorized'},
        403: {'description': 'Forbidden'},
        # 404 Not Found
        404: {'description': 'Not Found'},
        # For UnsupportedMediaType
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['PATCH'])
@has_roles([ROLE_USER, ROLE_ADMIN])
@count_requests
def partial_update_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Partial Update Account by ID."""
    app.logger.info(
        "Request to partially update an Account with id: %s",
        account_id
    )

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    roles = get_user_roles()

    app.logger.debug('Roles: %s', roles)

    if ROLE_ADMIN not in roles:
        # If not ROLE_ADMIN, check ownership шf admin, then skip ownership check.
        # Check if the logged-in user is the owner of the resource
        if not check_if_user_is_owner(current_user, account_id):
            abort(
                status.HTTP_403_FORBIDDEN,
                FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE
            )

    account = get_account_or_404(account_id)
    data = request.get_json()

    if not data:
        abort(
            status.HTTP_400_BAD_REQUEST,
            'No data provided for update'
        )

    account.partial_update(data)
    account.update()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)

    # Invalidate specific cache key
    cache.delete(ACCOUNTS_CACHE_KEY)  # Invalidate the list
    app.logger.debug("Cache key %s invalidated.", ACCOUNTS_CACHE_KEY)

    return account_dto.dict(), status.HTTP_200_OK


######################################################################
# DELETE AN ACCOUNT
######################################################################
@swag_from({
    'operationId': 'deleteAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Delete Account by ID',
    'description': 'Deletes an account based on its unique identifier.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{"bearerAuth": []}],
    'parameters': [
        {
            'in': 'path',
            'name': 'account_id',
            'type': 'string',
            'format': 'uuid',
            'required': True,
            'description': 'ID of the account to delete',
            'example': '51cb6dfd-c8fc-4ef0-b35c-8c76a216d274'
        }
    ],
    'responses': {
        204: {'description': 'No Content'},
        # For DataValidationError/IntegrityError
        400: {'description': 'Bad Request'},
        # For unauthorized requests
        401: {'description': 'Unauthorized'},
        403: {'description': 'Forbidden'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['DELETE'])
@has_roles([ROLE_USER, ROLE_ADMIN])
@count_requests
def delete_by_id(account_id: UUID) -> Tuple[str, int]:
    """Delete Account By ID."""
    app.logger.info(
        "Request to delete an Account with id: %s", account_id
    )

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    roles = get_user_roles()

    app.logger.debug('Roles: %s', roles)

    if ROLE_ADMIN not in roles:
        # If not ROLE_ADMIN, check ownership шf admin, then skip ownership check.
        # Check if the logged-in user is the owner of the resource
        if not check_if_user_is_owner(current_user, account_id):
            abort(
                status.HTTP_403_FORBIDDEN,
                FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE
            )

    account = Account.find(account_id)

    if account:
        account.delete()
        # Invalidate specific cache key
        cache.delete(ACCOUNTS_CACHE_KEY)  # Invalidate the list
        app.logger.debug("Cache key %s invalidated.", ACCOUNTS_CACHE_KEY)

    return "", status.HTTP_204_NO_CONTENT

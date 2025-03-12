"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime
import logging
import os
from typing import Dict, Tuple, Any, Callable
from uuid import UUID

import redis  # pylint: disable=E0401
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
from service.common.constants import (
    ROLE_USER, ROLE_ADMIN,
    ACCOUNT_CACHE_KEY
)
from service.common.keycloak_utils import has_roles, get_user_roles
from service.common.utils import (
    check_content_type,
    generate_etag_hash,
    count_requests
)
from service.models import Account
from service.schemas import AccountDTO

logger = logging.getLogger(__name__)

FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE = 'You are not authorized to update this resource.'
ACCOUNT_NOT_FOUND_MESSAGE = "Account with id [{account_id}] could not be found."
IF_NONE_MATCH_HEADER = 'If-None-Match'
CACHE_CONTROL_HEADER = 'Cache-Control'
ROOT_PATH = '/api'
HEALTH_PATH = f"{ROOT_PATH}/health"
INFO_PATH = f"{ROOT_PATH}/info"
ACCOUNTS_PATH_V1 = f"{ROOT_PATH}/v1/accounts"
CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 3600))
# Enable audit logging if AUDIT_ENABLED is set to "true"
AUDIT_ENABLED = os.environ.get(
    'AUDIT_ENABLED', 'False'
).lower() == 'true'

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


def invalidate_all_account_pages() -> None:
    """Invalidates all cached paginated account results."""
    app.logger.debug('Invalidated cache...')
    cache.clear()


def audit_log(function: Callable) -> Callable:
    """
    Conditionally apply Kafka-based audit logging to a function based on the audit configuration.

    If audit logging is enabled (i.e., AUDIT_ENABLED is True), this function dynamically imports
    and applies the audit_log_kafka decorator to the provided function. Otherwise, it simply returns
    the original function unmodified.

    Args:
        function (Callable): The function to be decorated with audit logging.

    Returns:
        Callable: The decorated function with Kafka-based audit logging if enabled,
                  otherwise the original function.

    Usage:
        @audit_log
        def my_route():
           ...
    """
    if AUDIT_ENABLED:
        # pylint:disable=C0415
        from service.common.audit_utils import audit_log_kafka
        logger.debug("Auditing Kafka log for %s", function.__name__)
        return audit_log_kafka(function)
    # Skip audit logging if audit is not enabled
    return function


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
    invalidate_all_account_pages()
    app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

    return make_response(
        jsonify(message), status.HTTP_201_CREATED, {'Location': location_url}
    )


######################################################################
# LIST ALL ACCOUNTS
######################################################################
@swag_from({
    'operationId': 'getAccountsV1',
    'tags': ['Accounts V1'],
    'summary': 'Lists all Accounts (paginated)',
    'description': 'Retrieves a paginated list of Account objects from the '
                   'database and returns them as a JSON array.</br></br>'
                   'Only authenticated users can access this endpoint.</br></br>'
                   'Query parameters `page` and `per_page` are used for pagination.',
    'security': [{'bearerAuth': []}],
    'parameters': [
        {
            'name': 'page',
            'in': 'query',
            'description': 'Page number',
            'schema': {'type': 'integer'},
            'default': 1
        },
        {
            'name': 'per_page',
            'in': 'query',
            'description': 'Items per page',
            'schema': {'type': 'integer'},
            'default': 10
        }
    ],
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
@audit_log
@count_requests
def list_accounts() -> Tuple[Dict[str, Any], int]:
    """Lists all Accounts."""
    app.logger.info('Request to list Accounts')

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # Cache key for paginated results (include page and per_page)
    cache_key = f"{ACCOUNT_CACHE_KEY}:{page}:{per_page}"

    # Attempt to retrieve cached data
    cached_data = cache.get(cache_key)

    if cached_data:
        app.logger.debug('Retrieving Accounts (page %d) from cache.', page)
        paginated_data, etag_hash = cached_data
    else:
        app.logger.debug('Fetching Accounts (page %d) from database.', page)

        accounts = Account.all_paginated(page=page, per_page=per_page)
        account_list = [
            AccountDTO.from_orm(account).dict() for account in accounts
        ]

        total_accounts = Account.query.count()

        # Paginate the results
        paginated_data = {
            'items': account_list,
            'page': page,
            'per_page': per_page,
            'total': total_accounts
        }

        # 1. Generate the ETag:
        etag_hash = generate_etag_hash(paginated_data)
        cache.set(
            cache_key, (paginated_data, etag_hash),
            timeout=CACHE_DEFAULT_TIMEOUT
        )

    if paginated_data['items']:
        app.logger.debug(
            "Returning %d accounts (page %d)",
            len(paginated_data['items']),
            page
        )

    # 2. Check If-None-Match:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # 3. Create the response with the ETag:
    response = make_response(jsonify(paginated_data), status.HTTP_200_OK)
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
@audit_log
@count_requests
def find_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Retrieve Account by ID."""
    app.logger.info("Request to read an Account with id: %s", account_id)

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    cache_key = f"{ACCOUNT_CACHE_KEY}:{account_id}"

    # Attempt to retrieve cached data
    cached_data = cache.get(cache_key)

    if cached_data:
        app.logger.debug('Retrieving Account from cache...')
        data, etag_hash = cached_data
    else:
        app.logger.debug('Fetching Account from database...')
        account = get_account_or_404(account_id)

        # Convert SQLAlchemy model to DTO
        account_dto = AccountDTO.from_orm(account)
        data = account_dto.dict()

        # 1. Generate the ETag:
        etag_hash = generate_etag_hash(data)

        # Cache the data
        try:
            cache.set(
                cache_key,
                (data, etag_hash),
                timeout=CACHE_DEFAULT_TIMEOUT
            )
        except TypeError as type_err:
            app.logger.error(
                "Failed to cache account due to type error: %s",
                type_err
            )
        except ValueError as value_err:
            app.logger.error(
                "Failed to cache account due to value error: %s",
                value_err
            )
        except AttributeError as attr_err:
            app.logger.error(
                "Failed to cache account due to attribute error: %s",
                attr_err
            )
        except Exception as err:  # pylint: disable=W0703
            app.logger.error("Failed to cache account: %s", err)

    app.logger.debug(f"Account returned: {data}")

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
@audit_log
@count_requests
def update_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Update Account by ID."""
    app.logger.info("Request to update an Account with id: %s", account_id)

    # Get the user identity from the JWT token
    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    # Retrieve user roles
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

    # Retrieve the account to be updated or return a 404 error if not found
    account = get_account_or_404(account_id)

    # Update account with provided JSON payload
    account.deserialize(request.get_json())
    account.update()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)

    # Invalidate specific cache key(s)
    invalidate_all_account_pages()
    app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

    # Return the updated account DTO as a JSON response with a 200 status code
    return make_response(jsonify(account_dto.dict()), status.HTTP_200_OK)


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
@audit_log
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

    # Retrieve user roles
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

    # Retrieve the account to be updated or return a 404 error if not found
    account = get_account_or_404(account_id)

    # Get the data payload from the request
    data = request.get_json()
    if not data:
        abort(
            status.HTTP_400_BAD_REQUEST,
            'No data provided for update'
        )

    # Partially update account with provided JSON payload
    account.partial_update(data)
    account.update()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)

    # Invalidate specific cache key(s)
    invalidate_all_account_pages()
    app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

    # Return the updated account DTO as a JSON response with a 200 status code
    return make_response(jsonify(account_dto.dict()), status.HTTP_200_OK)


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
        # Invalidate specific cache key(s)
        invalidate_all_account_pages()
        app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

    return "", status.HTTP_204_NO_CONTENT

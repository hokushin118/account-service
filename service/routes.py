"""
Account Routes.

This microservice handles the lifecycle of Accounts
"""
import datetime
import logging
from typing import Callable
from uuid import UUID

from flasgger import swag_from
# pylint: disable=unused-import
from flask import (
    Response,
    jsonify,
    request,
    make_response,
    abort,
    url_for
)  # noqa; F401
from flask_jwt_extended import jwt_required

from service import (
    app,
    VERSION,
    NAME,
    metrics, get_bool_from_env
)
from service.common import status
from service.common.constants import (
    ROLE_USER,
    ROLE_ADMIN
)
from service.common.keycloak_utils import has_roles
from service.common.utils import (
    check_content_type,
    count_requests
)
from service.schemas import (
    UpdateAccountDTO,
    PartialUpdateAccountDTO,
    CreateAccountDTO
)
from service.services import AccountService

logger = logging.getLogger(__name__)

JSON_INDENT = 4
IF_NONE_MATCH_HEADER = 'If-None-Match'
CACHE_CONTROL_HEADER = 'Cache-Control'
ROOT_PATH = '/api'
HEALTH_PATH = f"{ROOT_PATH}/health"
INFO_PATH = f"{ROOT_PATH}/info"
ACCOUNTS_PATH_V1 = f"{ROOT_PATH}/v1/accounts"
# Enable audit logging if AUDIT_ENABLED is set to "true"
AUDIT_ENABLED = get_bool_from_env('AUDIT_ENABLED', False)

# Initialize the AccountService
account_service = AccountService()


######################################################################
# HELPER METHODS
######################################################################
def audit_log(function: Callable) -> Callable:
    """Conditionally apply Kafka-based audit logging to a function based on the audit configuration.

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
        logger.info('Audit is enabled.')
        logger.debug("Auditing Kafka log for %s", function.__name__)
        return audit_log_kafka(function)
    # Skip audit logging if audit is not enabled
    logger.info('Audit is disabled.')
    return function


######################################################################
# GET INDEX
######################################################################
@swag_from({
    'operationId': 'getIndex',
    'tags': ['General'],
    'summary': 'Returns a welcome message for the Account API',
    'description': 'Provides a basic welcome message for the Account API.</br></br>'
                   'This endpoint is accessible to anonymous users.',
    'responses': {
        200: {'description': 'OK'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(ROOT_PATH, methods=['GET'])
@metrics.do_not_track()
def index() -> Response:
    """Returns a welcome message for the Account API"""
    return make_response(
        jsonify(
            {'message': 'Welcome to the Account API!'}
        ), status.HTTP_200_OK
    )


############################################################
# GET HEALTH
############################################################
@swag_from({
    'operationId': 'getHealth',
    'tags': ['General'],
    'summary': 'Returns the health status of the service',
    'description': 'Checks the overall health of the service. Currently, '
                   'it always returns a 200 OK status with a "status: UP" message.</br></br>'
                   'This endpoint is accessible to anonymous users.',
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
@metrics.do_not_track()
def health() -> Response:
    """Returns the health status of the service"""
    return make_response(jsonify({'status': 'UP'}), status.HTTP_200_OK)


############################################################
# GET INFO
############################################################
@swag_from({
    'operationId': 'getInfo',
    'tags': ['General'],
    'summary': 'Returns information about the service',
    'description': 'Provides information about the service, including its '
                   'name, version, and uptime.</br></br>'
                   'This endpoint is accessible to anonymous users.',
    'responses': {
        200: {'description': 'OK'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(INFO_PATH, methods=['GET'])
@metrics.do_not_track()
def info() -> Response:
    """Returns information about the service"""
    uptime = 'Not yet started'
    if hasattr(app, 'start_time'):
        uptime = str(datetime.datetime.now() - app.start_time)

    info_data = {
        'name': NAME,
        'version': VERSION,
        'uptime': uptime,
    }
    return make_response(jsonify(info_data), status.HTTP_200_OK)


######################################################################
# CREATE A NEW ACCOUNT
######################################################################
@swag_from({
    'operationId': 'createAccountV1',
    'tags': ['Accounts V1'],
    'summary': 'Create a New Account',
    'description': 'Creates a new account based on the provided JSON data.</br></br>'
                   'Only authenticated users can access this endpoint.',
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
    'requestBody': {
        'content': {
            'application/json': {
                'schema': {
                    '$ref': '#/components/schemas/CreateAccountDTO'}
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
@jwt_required()
@audit_log
@count_requests
def create() -> Response:
    """Create a New Account"""
    app.logger.info('Request to create an Account...')

    check_content_type('application/json')

    # Get the data payload from the request
    data = request.get_json()
    if not data:
        app.logger.warning(
            "No data provided to create an account..."
        )
        abort(
            status.HTTP_400_BAD_REQUEST,
            'No data provided for create.'
        )

    create_account_dto = CreateAccountDTO(**data)

    # Create account with provided JSON payload
    account_dto = account_service.create(create_account_dto)
    json_data = account_dto.model_dump_json(
        exclude_none=True,
        indent=JSON_INDENT
    )

    location_url = url_for(
        'find_by_id',
        account_id=account_dto.id,
        _external=True
    )

    return make_response(
        json_data, status.HTTP_201_CREATED, {'Location': location_url}
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
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
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
def list_accounts() -> Response:
    """Lists all Accounts."""
    app.logger.info('Request to list Accounts')

    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)

    # Retrieve account data and ETag.
    account_paginated_list_dto, etag_hash = account_service.list_accounts(
        page,
        per_page
    )
    json_data = account_paginated_list_dto.model_dump_json(
        exclude_none=True,
        indent=JSON_INDENT
    )

    # Check If-None-Match:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # Create the response with the ETag:
    response = make_response(json_data, status.HTTP_200_OK)
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
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
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
def find_by_id(account_id: UUID) -> Response:
    """Retrieve Account by ID."""
    app.logger.info("Request to read an Account with id: %s", account_id)

    # Retrieve account data and ETag.
    account_dto, etag_hash = account_service.get_account_by_id(account_id)
    json_data = account_dto.model_dump_json(
        exclude_none=True,
        indent=JSON_INDENT
    )

    # Check for If-None-Match header:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # Create the response with the ETag:
    response = make_response(json_data, status.HTTP_200_OK)
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
                   'Only authenticated users can access this endpoint.</br></br>'
                   'A user with the role **ROLE_USER** can update only their own account.</br>'
                   'A user with the role **ROLE_ADMIN** can update any account.',
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
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
                    '$ref': '#/components/schemas/UpdateAccountDTO'}
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
def update_by_id(account_id: UUID) -> Response:
    """Update Account by ID."""
    app.logger.info("Request to update an Account with id: %s", account_id)

    # Get the data payload from the request
    data = request.get_json()
    if not data:
        app.logger.warning(
            "No data provided for update of account %s.",
            account_id
        )
        abort(
            status.HTTP_400_BAD_REQUEST,
            'No data provided for update.'
        )

    update_account_dto = UpdateAccountDTO(**data)

    # Update account with provided JSON payload
    account_dto = account_service.update_by_id(
        account_id,
        update_account_dto
    )
    json_data = account_dto.model_dump_json(
        exclude_none=True,
        indent=JSON_INDENT
    )

    # Return the updated account DTO as a JSON response with a 200 status code
    return make_response(json_data, status.HTTP_200_OK)


######################################################################
# PARTIAL UPDATE AN EXISTING ACCOUNT
######################################################################
@swag_from({
    'operationId': 'partialUpdateAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Partial Update Account by ID',
    'description': 'Partially updates an existing account with the provided JSON data.</br></br>'
                   'Only authenticated users can access this endpoint.</br></br>'
                   'A user with the role **ROLE_USER** can update only their own account.</br>'
                   'A user with the role **ROLE_ADMIN** can update any account.',
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
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
                    '$ref': '#/components/schemas/PartialUpdateAccountDTO'}
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
def partial_update_by_id(account_id: UUID) -> Response:
    """Partial Update Account by ID."""
    app.logger.info(
        "Request to partially update an Account with id: %s",
        account_id
    )

    # Get the data payload from the request
    data = request.get_json()
    if not data:
        app.logger.warning(
            "No data provided for update of account %s.",
            account_id
        )
        abort(
            status.HTTP_400_BAD_REQUEST,
            'No data provided for update.'
        )

    partial_update_account_dto = PartialUpdateAccountDTO(**data)

    # Partially update account with provided JSON payload
    account_dto = account_service.partial_update_by_id(
        account_id,
        partial_update_account_dto
    )
    json_data = account_dto.model_dump_json(
        exclude_none=True,
        indent=JSON_INDENT
    )

    # Return the updated account DTO as a JSON response with a 200 status code
    return make_response(json_data, status.HTTP_200_OK)


######################################################################
# DELETE AN ACCOUNT
######################################################################
@swag_from({
    'operationId': 'deleteAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Delete Account by ID',
    'description': 'Deletes an account based on its unique identifier.</br></br>'
                   'Only authenticated users can access this endpoint.</br></br>'
                   'A user with the role **ROLE_USER** can delete only their own account.</br>'
                   'A user with the role **ROLE_ADMIN** can delete any account.',
    'security': [{'oauth2': ['openid', 'profile', 'email']}],
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
@audit_log
@count_requests
def delete_by_id(account_id: UUID) -> Response:
    """Delete Account By ID."""
    app.logger.info(
        "Request to delete an Account with id: %s", account_id
    )

    # Delete the account
    account_service.delete_by_id(account_id)

    # Return the empty body with a 204 status code
    return make_response('', status.HTTP_204_NO_CONTENT)

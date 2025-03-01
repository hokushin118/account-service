"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime
from typing import Dict, Tuple, Any, List
from uuid import UUID

from flasgger import swag_from
# pylint: disable=unused-import
from flask import jsonify, request, make_response, abort, url_for  # noqa; F401
from flask_jwt_extended import jwt_required, get_jwt_identity

from service import app, VERSION, NAME
from service.common import status
from service.common.utils import check_content_type, generate_etag_hash, \
    count_requests
from service.models import Account
from service.schemas import AccountDTO

IF_NONE_MATCH_HEADER = 'If-None-Match'

ROOT_PATH = '/api'
HEALTH_PATH = f"{ROOT_PATH}/health"
INFO_PATH = f"{ROOT_PATH}/info"
ACCOUNTS_PATH_V1 = f"{ROOT_PATH}/v1/accounts"


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
                   'database and returns them as a JSON array.',
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
    """Lists all Accounts"""
    app.logger.info('Request to list Accounts')

    current_user = get_jwt_identity()
    app.logger.debug('Current user: %s', current_user)

    accounts = Account.all()
    account_list = [
        AccountDTO.from_orm(account).dict() for account in
        accounts
    ]

    app.logger.info("Returning %d accounts", len(account_list))

    if account_list:
        app.logger.debug(
            f"Accounts returned: {account_list}"
        )

    # 1. Generate the ETag:
    etag_hash = generate_etag_hash(account_list)

    # 2. Check If-None-Match:
    if_none_match = request.headers.get(IF_NONE_MATCH_HEADER)
    if if_none_match and if_none_match == etag_hash:
        return make_response('', status.HTTP_304_NOT_MODIFIED)

    # 3. Create the response with the ETag:
    response = make_response(jsonify(account_list), status.HTTP_200_OK)
    response.set_etag(etag_hash)  # Set the ETag header
    return response


######################################################################
# READ AN ACCOUNT
######################################################################
@swag_from({
    'operationId': 'getAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Retrieve Account by ID',
    'description': 'Retrieves an account based on its unique identifier.',
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
@count_requests
def find_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Retrieve Account by ID"""
    app.logger.info("Request to read an Account with id: %s", account_id)

    account = Account.find(account_id)

    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            f"Account with id [{account_id}] could not be found."
        )

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
    response.set_etag(etag_hash)  # Set the ETag header
    return response


######################################################################
# UPDATE AN EXISTING ACCOUNT
######################################################################
@swag_from({
    'operationId': 'updateAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Update Account by ID',
    'description': 'Updates an existing account with the provided JSON data.',
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
        # 404 Not Found
        404: {'description': 'Not Found'},
        # For UnsupportedMediaType
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['PUT'])
@count_requests
def update_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Update Account by ID"""
    app.logger.info("Request to update an Account with id: %s", account_id)

    account = Account.find(account_id)

    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            f"Account with id [{account_id}] could not be found."
        )

    account.deserialize(request.get_json())
    account.update()

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)
    return account_dto.dict(), status.HTTP_200_OK


######################################################################
# PARTIAL UPDATE AN EXISTING ACCOUNT
######################################################################
@swag_from({
    'operationId': 'partialUpdateAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Partial Update Account by ID',
    'description': 'Partially updates an existing account with the provided JSON data.',
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
        # 404 Not Found
        404: {'description': 'Not Found'},
        # For UnsupportedMediaType
        415: {'description': 'Unsupported Media Type'},
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['PATCH'])
@count_requests
def partial_update_by_id(account_id: UUID) -> Tuple[Dict[str, Any], int]:
    """Partial Update Account by ID"""
    app.logger.info(
        "Request to partially update an Account with id: %s",
        account_id
    )

    account = Account.find(account_id)

    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            f"Account with id [{account_id}] could not be found."
        )

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
    return account_dto.dict(), status.HTTP_200_OK


######################################################################
# DELETE AN ACCOUNT
######################################################################
@swag_from({
    'operationId': 'deleteAccountByIdV1',
    'tags': ['Accounts V1'],
    'summary': 'Delete Account by ID',
    'description': 'Deletes an account based on its unique identifier.',
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
        # For any other internal errors
        500: {'description': 'Internal Server Error'}
    }
})
@app.route(f"{ACCOUNTS_PATH_V1}/<uuid:account_id>", methods=['DELETE'])
@count_requests
def delete_by_id(account_id: UUID) -> Tuple[str, int]:
    """Delete Account By ID"""
    app.logger.info("Request to delete an Account with id: %s", account_id)

    account = Account.find(account_id)
    if account:
        account.delete()

    return "", status.HTTP_204_NO_CONTENT

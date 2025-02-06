"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime
from typing import Dict, Tuple, Any, List

# pylint: disable=unused-import
from flask import jsonify, request, make_response, abort, url_for  # noqa; F401

from service import app, VERSION, NAME
from service.common import status
from service.common.utils import check_content_type
from service.models import Account
from service.schemas import AccountDTO

ROOT_ENDPOINT = '/'
HEALTH_ENDPOINT = '/health'
INFO_ENDPOINT = '/info'
ACCOUNT_ENDPOINT = '/accounts'


######################################################################
# GET INDEX
######################################################################
@app.route(ROOT_ENDPOINT, methods=['GET'])
def index() -> Tuple[Dict[str, Any], int]:
    """Returns a welcome message for the Account API.

    This endpoint provides a basic welcome message for the Account API.

    Returns:
        A tuple containing a JSON response (a dictionary) and the HTTP
        status code (200 OK).
    """
    return jsonify(
        {'message': 'Welcome to the Account API!'}
    ), status.HTTP_200_OK


############################################################
# GET HEALTH
############################################################
@app.route(HEALTH_ENDPOINT, methods=['GET'])
def health() -> Tuple[Dict[str, Any], int]:
    """Returns the health status of the service.

    This endpoint checks the overall health of the service. Currently,
    it always returns a 200 OK status with a "status: UP" message.  In a
    more complex application, this endpoint could perform more extensive
    health checks (e.g., database connectivity, dependent services).

    Returns:
        A tuple containing a JSON response (a dictionary) and the HTTP
        status code (200 OK).
    """
    return jsonify({'status': 'UP'}), status.HTTP_200_OK


############################################################
# GET INFO
############################################################
@app.route(INFO_ENDPOINT, methods=['GET'])
def info() -> Tuple[Dict[str, Any], int]:
    """Returns information about the service.

    This endpoint provides information about the service, including its
    name, version, and uptime.

    Returns:
        A tuple containing a JSON response (a dictionary) and the HTTP
        status code (200 OK).
    """
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
@app.route(ACCOUNT_ENDPOINT, methods=['POST'])
def create() -> Tuple[Dict[str, Any], int, Dict[str, str]]:
    """Creates a new Account.

    This endpoint creates a new Account based on the JSON data provided
    in the request body.

    Returns:
        A tuple containing the JSON response (a dictionary representing
        the created account), the HTTP status code (201 Created), and a
        dictionary containing the "Location" header URL.

    Raises:
      werkzeug.exceptions.UnsupportedMediaType: If the Content-Type is not 'application/json'
      DataValidationError: If the data is invalid.
      IntegrityError: If a database integrity error occurs.
    """
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
@app.route(ACCOUNT_ENDPOINT, methods=['GET'])
def list_accounts() -> Tuple[List[Dict[str, Any]], int]:
    """Lists all Accounts.

    This endpoint retrieves a list of all Account objects from the database
    and returns them as a JSON array of dictionaries.

    Returns:
        A tuple containing a JSON array of dictionaries representing the
        accounts and the HTTP status code (200 OK).
    """
    app.logger.info('Request to list Accounts')

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

    return jsonify(account_list), status.HTTP_200_OK


######################################################################
# READ AN ACCOUNT
######################################################################
@app.route(f"{ACCOUNT_ENDPOINT}/<int:account_id>", methods=['GET'])
def find_by_id(account_id: int) -> Tuple[Dict[str, Any], int]:
    """Reads an Account by ID.

    This endpoint retrieves an Account object by its ID and returns it
    as a JSON dictionary.

    Args:
        account_id: The ID of the Account to retrieve.

    Returns:
        A tuple containing the JSON representation of the Account (a
        dictionary) and the HTTP status code (200 OK).

    Raises:
        werkzeug.exceptions.NotFound: If the Account with the given ID is
                                       not found.
    """
    app.logger.info("Request to read an Account with id: %s", account_id)

    account = Account.find(account_id)

    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            f"Account with id [{account_id}] could not be found."
        )

    # Convert SQLAlchemy model to DTO
    account_dto = AccountDTO.from_orm(account)
    return account_dto.dict(), status.HTTP_200_OK


######################################################################
# UPDATE AN EXISTING ACCOUNT
######################################################################
@app.route(f"{ACCOUNT_ENDPOINT}/<int:account_id>", methods=['PUT'])
def update_by_id(account_id: int) -> Tuple[Dict[str, Any], int]:
    """Updates an Account.

    This endpoint updates an existing Account object with the data provided
    in the request body.

    Args:
        account_id: The ID of the Account to update.

    Returns:
        A tuple containing the JSON representation of the updated Account
        (a dictionary) and the HTTP status code (200 OK).

    Raises:
        werkzeug.exceptions.NotFound: If the Account with the given ID is
                                       not found.
        werkzeug.exceptions.UnsupportedMediaType: If the Content-Type is not 'application/json'
        DataValidationError: If the data is invalid.
        IntegrityError: If a database integrity error occurs.
    """
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
@app.route(f"{ACCOUNT_ENDPOINT}/<int:account_id>", methods=['PATCH'])
def partial_update_by_id(account_id: int) -> Tuple[Dict[str, Any], int]:
    """Partially updates an Account.

    This endpoint partially updates an existing Account object with the
    data provided in the request body.

    Args:
        account_id: The ID of the Account to update.

    Returns:
        A tuple containing the JSON representation of the updated Account
        (a dictionary) and the HTTP status code (200 OK).

    Raises:
        werkzeug.exceptions.NotFound: If the Account with the given ID is
                                       not found.
        werkzeug.exceptions.BadRequest: If no data is provided in the
                                       request body.
        DataValidationError: If the data is invalid.
        IntegrityError: If a database integrity error occurs.
        werkzeug.exceptions.UnsupportedMediaType: If the Content-Type is not 'application/json'
    """
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
@app.route(f"{ACCOUNT_ENDPOINT}/<int:account_id>", methods=['DELETE'])
def delete_by_id(account_id: int) -> Tuple[str, int]:
    """Deletes an Account.

    This endpoint deletes an Account object with the specified ID.

    Args:
        account_id: The ID of the Account to delete.

    Returns:
        A tuple containing an empty string (as the response body) and the
        HTTP status code (204 No Content).

    Raises:
        werkzeug.exceptions.NotFound: If the Account with the given ID is
                                       not found.
        DataValidationError: If an error occurs during the deletion.
        IntegrityError: If a database integrity error occurs.
    """
    app.logger.info("Request to delete an Account with id: %s", account_id)

    account = Account.find(account_id)
    if account:
        account.delete()

    return "", status.HTTP_204_NO_CONTENT

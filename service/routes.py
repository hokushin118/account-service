"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime

# pylint: disable=unused-import
from flask import jsonify, request, make_response, abort, url_for  # noqa; F401

from service import app, VERSION, NAME
from service.common import status
from service.common.util import check_content_type
from service.models import Account

ROOT_ENDPOINT = '/'
HEALTH_ENDPOINT = '/health'
INFO_ENDPOINT = '/info'
ACCOUNT_ENDPOINT = '/accounts'


############################################################
# Health Endpoint
############################################################
@app.route(HEALTH_ENDPOINT)
def health():
    """Returns the health status of the service."""
    return jsonify({'status': 'UP'}), status.HTTP_200_OK


############################################################
# Info Endpoint
############################################################
@app.route(INFO_ENDPOINT)
def info():
    """Returns information about the service."""
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
# GET INDEX
######################################################################
@app.route(ROOT_ENDPOINT)
def index():
    """Returns a welcome message."""
    return jsonify(
        {'message': 'Welcome to the Account API!'}
    ), status.HTTP_200_OK


######################################################################
# CREATE A NEW ACCOUNT
######################################################################
@app.route(ACCOUNT_ENDPOINT, methods=['POST'])
def create_accounts():
    """
    Creates an Account.

    This endpoint will create an Account based the data in the body that is
    posted.
    """
    app.logger.info('Request to create an Account...')

    check_content_type('application/json')

    account = Account()
    account.deserialize(request.get_json())
    account.create()
    message = account.serialize()

    location_url = url_for(
        'get_account_by_id',
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
def list_accounts():
    """
    List all Accounts.

    This endpoint retrieves a list of all accounts.
    """
    app.logger.info('Request to list Accounts')

    accounts = Account.all()
    account_list = [account.serialize() for account in accounts]

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
def get_account_by_id(account_id):
    """
    Reads an Account by id.

    This endpoint will read an Account based the account_id that is requested.
    """
    app.logger.info("Request to read an Account with id: %s", account_id)

    account = Account.find(account_id)

    if not account:
        abort(
            status.HTTP_404_NOT_FOUND,
            f"Account with id [{account_id}] could not be found."
        )

    return account.serialize(), status.HTTP_200_OK


######################################################################
# UPDATE AN EXISTING ACCOUNT
######################################################################
@app.route(f"{ACCOUNT_ENDPOINT}/<int:account_id>", methods=['PUT'])
def update_account_by_id(account_id):
    """
    Update an Account.

    This endpoint will update an Account based on the posted data.
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

    return account.serialize(), status.HTTP_200_OK

"""
Account Service

This microservice handles the lifecycle of Accounts
"""
import datetime

# pylint: disable=unused-import
from flask import jsonify, request, make_response, abort, url_for  # noqa; F401

from service import app, VERSION, NAME
from service.common import status

ROOT_ENDPOINT = '/'
HEALTH_ENDPOINT = '/health'
INFO_ENDPOINT = '/info'


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

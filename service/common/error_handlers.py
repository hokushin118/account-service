"""
Module: error_handlers.
"""
from typing import Any, Dict, Tuple

from flask import jsonify

from service import app
from service.common import status
from service.models import DataValidationError


######################################################################
# Error Handlers
######################################################################
@app.errorhandler(DataValidationError)
def request_validation_error(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles validation errors (e.g., from bad data).

    This error handler catches DataValidationError exceptions
    and returns a 400 Bad Request response with
    details about the validation errors.

    Args:
        error: The DataValidationError instance.

    Returns:
        A tuple containing the error response (a dictionary) and the
        HTTP status code (400).
    """
    return bad_request(error)


@app.errorhandler(status.HTTP_400_BAD_REQUEST)
def bad_request(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles bad requests (400 Bad Request).

    This error handler catches 400 Bad Request exceptions and returns a
    JSON response with an error message.

    Args:
        error: The exception that caused the 400 error.  It will often be a
            werkzeug.exceptions.BadRequest instance, but could be other
            exceptions.

    Returns:
        A tuple containing the error response (a JSON-serializable dictionary)
        and the HTTP status code (400).
    """
    message = str(error)
    app.logger.warning(message)
    return (
        jsonify(
            status=status.HTTP_400_BAD_REQUEST,
            error='Bad Request',
            message=message
        ),
        status.HTTP_400_BAD_REQUEST,
    )


@app.errorhandler(status.HTTP_404_NOT_FOUND)
def not_found(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles "Not Found" errors (404 Not Found).

    This error handler catches 404 Not Found exceptions and returns a
    JSON response with an error message.

    Args:
        error: The exception that caused the 404 error. It will often be a
            werkzeug.exceptions.NotFound instance.

    Returns:
        A tuple containing the error response (a JSON-serializable dictionary)
        and the HTTP status code (404).
    """
    message = str(error)
    app.logger.warning(message)
    return (
        jsonify(
            status=status.HTTP_404_NOT_FOUND,
            error='Not Found',
            message=message
        ),
        status.HTTP_404_NOT_FOUND,
    )


@app.errorhandler(status.HTTP_405_METHOD_NOT_ALLOWED)
def method_not_supported(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles "Method Not Allowed" errors (405 Method Not Allowed).

    This error handler catches 405 Method Not Allowed exceptions and returns a
    JSON response with an error message.

    Args:
        error: The exception that caused the 405 error.  It will often be a
            werkzeug.exceptions.MethodNotAllowed instance.

    Returns:
        A tuple containing the error response (a JSON-serializable dictionary)
        and the HTTP status code (405).
    """
    message = str(error)
    app.logger.warning(message)
    return (
        jsonify(
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
            error='Method not Allowed',
            message=message,
        ),
        status.HTTP_405_METHOD_NOT_ALLOWED,
    )


@app.errorhandler(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE)
def mediatype_not_supported(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles "Unsupported Media Type" errors (415 Unsupported Media Type).

    This error handler catches 415 Unsupported Media Type exceptions and
    returns a JSON response with an error message.

    Args:
        error: The exception that caused the 415 error.  It will often be a
            werkzeug.exceptions.UnsupportedMediaType instance.

    Returns:
        A tuple containing the error response (a JSON-serializable dictionary)
        and the HTTP status code (415).
    """
    message = str(error)
    app.logger.warning(message)
    return (
        jsonify(
            status=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            error='Unsupported media type',
            message=message,
        ),
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    )


@app.errorhandler(status.HTTP_500_INTERNAL_SERVER_ERROR)
def internal_server_error(error: Exception) -> Tuple[Dict[str, Any], int]:
    """Handles internal server errors (500 Internal Server Error).

    This error handler catches 500 Internal Server Error exceptions and
    returns a JSON response with a generic error message.  It's generally
    best *not* to expose detailed error information to the client in
    production for security reasons.

    Args:
        error: The exception that caused the 500 error.

    Returns:
        A tuple containing the error response (a JSON-serializable dictionary)
        and the HTTP status code (500).
    """
    message = str(error)
    app.logger.error(message)
    return (
        jsonify(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error='Internal Server Error',
            message=message,
        ),
        status.HTTP_500_INTERNAL_SERVER_ERROR,
    )

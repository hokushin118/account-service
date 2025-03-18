"""
This module defines and registers error handlers for a Flask application.

It provides centralized exception handling for common HTTP errors and custom
application exceptions, ensuring consistent error responses in JSON format.

Usage:
    To use this module, import `register_error_handlers` and call it with your
    Flask application instance:

    ```python
    from flask import Flask
    from error_handlers import register_error_handlers

    app = Flask(__name__)
    register_error_handlers(app)
    ```
"""
from typing import Any, Dict, Tuple

from flask import Flask, jsonify

from service.common import status
from service.errors import AccountNotFoundError, AccountError, \
    AccountAuthorizationError
from service.models import DataValidationError


######################################################################
# Error Handlers
######################################################################
def register_error_handlers(app: Flask) -> None:
    """Registers error handlers for the Flask application.

    This function sets up handlers for various exceptions and HTTP error codes,
    allowing the application to return consistent and informative JSON error
    responses.

    Args:
        app (Flask): The Flask application instance to which error handlers
                     will be registered.
    """

    @app.errorhandler(DataValidationError)
    def handle_data_validation_error(
            error: DataValidationError
    ) -> Tuple[Dict[str, Any], int]:
        """Handles DataValidationError exceptions.

        This handler is triggered when a DataValidationError is raised,
        indicating that the data provided in the request is invalid. It returns
        a JSON response with details of the validation error and a 400
        HTTP status code.

        Args:
            error (DataValidationError): The DataValidationError instance containing
                                         the error details.

        Returns:
            Tuple[Dict[str, Any], int]: A tuple containing the error response as a
                                        dictionary and the HTTP status code (400).
        """
        app.logger.debug(
            'Account validation error handler invoked...'
        )
        return handle_bad_request(error)

    @app.errorhandler(AccountError)
    def handle_account_error(
            error: AccountError
    ) -> Tuple[Dict[str, Any], int]:
        """Handles AccountError exceptions.

        This error handler catches AccountError exceptions
        and returns a 400 Bad Request response.

        Args:
            error: The AccountError instance.

        Returns:
            A tuple containing the error response (a dictionary) and the
            HTTP status code (400).
        """
        app.logger.debug(
            'General Account error handler invoked...'
        )
        return handle_bad_request(error)

    @app.errorhandler(AccountNotFoundError)
    def handle_account_not_found_error(
            error: AccountNotFoundError
    ) -> Tuple[Dict[str, Any], int]:
        """Handles AccountNotFoundError exceptions.

        This error handler catches AccountNotFoundError exceptions
        and returns a 404 Not Found response.

        Args:
            error: The AccountNotFoundError instance.

        Returns:
            A tuple containing the error response (a dictionary) and the
            HTTP status code (404).
        """
        app.logger.debug(
            'Account not found error handler invoked...'
        )
        return handle_not_found(error)

    @app.errorhandler(AccountAuthorizationError)
    def handle_account_authorization_error(
            error: AccountAuthorizationError
    ) -> Tuple[Dict[str, Any], int]:
        """Handles AccountAuthorizationError exceptions.

        This error handler catches AccountAuthorizationError exceptions
        and returns a 403 Forbidden response.

        Args:
            error: The AccountAuthorizationError instance.

        Returns:
            A tuple containing the error response (a dictionary) and the
            HTTP status code (403).
        """
        app.logger.debug(
            'Account authorization error handler invoked...'
        )
        return handle_forbidden(error)

    @app.errorhandler(status.HTTP_400_BAD_REQUEST)
    def handle_bad_request(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
        """Handles bad requests (400 Bad Request).

        This error handler catches 400 Bad Request exceptions and returns a
        JSON response with an error message.

        Args:
            error: The exception that caused the 400 error.

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

    @app.errorhandler(status.HTTP_403_FORBIDDEN)
    def handle_forbidden(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
        """Handles authorization errors (403 Forbidden).

        This error handler catches 403 Forbidden exceptions and returns a
        JSON response with an error message.

        Args:
            error: The exception that caused the 403 error.

        Returns:
            A tuple containing the error response (a JSON-serializable dictionary)
            and the HTTP status code (403).
        """
        message = str(error)
        app.logger.warning(message)
        return (
            jsonify(
                status=status.HTTP_403_FORBIDDEN,
                error='Forbidden',
                message=message
            ),
            status.HTTP_403_FORBIDDEN,
        )

    @app.errorhandler(status.HTTP_404_NOT_FOUND)
    def handle_not_found(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
        """Handles "Not Found" errors (404 Not Found).

        This error handler catches 404 Not Found exceptions and returns a
        JSON response with an error message.

        Args:
            error: The exception that caused the 404 error.

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
    def handle_method_not_supported(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
        """Handles "Method Not Allowed" errors (405 Method Not Allowed).

        This error handler catches 405 Method Not Allowed exceptions and returns a
        JSON response with an error message.

        Args:
            error: The exception that caused the 405 error.

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
    def handle_mediatype_not_supported(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
        """Handles "Unsupported Media Type" errors (415 Unsupported Media Type).

        This error handler catches 415 Unsupported Media Type exceptions and
        returns a JSON response with an error message.

        Args:
            error: The exception that caused the 415 error.

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
    def handle_internal_server_error(
            error: Exception
    ) -> Tuple[Dict[str, Any], int]:
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

"""
Utility functions.

This module contains utility functions to REST API.
"""
import hashlib
from functools import wraps
from typing import Any, Union, Callable

from flask import request, abort
from prometheus_flask_exporter import Counter  # Make sure this import is here

from service import app
from service.common import status

######################################################################
#  U T I L I T Y   F U N C T I O N S
######################################################################

request_counter = Counter(
    'http_requests_total', 'Total number of HTTP requests', ['method', 'path']
)


def count_requests(func: Callable[..., Any]) -> Callable[..., Any]:
    """A decorator to increment the HTTP request counter for a given endpoint.

    This decorator increments the 'http_requests_total' Prometheus counter
    with labels for the HTTP method and path of the request.  It preserves
    the original function's metadata (name, docstring, etc.) using @wraps.

    Args:
        func: The function to be decorated (a Flask route function).

    Returns:
        The decorated function.
    """

    @wraps(func)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        """The decorated function that increments the counter and calls the original function.

        This inner function is what actually gets called when the decorated route is accessed.
        It increments the Prometheus counter using labels for the HTTP method and path, and
        then calls the original route function (`f`).

        Args:
            *args:  Positional arguments passed to the original function.
            **kwargs: Keyword arguments passed to the original function.

        Returns:
            The return value of the original function (`f`).
        """
        request_counter.labels(method=request.method, path=request.path).inc()
        return func(*args, **kwargs)

    return decorated_function


def check_content_type(media_type: str) -> None:
    """Checks that the Content-Type header matches the expected media type.

    Args:
        media_type: The expected Content-Type string (e.g., "application/json").

    Raises:
        HTTPException: If the Content-Type header is missing or does not match
                       the expected media type.  A 415 Unsupported Media Type
                       error is raised.
    """
    content_type = request.headers.get('Content-Type')
    if content_type and content_type == media_type:
        return
    app.logger.error("Invalid Content-Type: %s", content_type)
    abort(
        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        f"Content-Type must be {media_type}",
    )


def account_to_dict(account_or_dto: Union[object, dict]) -> dict[str, Any]:
    """Converts an Account object or DTO to a dictionary.

    Handles both Account objects (presumably from SQLAlchemy or a similar ORM)
    and AccountDTO (or similar DTO) objects.  Converts the date_joined field
    to an ISO 8601 string if it's a date object.

    Args:
        account_or_dto: The Account object or DTO to convert.

    Returns:
        A dictionary representation of the Account object or DTO.
    """
    return {
        'id': account_or_dto.id,
        'name': account_or_dto.name,
        'email': account_or_dto.email,
        'address': account_or_dto.address,
        'phone_number': account_or_dto.phone_number,
        'date_joined': account_or_dto.date_joined.isoformat(),
    }


def generate_etag_hash(data: dict) -> str:
    """Generates an ETag hash for the given data.

    This function calculates the MD5 hash of the string representation of the
    input dictionary.  The resulting hash can be used as an ETag for caching
    purposes.

    Args:
        data: A dictionary representing the data to be hashed.

    Returns:
        A string representing the hexadecimal MD5 hash of the data.
    """
    data_str = str(data).encode('utf-8')  # Encode to bytes before hashing
    return hashlib.md5(data_str).hexdigest()  # Hash the data

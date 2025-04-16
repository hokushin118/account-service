"""
Utility functions.

This module contains utility functions to REST API.
"""
import logging
import sys
from functools import wraps
from typing import Any, Union, Callable
from typing import Tuple

from flask import request
from prometheus_flask_exporter import Counter
from sqlalchemy import (
    Column,
    TIMESTAMP,
    func
)

logger = logging.getLogger(__name__)

######################################################################
#  UTILITY FUNCTIONS
######################################################################

request_counter = Counter(
    'http_requests_total', 'Total number of HTTP requests', ['method', 'path']
)


def count_requests(function: Callable[..., Any]) -> Callable[..., Any]:
    """A decorator to increment the HTTP request counter for a given endpoint.

    This decorator increments the 'http_requests_total' Prometheus counter
    with labels for the HTTP method and path of the request.  It preserves
    the original function's metadata (name, docstring, etc.) using @wraps.

    Args:
        function: The function to be decorated (a Flask route function).

    Returns:
        The decorated function.
    """

    @wraps(function)
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
        return function(*args, **kwargs)

    return decorated_function


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
        'gender': account_or_dto.gender,
        'address': account_or_dto.address,
        'phone_number': account_or_dto.phone_number,
        'date_joined': account_or_dto.date_joined.isoformat(),
        'user_id': account_or_dto.user_id,
    }


def timestamps(
        is_indexed: bool = False
) -> Tuple[Column, Column]:
    """Creating auditing fields for an entity.

    Args:
        is_indexed (bool): A flag indicating whether the field
        should be indexed.

    Returns:
        A tuple of auditing fields for the entity.
    """
    return (
        Column(
            'created_at',
            TIMESTAMP(timezone=True),
            server_default=func.now(),  # pylint: disable=not-callable
            nullable=False,
            index=is_indexed,
        ),
        Column(
            'updated_at',
            TIMESTAMP(timezone=True),
            server_default=func.now(),  # pylint: disable=not-callable
            nullable=False,
            index=is_indexed,
        ),
    )


def is_flask_cli_alternative() -> bool:
    """
    Determines if a Flask CLI command is being invoked using command-line arguments.

    Returns:
        bool: True if 'flask' appears in sys.argv (or if specific CLI commands are detected),
              False otherwise.
    """
    # This is a simplistic check; you might want to refine based on your use-case.
    flask_commands = {
        'run', 'shell', 'db-upgrade', 'db', 'create', 'init',
        'db-init', 'db-migrate', 'db-revision', 'db-downgrade',
        'db-history', 'db-create'
    }
    return any(arg in flask_commands for arg in sys.argv)

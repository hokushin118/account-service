"""
Audit utils.

This module contains utility functions to Flask Audit.
"""
import logging
from functools import wraps
from inspect import isfunction
from typing import Callable, Optional, Any

logger = logging.getLogger(__name__)

# Import the specific Flask adapter from your library
try:
    from cba_core_lib.audit.adapters import FlaskAuditAdapter

    IS_ADAPTER_AVAILABLE = True
    logger.debug('FlaskAuditAdapter imported successfully.')
except ImportError:
    IS_ADAPTER_AVAILABLE = False
    FlaskAuditAdapter = Any
    logger.debug(
        'FlaskAuditAdapter not found. Audit functionality requires it.'
    )

# Import Flask related things needed *here*
try:
    from flask import current_app

    IS_FLASK_AVAILABLE = True
    logger.debug('Flask components imported successfully.')
except ImportError:
    IS_FLASK_AVAILABLE = False
    Response = Any
    current_app = None
    logger.debug(
        'Flask not found. Audit decorator requires a Flask context.'
    )


def audit_log(
        function: Callable
) -> Callable:
    """Decorator factory for conditionally applying Flask audit logging.

    This decorator retrieves the pre-configured FlaskAuditAdapter from the
    Flask 'current_app' and applies its decorator *if* audit logging is
    enabled in the application's configuration.  This is done *at the time
    the route is called*, not when the route is defined.

    Args:
        function: The Flask route function (or any callable) to be decorated.

    Returns:
        The wrapped function.  When the wrapped function is called, this
        wrapper executes the conditional audit logic before calling the
        original function.

    Raises:
        RuntimeError: If used outside of a Flask application context,
            or if the FlaskAuditAdapter is not correctly configured
            when audit logging is enabled.
    """
    if not isfunction(function):
        raise TypeError(f"Expected a function, but got {type(function)}")

    @wraps(function)
    def wrapper(
            *args: Any,
            **kwargs: Any
    ) -> Any:
        """Inner wrapper function executed when the decorated route is
        called."""
        if not IS_FLASK_AVAILABLE:
            logger.error(
                'The audit_log decorator is being used outside of '
                'a Flask application context. Ensure that the decorator '
                'is only applied to functions within a Flask route handler.'
            )
            raise RuntimeError(
                'Flask is not available. The audit_log decorator '
                'requires a Flask application context.'
            )

        try:
            audit_is_enabled: bool = current_app.config.get(
                'AUDIT_ENABLED',
                False
            )
        except Exception as err:  # pylint: disable=W0703
            logger.error(
                "Error accessing current_app.config for AUDIT_ENABLED in "
                "decorator (%s): %s. Skipping audit.",
                getattr(
                    function,
                    '__name__',
                    '<unknown_function>'
                ),
                err,
                exc_info=True
            )
            return function(*args, **kwargs)

        if audit_is_enabled:
            logger.debug(
                "Audit enabled, attempting to apply decorator for route %s.",
                getattr(
                    function,
                    '__name__',
                    '<unknown_function>'
                )
            )
            flask_adapter: Optional[FlaskAuditAdapter] = getattr(
                current_app,
                'flask_audit_adapter',
                None
            )

            if flask_adapter and isinstance(flask_adapter, FlaskAuditAdapter):
                decorator_instance = flask_adapter.create_audit_decorator()
                decorated_func = decorator_instance(function)
                return decorated_func(
                    *args,
                    **kwargs
                )
            logger.warning(
                "AUDIT_ENABLED is True, but FlaskAuditAdapter "
                "not found or incorrectly configured on current_app. "
                "Skipping audit for %s.",
                function.__name__
            )
            return function(*args, **kwargs)
        return function(*args, **kwargs)

    return wrapper

"""
Keycloak Utilities Module.

This module provides utility functions for interacting with Keycloak IAM, including:

- Retrieving Keycloak certificates for JWT verification.
- Implementing a custom decorator for role-based access control using JWT claims.

It handles Keycloak configuration, certificate retrieval with retry logic,
and role validation based on JWT claims extracted fro
"""
import logging
import os
import time
from typing import Union, Any, Callable

import requests
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt

from service.common import status

logger = logging.getLogger(__name__)

# Keycloak Configuration
# Keycloak realm - an application security domain.
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'cba-dev')
# Keycloak hostname or ip address.
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', 'localhost')
# Keycloak port.
KEYCLOAK_PORT = os.getenv('KEYCLOAK_PORT', '28080')
# A unique identifier for an application or service that wants to
# authenticate or authorize users through Keycloak.
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'oauth2-proxy')
# Keycloak communication protocol.
KEYCLOAK_SCHEMA = os.getenv('KEYCLOAK_SCHEMA', 'http')
KEYCLOAK_URL = f"{KEYCLOAK_SCHEMA}://{KEYCLOAK_HOST}:{KEYCLOAK_PORT}"
# x5c (X.509 Certificate Chain): An array of X.509 certificates.
# The first element (x5c[0]) is the public key certificate itself.
X5C_KID = 'x5c'
# A unique identifier for a specific cryptographic key within a JWK Set.
JWT_KID = 'kid'
# The "keys" field in a JWKS is an array that contains one or more JSON Web Key (JWK) objects.
KEYS = 'keys'
# A claim within a JSON Web Token (JWT) that carries information about the
# user's roles at the realm level.
REALM_ACCESS_CLAIM = 'realm_access'
# is a claim within a JSON Web Token (JWT) that carries information
# about the user's roles specific to a particular client (application).
RESOURCE_ACCESS = 'resource_access'
# The roles claim in Keycloak's JWTs.
ROLES_CLAIM = 'roles'
INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE = 'Insufficient permissions'


def get_keycloak_certificate_with_retry(
        max_retries: Union[int, None] = None
) -> Union[str, None]:
    """Retrieves the Keycloak certificate, retrying every second until successful.

    Args:
        max_retries (Union[int, None], optional): The maximum number of retries.
            If None, retries indefinitely. Defaults to None.

    Returns:
        Union[str, None]: The Keycloak certificate string if retrieved successfully,
            otherwise None.
    """
    retries = 0
    while True:
        certificate = get_keycloak_certificate()
        if certificate:
            logger.debug('Keycloak certificate retrieved successfully.')
            return certificate

        if max_retries is not None and retries >= max_retries:
            logger.error(
                'Max retries reached. Failed to retrieve Keycloak certificate.'
            )
            return None

        logger.debug('Retrying Keycloak certificate retrieval in 5 seconds...')
        time.sleep(5)
        retries += 1


def get_keycloak_certificate() -> Union[str, None]:
    """
    Retrieves the X.509 certificate for a given kid from Keycloak.

       Returns:
           Union[str, None]: The X.509 certificate string if found, otherwise None.
    """
    jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    logger.debug("Fetching JWKS from URI: %s", jwks_url)

    try:
        response = requests.get(jwks_url)
        response.raise_for_status()  # Raises an HTTPError on bad responses
    except requests.exceptions.RequestException as req_error:
        logger.error(
            "Failed to retrieve JWKS from Keycloak: %s",
            req_error
        )
        return None

    try:
        jwks = response.json()
        logger.debug("Response (json): %s", jwks)
    except ValueError as json_error:
        logger.error("Invalid JSON received from Keycloak: %s", json_error)
        return None

    keys = jwks.get(KEYS, [])
    for key in keys:
        x5c_list = key.get(X5C_KID, [])
        if x5c_list:
            logger.debug("Found x5c certificate for kid: %s", key.get(JWT_KID))
            return x5c_list[0]

    logger.error("Key with kid '%s' not found in JWKS.", X5C_KID)
    return None


def has_role(required_role: str):
    """
    Decorator to enforce role-based access control.

    This decorator checks if the user, identified by their JWT, possesses the
    specified `required_role`. It extracts roles from the JWT's
    `resource_access` claim (or `realm_access` if applicable) and compares them
    against the `required_role`.

    Args:
        required_role (str): The role required to access the decorated function.

    Returns:
        callable: A decorator that wraps the provided function with role-based
                  access control.

    Raises:
        HTTP 403 Forbidden: If the user does not have the required role.
    """

    def wrapper(wrapped_fn: Callable) -> Callable:
        """
        Wrapper function that performs role-based access control.

        Args:
            wrapped_fn (callable): The function to be wrapped.

        Returns:
            callable: The wrapped function with role-based access control.
        """

        @jwt_required()
        def decorated_function(*args, **kwargs) -> Any:
            """
            Decorated function that retrieves JWT claims and checks roles.

            Args:
                *args: Positional arguments passed to the wrapped function.
                **kwargs: Keyword arguments passed to the wrapped function.

            Returns:
                Any: The result of the wrapped function if the user has the
                     required role, or a JSON response with a 403 Forbidden
                     status if not.
            """
            claims = get_jwt()
            roles = claims.get(RESOURCE_ACCESS, {}).get(
                KEYCLOAK_CLIENT_ID,
                {}).get(
                ROLES_CLAIM,
                []
            )

            if required_role in roles:
                return wrapped_fn(*args, **kwargs)

            # Check realm_access if resource_access check failed.
            realm_roles = claims.get(
                REALM_ACCESS_CLAIM, {}
            ).get(ROLES_CLAIM, [])

            if required_role in realm_roles:
                return wrapped_fn(*args, **kwargs)

            return jsonify(
                {'message': INSUFFICIENT_PERMISSIONS_ERROR_MESSAGE}
            ), status.HTTP_403_FORBIDDEN

        decorated_function.__name__ = wrapped_fn.__name__
        return decorated_function

    return wrapper

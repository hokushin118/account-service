"""
Environment utility functions.

This module contains environment utility functions.
"""
import logging
import os
from enum import Enum

logger = logging.getLogger(__name__)


######################################################################
#  ENVIRONMENT UTILITY FUNCTIONS
######################################################################
def get_enum_from_env(
        enum_type: Enum,
        env_var_name: str,
        default_value: Enum
) -> Enum:
    """Retrieves an enum value from an environment variable.

    This helper function attempts to retrieve a value from the specified environment
    variable and convert it to the corresponding enum member. If the environment
    variable is not set or the value is invalid, it returns the provided default value.

    Args:
        enum_type (Enum): The enum type to convert the environment variable value to.
        env_var_name (str): The name of the environment variable to retrieve.
        default_value (Enum): The default enum value to return if the environment
            variable is not set or the value is invalid.

    Returns:
        Enum: The enum member corresponding to the environment variable value, or
            the default value if the environment variable is not set or the value is
            invalid.
    """
    env_value = os.getenv(env_var_name, default_value.value)
    logger.debug(
        "Attempting to retrieve %s from environment: %s",
        env_var_name,
        env_value
    )
    try:
        enum_member = enum_type[env_value.upper()]
        logger.debug(
            "%s set to %s from environment.",
            env_var_name,
            enum_member.value
        )
        return enum_member
    except KeyError:
        logger.warning(
            "Invalid value %s for %s. Using default: %s",
            env_value,
            env_var_name,
            default_value.value
        )
        return default_value


def get_bool_from_env(
        env_var_name: str,
        default_value: bool
) -> bool:
    """Retrieves a boolean value from an environment variable.

    This helper function attempts to retrieve a boolean value from the specified
    environment variable. If the environment variable is not set or the value is
    invalid, it returns the provided default value.

    Args:
        env_var_name (str): The name of the environment variable to retrieve.
        default_value (bool): The default boolean value to return if the environment
            variable is not set or the value is invalid.

    Returns:
        bool: The boolean value corresponding to the environment variable value, or
            the default value if the environment variable is not set or the value is
            invalid.
    """
    env_value = os.getenv(env_var_name, str(default_value)).lower()
    logger.debug(
        "Attempting to retrieve %s from environment: %s",
        env_var_name, env_value
    )

    if env_value == 'true':
        logger.debug("%s set to True from environment.", env_var_name)
        return True

    if env_value == 'false':
        logger.debug("%s set to False from environment.", env_var_name)
        return False

    logger.warning(
        "Invalid boolean value '%s' for %s. Using default: %s",
        env_value,
        env_var_name,
        default_value,
    )

    return default_value


def get_int_from_env(
        env_var_name: str,
        default_value: int
) -> int:
    """Retrieves an integer value from an environment variable.

    This helper function attempts to retrieve an integer value from the specified
    environment variable. If the environment variable is not set or the value is
    invalid, it returns the provided default value.

    Args:
        env_var_name (str): The name of the environment variable to retrieve.
        default_value (int): The default integer value to return if the environment
            variable is not set or the value is invalid.

    Returns:
        int: The integer value corresponding to the environment variable value, or
            the default value if the environment variable is not set or the value is
            invalid.
    """
    env_value = os.getenv(env_var_name)
    if env_value is None:
        logger.debug(
            "%s not set, using default value: %s",
            env_var_name,
            default_value
        )
        return default_value

    try:
        int_value = int(env_value)
        logger.debug(
            "%s set to: %s",
            env_var_name,
            int_value
        )
        return int_value
    except ValueError:
        logger.warning(
            "Invalid integer value %s for %s. Using default: %s",
            env_value,
            env_var_name,
            default_value
        )
        return default_value

"""
Env Utils Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from unittest import TestCase
from unittest.mock import patch

from service.common.env_utils import (
    get_enum_from_env,
    get_bool_from_env, get_int_from_env
)
from service.configs import SecurityProtocol


######################################################################
#  ENV UTILS UNIT TEST CASES
######################################################################
class TestGetEnumFromEnv(TestCase):
    """The get_enum_from_env Function Tests."""

    def test_valid_env_value(self):
        """It should return the correct enum value when a valid environment variable is set."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_SECURITY_PROTOCOL': 'PLAINTEXT'}
        ):
            actual = get_enum_from_env(
                SecurityProtocol,
                'KAFKA_CONSUMER_SECURITY_PROTOCOL',
                SecurityProtocol.PLAINTEXT
            )
            self.assertEqual(actual, SecurityProtocol.PLAINTEXT)

    def test_invalid_env_value(self):
        """It should return the default enum value when an invalid environment variable is set."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_SECURITY_PROTOCOL': 'invalid'}
        ):
            actual = get_enum_from_env(
                SecurityProtocol,
                'KAFKA_CONSUMER_SECURITY_PROTOCOL',
                SecurityProtocol.PLAINTEXT
            )
            self.assertEqual(actual, SecurityProtocol.PLAINTEXT)

    def test_env_var_not_set(self):
        """It should return the default enum value when the environment variable is not set."""
        with patch.dict(os.environ, {}):
            actual = get_enum_from_env(
                SecurityProtocol,
                'KAFKA_CONSUMER_SECURITY_PROTOCOL',
                SecurityProtocol.PLAINTEXT
            )
            self.assertEqual(actual, SecurityProtocol.PLAINTEXT)

    def test_env_var_case_insensitive(self):
        """It should return the correct enum value when the environment variable is
        set with mixed case."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_SECURITY_PROTOCOL': 'SASL_Plaintext'}
        ):
            actual = get_enum_from_env(
                SecurityProtocol,
                'KAFKA_CONSUMER_SECURITY_PROTOCOL',
                SecurityProtocol.PLAINTEXT
            )
            self.assertEqual(actual, SecurityProtocol.SASL_PLAINTEXT)


class TestGetBoolFromEnv(TestCase):
    """The get_bool_from_env Function Tests."""

    def test_valid_true_env_value(self):
        """It should return True when the environment variable is 'true'."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT': 'true'}
        ):
            self.assertTrue(get_bool_from_env(
                'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                False
            ))

    def test_valid_false_env_value(self):
        """It should return False when the environment variable is 'false'."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT': 'false'}
        ):
            self.assertFalse(
                get_bool_from_env(
                    'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                    True
                )
            )

    def test_invalid_env_value(self):
        """It should return the default value for invalid environment values."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT': 'invalid'}
        ):
            self.assertTrue(
                get_bool_from_env(
                    'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                    True
                )
            )

    def test_env_var_not_set(self):
        """It should return the default value when the variable is not set."""
        with patch.dict(os.environ, {}):
            self.assertFalse(
                get_bool_from_env(
                    'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                    False
                )
            )

    def test_env_var_case_insensitive(self):
        """It should handle case-insensitive 'true' and 'false'."""
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT': 'TRUE'}
        ):
            self.assertTrue(
                get_bool_from_env(
                    'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                    False
                )
            )
        with patch.dict(
                os.environ,
                {'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT': 'FALSE'}
        ):
            self.assertFalse(
                get_bool_from_env(
                    'KAFKA_CONSUMER_ENABLE_AUTO_COMMIT',
                    True
                )
            )


class TestGetIntFromEnv(TestCase):
    """The get_int_from_env Function Tests."""

    def test_valid_int_env_value(self):
        """It should return the integer when the environment variable is a valid integer string."""
        with patch.dict(
                os.environ,
                {'KAFKA_PRODUCER_RETRIES': '5'}
        ):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES', 5
                ),
                5
            )

    def test_invalid_int_env_value(self):
        """It should return the default value for invalid integer environment values."""
        with patch.dict(
                os.environ,
                {'KAFKA_PRODUCER_RETRIES': 'invalid'}
        ):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES',
                    5
                ),
                5)

    def test_env_var_not_set(self):
        """It should return the default value when the variable is not set."""
        with patch.dict(os.environ, {}):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES',
                    5
                ),
                5
            )

    def test_env_var_float_string(self):
        """It should return the default value when the environment variable is a float string."""
        with patch.dict(
                os.environ,
                {'KAFKA_PRODUCER_RETRIES': '10.5'}
        ):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES',
                    5
                ),
                5
            )

    def test_env_var_negative_int(self):
        """It should return the negative integer when the environment variable is a
        negative integer string."""
        with patch.dict(
                os.environ,
                {'KAFKA_PRODUCER_RETRIES': '-50'}
        ):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES',
                    5),
                -50
            )

    def test_env_var_zero(self):
        """It should return zero when the environment variable is '0'."""
        with patch.dict(
                os.environ,
                {'KAFKA_PRODUCER_RETRIES': '0'}
        ):
            self.assertEqual(
                get_int_from_env(
                    'KAFKA_PRODUCER_RETRIES',
                    5
                ),
                0
            )

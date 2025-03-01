"""
This module provides constants for use in unit tests.
"""
import os

DATABASE_URI = os.getenv(
    'DATABASE_URI', 'postgresql://cba:pa$$wOrd123!@localhost:15432/account_db'
)
TEST_ROLE = 'ROLE_TEST'
TEST_OTHER_ROLE = 'ROLE_OTHER'
TEST_USER = 'test_user'

"""
Package: tests
Package for the application tests.
"""
import os

DATABASE_URI = os.getenv(
    'DATABASE_URI', 'postgresql://cba:pa$$wOrd123!@localhost:15432/account_db'
)

"""
Global Configuration for Application
"""
import logging
import os

logger = logging.getLogger('account-service')


def get_database_uri() -> str:
    """Constructs and returns the database URI.

    This function prioritizes the DATABASE_URI environment variable.
    If it's not set, it constructs the URI from individual database
    credentials (user, password, name, host, port) from environment variables,
    using default values if they are not set.

    Returns:
        The database URI string.
    """
    uri = os.getenv('DATABASE_URI')
    if uri:
        return uri

    user = os.getenv('DATABASE_USER', 'cba')
    password = os.getenv('DATABASE_PASSWORD', 'pa$$wOrd123!')
    name = os.getenv('DATABASE_NAME', 'account_db')
    host = os.getenv('DATABASE_HOST', 'localhost')
    port = os.getenv('DATABASE_PORT', '15432')

    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


# Load configuration values (call the function to get the URI)
DATABASE_URI = get_database_uri()
SQLALCHEMY_DATABASE_URI = DATABASE_URI
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Secret for session management
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    import secrets  # Use secrets module for better random key generation

    SECRET_KEY = secrets.token_urlsafe(
        32
    )  # Generate a 32-character random key
    logger.warning(
        'Using a generated secret key. Set SECRET_KEY in environment for production.'
    )

API_VERSION = os.getenv('API_VERSION', 'v1')

if not DATABASE_URI:
    raise ValueError(
        'DATABASE_URI must be configured. Set the DATABASE_URI environment '
        'variable or other database credentials.'
    )

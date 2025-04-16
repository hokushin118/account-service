"""
Global Configuration for Application
"""
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


######################################################################
# APPLICATION CONFIGURATION
######################################################################
@dataclass(frozen=True)
class AppConfig:
    """Encapsulates application configuration settings, including database
    and runtime parameters.

    Retrieves settings from environment variables with sensible defaults.

    This class is immutable.
    """
    database_uri: str = field(init=False, repr=False)
    """The PostgreSQL database URI, constructed from environment variables."""

    sqlalchemy_database_uri: str = field(init=False, repr=False)
    """The SQLAlchemy database URI, typically the same as database_uri."""

    sqlalchemy_track_modifications: bool = False
    """Flag indicating whether SQLAlchemy should track modifications."""

    secret_key: str = field(init=False, repr=False)
    """Secret key used for session management and security."""

    api_version: str = field(init=False)
    """The version of the API, retrieved from the API_VERSION environment
    variable."""

    log_level: str = field(init=False)
    """Log level of the application, retrieved from the LOG_LEVEL
    environment variable."""

    def __post_init__(self) -> None:
        """Post-initialization to set derived attributes and validate
        configuration.

        Sets the database_uri, sqlalchemy_database_uri, secret_key,
        api_version and log_level attributes.

        Raises:
            ValueError: If the database URI cannot be constructed.
        """
        database_uri = self._get_database_uri()
        secret_key = self._get_secret_key()
        api_version = os.getenv('API_VERSION', 'v1')
        log_level = os.getenv('LOG_LEVEL', 'INFO')

        object.__setattr__(self, 'database_uri', database_uri)
        object.__setattr__(self, 'sqlalchemy_database_uri', database_uri)
        object.__setattr__(self, 'secret_key', secret_key)
        object.__setattr__(self, 'api_version', api_version)
        object.__setattr__(self, 'log_level', log_level)

        if not database_uri:
            raise ValueError(
                'DATABASE_URI must be configured. Set the DATABASE_URI '
                'environment variable or other database credentials.'
            )

    @staticmethod
    def _get_database_uri() -> str:
        """Constructs and returns the PostgreSQL database URI.

        Prioritizes a complete DATABASE_URI environment variable. If not found,
        constructs the URI from individual components.

        Returns:
            str: The PostgreSQL database URI.
        """
        uri = os.getenv('DATABASE_URI')
        if uri:
            logger.debug('DATABASE_URI from environment: %s', uri)
            return uri

        # Retrieve individual components with defaults
        user = os.getenv('DATABASE_USER', 'cba')
        password = os.getenv('DATABASE_PASSWORD', 'pa$$wOrd123!')
        name = os.getenv('DATABASE_NAME', 'account_db')
        host = os.getenv('DATABASE_HOST', 'localhost')
        port = os.getenv('DATABASE_PORT', '15432')

        logger.debug(
            'Database connection: user=%s, name=%s, host=%s, port=%s',
            user,
            name,
            host,
            port,
        )

        return f"postgresql://{user}:{password}@{host}:{port}/{name}"

    @staticmethod
    def _get_secret_key() -> str:
        """Retrieves the secret key for session management.

        Generates a secure random key if SECRET_KEY is not set in the
        environment.

        Returns:
            str: The secret key.
        """
        secret_key = os.getenv('SECRET_KEY')
        if not secret_key:
            import secrets  # pylint: disable=C0415
            # Generate a secure random secret key if not set
            secret_key = secrets.token_urlsafe(32)
            logger.warning(
                'Using a generated secret key. Set SECRET_KEY in environment '
                'for production.'
            )
        return secret_key

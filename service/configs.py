"""
Global Configuration for Application
"""
import logging
import os
from typing import Union, Optional

logger = logging.getLogger(__name__)


class AppConfig:
    """Encapsulates application configuration settings, including database and runtime parameters.

    Retrieves settings from environment variables with sensible defaults.
    """

    def __init__(self) -> None:
        """Initializes the application configuration.

        Sets database URI, SQLAlchemy settings, secret key, and API version.

        Raises:
            ValueError: If the DATABASE_URI cannot be constructed from environment variables.
        """
        self.database_uri: str = self._get_database_uri()
        self.sqlalchemy_database_uri: str = self.database_uri
        self.sqlalchemy_track_modifications: bool = False
        self.secret_key: str = self._get_secret_key()
        self.api_version: str = os.getenv('API_VERSION', 'v1')

        if not self.database_uri:
            raise ValueError(
                'DATABASE_URI must be configured. Set the DATABASE_URI environment '
                'variable or other database credentials.'
            )

    @staticmethod
    def _get_database_uri() -> str:
        """Constructs and returns the PostgreSQL database URI.

        Prioritizes a complete DATABASE_URI environment variable. If not found, constructs
        the URI from individual components.

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

        Generates a secure random key if SECRET_KEY is not set in the environment.

        Returns:
            str: The secret key.
        """
        secret_key = os.getenv('SECRET_KEY')
        if not secret_key:
            import secrets  # pylint: disable=C0415
            # Generate a secure random secret key if not set
            secret_key = secrets.token_urlsafe(32)
            logger.warning(
                'Using a generated secret key. Set SECRET_KEY in environment for production.'
            )
        return secret_key


class KafkaProducerConfig:
    """Encapsulates Kafka producer configuration settings."""

    def __init__(
            self,
            bootstrap_servers: str,
            retries: int,
            acks: Union[int, str],
            linger_ms: int,
            batch_size: int,
            health_check_interval: int,
            compression_type: Optional[str] = None,
    ) -> None:
        """Initialize a new instance of KafkaProducerConfig with the specified parameters.

        Args:
            bootstrap_servers (str): A comma-separated string specifying the Kafka broker addresses.
            retries (int, optional): The number of retry attempts when sending messages.
            acks (Union[int, str], optional): The acknowledgment policy to ensure message
            durability.
            linger_ms (int, optional): The number of milliseconds to buffer data before sending
            a batch. This can help improve throughput at the expense of latency.
            batch_size (int, optional): The size (in bytes) of the batch of messages to be sent.
            Larger values may increase throughput.
            health_check_interval (int, optional): The interval, in seconds, to perform connection
            health checks.
            compression_type (Optional[str], optional): The compression algorithm for the messages.
                Options include None, 'gzip', 'snappy', 'lz4', or 'zstd'. Defaults to None.
        """
        self.bootstrap_servers = bootstrap_servers
        self.retries = retries
        self.acks = acks
        self.linger_ms = linger_ms
        self.batch_size = batch_size
        self.compression_type = compression_type
        self.health_check_interval = health_check_interval

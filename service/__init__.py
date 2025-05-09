"""
Package: service
Package for the application models and service routes
This module creates and configures the Flask app and sets up the logging
and SQL database
"""
import datetime
import logging
import os
import signal
import sys
from types import FrameType
from typing import Optional

from cba_core_lib.logging import init_logging
from cba_core_lib.utils.constants import (
    AUTHORIZATION_HEADER,
    BEARER_HEADER,
)
from cba_core_lib.utils.env_utils import get_bool_from_env, get_int_from_env
from dotenv import load_dotenv
from flasgger import Swagger, LazyString, LazyJSONEncoder, MK_SANITIZER
from flask import Flask, request
from flask_caching import Cache  # pylint: disable=E0401
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman
from prometheus_flask_exporter import PrometheusMetrics

from service.common.constants import (
    NAME_MAX_LENGTH,
    NAME_MIN_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH,
    GENDER_MAX_LENGTH
)
from service.consumers import get_kafka_consumer_manager

logger = logging.getLogger(__name__)

APP_INFO_METRICS = 'app_info'


# --- Configuration and Environment Setup ---

def load_environment_variables() -> None:
    """
    Loads environment variables from a .env file into the operating system's
    environment.

    This function uses the `dotenv` library to load key-value pairs from a
    .env file located in the current working directory and sets them as
    environment variables. This allows the application to access configuration
    settings without hardcoding them in the source code.

    Returns:
        None: This function modifies the operating system's environment and does
        not return a value.
    """
    # Load the correct .env file based on APP_SETTINGS
    # export APP_SETTINGS=docker  # Or production, etc.
    env = os.environ.get('APP_SETTINGS')
    logging.warning("Environment variables: %s", env)
    base_dir = os.path.dirname(os.path.dirname(__file__))
    dotenv_filename = '.env' if not env else f'.env.{env}'
    dotenv_path = os.path.join(base_dir, dotenv_filename)
    logger.debug("Loading environment variables from: %s", dotenv_path)
    try:
        if os.path.exists(dotenv_path):
            load_dotenv(dotenv_path)
            logger.info("Environment variables loaded from %s", dotenv_path)
        else:
            logger.warning("Dotenv file not found at %s", dotenv_path)
    except FileNotFoundError as err:
        logging.error(
            "Dotenv file not found: %s: %s",
            dotenv_path,
            err
        )
    except UnicodeDecodeError as err:
        logging.error(
            "Encoding error in dotenv file: %s: %s",
            dotenv_path,
            err
        )
    except OSError as err:
        logging.error(
            "OS error reading dotenv file: %s: %s",
            dotenv_path,
            err
        )
    except SyntaxError as err:
        logging.error(
            "Syntax error in dotenv file: %s: %s",
            dotenv_path,
            err
        )
    except TypeError as err:
        logging.error(
            "Type error while loading dotenv file: %s: %s",
            dotenv_path,
            err
        )


# Load environment at startup
load_environment_variables()

from service.configs import AppConfig  # pylint: disable=C0413
# pylint: disable=C0413
from service.common.keycloak_utils import (
    KEYCLOAK_URL,
    KEYCLOAK_REALM,
    get_keycloak_certificate,
    get_keycloak_certificate_with_retry,
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_SECRET, get_current_user_id
)

app_config = AppConfig()

# Get the root logger
root_logger = logging.getLogger()

# Initialize logging with the root logger.
# The logging configuration sets the application's logger to DEBUG level.
# This will affect all loggers in the application.
init_logging(root_logger, log_level=app_config.log_level)

# Retrieving Information (Environment Variables Example):
# This is a common way to manage configuration, especially in
# containerized environments.
VERSION = os.environ.get('VERSION', '0.0.1')  # Default if not set
NAME = os.environ.get('NAME', 'account-service')
FORCE_HTTPS = get_bool_from_env('FORCE_HTTPS', False)
SWAGGER_ENABLED = get_bool_from_env('SWAGGER_ENABLED', False)
AUDIT_ENABLED = get_bool_from_env('AUDIT_ENABLED', False)
CACHE_TYPE = os.environ.get('CACHE_TYPE', 'redis')
CACHE_REDIS_HOST = os.environ.get('CACHE_REDIS_HOST', 'localhost')
CACHE_REDIS_PORT = os.environ.get('CACHE_REDIS_PORT', '6379')
CACHE_REDIS_DB = os.environ.get('CACHE_REDIS_DB', '0')
CACHE_REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')


# --- Security Configuration ---
def configure_security(current_app: Flask) -> None:
    """
    Configures the security settings for the Flask application.

    This function sets up various security measures for the Flask application
    by applying the following configurations:
      - Configures a Content Security Policy (CSP) that restricts sources for scripts, styles,
      images, fonts, and connections.
      - Enables Talisman to enforce HTTPS and apply the defined CSP.
      - Enables Cross-Origin Resource Sharing (CORS) for all routes and origins.

    Args:
        current_app (Flask): The Flask application instance to configure.

    Returns:
        None: This function modifies the Flask application in place and does not return a value.
    """
    # Define your CSP (adjust as needed for your application)
    # Allow inline styles (often needed by Swagger UI) and CDNs
    # Add Google Fonts
    # Add any CDNs needed by your app
    csp = {
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net',
                       "'unsafe-inline'"],
        'style-src': ['\'self\'', '\'unsafe-inline\'',
                      'https://cdn.jsdelivr.net',
                      'https://fonts.googleapis.com'],
        'img-src': ["'self'", "data:"],
        'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
        # Important for Google Fonts
        'connect-src': ['\'self\'', 'http://localhost:28080', KEYCLOAK_URL],
    }

    # Initialize Talisman to enforce HTTPS and apply security headers including the CSP
    Talisman(
        current_app,
        content_security_policy=csp,
        force_https=FORCE_HTTPS
    )
    # Enable CORS for all routes and origins
    CORS(current_app)


# --- Monitoring Configuration ---
def configure_monitoring(current_app: Flask) -> PrometheusMetrics:
    """Configure Prometheus monitoring for the Flask application.

    This function initializes Prometheus metrics for an application factory.
    It performs the following actions:
      - Creates a PrometheusMetrics instance using the application factory method.
      - Initializes the metrics with the provided Flask application.
      - Sets application-specific info metrics (such as application name and version).

    Args:
        current_app (Flask): The Flask application instance to configure.

    Returns:
        PrometheusMetrics: A configured PrometheusMetrics object that is attached
        to the app for monitoring.
    """
    prometheus_metrics = PrometheusMetrics.for_app_factory()
    prometheus_metrics.init_app(current_app)
    prometheus_metrics.info(APP_INFO_METRICS, NAME, version=VERSION)
    return prometheus_metrics


# --- Swagger Configuration ---
def configure_swagger(current_app: Flask) -> None:
    """
    Configures Swagger UI for API documentation in the Flask application.

    This function initializes and configures Swagger UI to provide interactive
    API documentation based on the application's routes and docstrings. It sets up
    the necessary configuration for Swagger to generate and display API documentation.

    Args:
        current_app (Flask): The Flask application instance to configure.

    Returns:
        None: This function modifies the Flask application in place and does not return a value.
    """
    # Set the custom Encoder (Inherit it if you need to customize)
    current_app.json_encoder = LazyJSONEncoder

    # Customize Swagger default configurations (important: define before Talisman)
    swagger_config = {
        'openapi': "3.0.2",
        'title': NAME,
        'headers': [
            ('Access-Control-Allow-Origin', '*'),
            (
                'Access-Control-Allow-Methods',
                'GET, POST, PUT, DELETE, OPTIONS'
            ),
            ('Access-Control-Allow-Credentials', 'true'),
            (
                'Cache-Control',
                'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            ),
            ('Pragma', 'no-cache'),
            ('Expires', '-1'),
        ],
        'specs': [
            {
                'version': VERSION,
                'title': 'Api v1',
                'endpoint': 'v1_spec',
                'description': 'This is the version 1 of Account REST API',
                'route': '/v1/spec',
                'rule_filter': lambda rule: True,  # all in
                'model_filter': lambda tag: True,  # all in
            }
        ],
        'static_url_path': '/flasgger_static',  # Must be defined
        'swagger_ui': True,
        'specs_route': '/apidocs/',
        'components': {
            'securitySchemes': {
                'oauth2': {
                    'type': 'oauth2',
                    'flows': {
                        'authorizationCode': {
                            'authorizationUrl':
                                f"http://localhost:28080/realms/{KEYCLOAK_REALM}"
                                f"/protocol/openid-connect/auth",
                            'tokenUrl':
                                f"http://localhost:28080/realms/{KEYCLOAK_REALM}"
                                f"/protocol/openid-connect/token",
                            'scopes': {
                                'openid': 'openid',
                                'profile': 'profile',
                                'email': 'email',
                                'offline_access': 'offline_access'
                            }
                        }
                    }
                }
            },
            'schemas': {
                'HealthDTO': {
                    'type': 'object',
                    'properties': {
                        'status': {
                            'type': 'string',
                            'description': 'Health status'
                        }
                    },
                    'required': ['status']
                },
                'AccountDTO': {
                    'type': 'object',
                    'properties': {
                        'id': {
                            'type': 'string',
                            'format': 'uuid',
                            'description': 'The account ID'
                        },
                        'name': {
                            'type': 'string',
                            'description': 'The account name',
                            'minLength': NAME_MIN_LENGTH,
                            'maxLength': NAME_MAX_LENGTH
                        },
                        'email': {
                            'type': 'string',
                            'format': 'email',
                            'description': 'The account email address'
                        },
                        'gender': {
                            'type': 'string',
                            'enum': ['male', 'female', 'other'],
                            'description': 'Gender of the account holder',
                            'maxLength': GENDER_MAX_LENGTH
                        },
                        'address': {
                            'type': 'string',
                            'description': 'The account address',
                            'maxLength': ADDRESS_MAX_LENGTH
                        },
                        'phone_number': {
                            'type': 'string',
                            'description': 'The account phone number',
                            'maxLength': PHONE_MAX_LENGTH
                        },
                        'date_joined': {
                            'type': 'string',
                            'format': 'date',
                            'description': 'The date the account was created (ISO 8601 format)'
                        },
                        'user_id': {
                            'type': 'string',
                            'format': 'uuid',
                            'description': 'The user ID'
                        },
                    },
                    'required': ['id', 'name', 'email', 'date_joined']
                },
                'CreateAccountDTO': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'The account name',
                            'minLength': NAME_MIN_LENGTH,
                            'maxLength': NAME_MAX_LENGTH
                        },
                        'email': {
                            'type': 'string',
                            'format': 'email',
                            'description': 'The account email address'
                        },
                        'gender': {
                            'type': 'string',
                            'enum': ['male', 'female', 'other'],
                            'description': 'Gender of the account holder',
                            'maxLength': GENDER_MAX_LENGTH
                        },
                        'address': {
                            'type': 'string',
                            'description': 'The account address',
                            'maxLength': ADDRESS_MAX_LENGTH
                        },
                        'phone_number': {
                            'type': 'string',
                            'description': 'The account phone number',
                            'maxLength': PHONE_MAX_LENGTH
                        }
                    },
                    'required': ['name', 'email']
                },
                'UpdateAccountDTO': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'The account name',
                            'minLength': NAME_MIN_LENGTH,
                            'maxLength': NAME_MAX_LENGTH
                        },
                        'email': {
                            'type': 'string',
                            'format': 'email',
                            'description': 'The account email address'
                        },
                        'gender': {
                            'type': 'string',
                            'enum': ['male', 'female', 'other'],
                            'description': 'Gender of the account holder',
                            'maxLength': GENDER_MAX_LENGTH
                        },
                        'address': {
                            'type': 'string',
                            'description': 'The account address',
                            'maxLength': ADDRESS_MAX_LENGTH
                        },
                        'phone_number': {
                            'type': 'string',
                            'description': 'The account phone number',
                            'maxLength': PHONE_MAX_LENGTH
                        }
                    },
                    'required': ['name', 'email']
                },
                'PartialUpdateAccountDTO': {
                    'type': 'object',
                    'properties': {
                        'name': {
                            'type': 'string',
                            'description': 'The account name',
                            'minLength': NAME_MIN_LENGTH,
                            'maxLength': NAME_MAX_LENGTH
                        },
                        'email': {
                            'type': 'string',
                            'format': 'email',
                            'description': 'The account email address'
                        },
                        'gender': {
                            'type': 'string',
                            'enum': ['male', 'female', 'other'],
                            'description': 'Gender of the account holder',
                            'maxLength': GENDER_MAX_LENGTH
                        },
                        'address': {
                            'type': 'string',
                            'description': 'The account address',
                            'maxLength': ADDRESS_MAX_LENGTH
                        },
                        'phone_number': {
                            'type': 'string',
                            'description': 'The account phone number',
                            'maxLength': PHONE_MAX_LENGTH
                        }
                    }
                },
                'ListOfAccountDTO': {
                    'type': 'object',
                    'properties': {
                        'items': {
                            'type': 'array',
                            'items': {
                                '$ref': '#/components/schemas/AccountDTO'
                            }
                        },
                        'page': {
                            'type': 'integer',
                            'description': 'Current page number',
                            'example': 1,
                            'format': 'int32'
                        },
                        'per_page': {
                            'type': 'integer',
                            'description': 'Number of items per page',
                            'example': 5,
                            'format': 'int32'
                        },
                        'total': {
                            'type': 'integer',
                            'description': 'Total number of entries',
                            'example': 1,
                            'format': 'int32'
                        }
                    }
                }
            }
        },
        'swaggerUiConfig': {
            'oauth2': {
                'clientId': KEYCLOAK_CLIENT_ID,
                'clientSecret': KEYCLOAK_SECRET,
                'defaultScopes': [
                    'openid', 'profile', 'email', 'offline_access'
                ],
            }
        }
    }

    # Initializing Swagger with default data
    swagger_template = dict(
        # if Swagger is behind a reverse proxy
        swaggerUiPrefix=LazyString(
            lambda: request.environ.get('HTTP_X_SCRIPT_NAME', '')
        ),
        info={
            'title': LazyString(lambda: NAME),
            'version': LazyString(lambda: VERSION),
            'description': LazyString(
                lambda: "The core purpose of the **Account** cloud-native "
                        "microservice is to handle the **CRUD** (Create, "
                        "Read, Update, Delete) operations for **Account** "
                        "objects. It provides endpoints for creating new "
                        "accounts, listing all accounts, retrieving a "
                        "specific account by ID, updating an account, "
                        "partially updating an account, and deleting an account.</br></br>"
                        "The following test users are available in the "
                        "Keycloak IAM development/testing realm **cba-dev**.</br>"
                        "<table><thead><tr><th>user name</th><th>password</th><th>roles"
                        "</th></tr></thead><tbody><tr><td>admin</td><td>admin</td>"
                        "<td>__ROLE_ADMIN__, __ROLE_USER__</td></tr><tr><td>test</td>"
                        "<td>test</td><td>__ROLE_USER__</td></tr></tbody></table>"
            ),
            'contact': {
                'responsibleOrganization': LazyString(lambda: 'ME'),
                'responsibleDeveloper': LazyString(lambda: 'ME'),
                'email': LazyString(lambda: 'me@me.com'),
                'url': LazyString(lambda: 'www.account.com')
            },
            # 'termsOfService': LazyString(lambda: '/there_is_no_tos')
        },
        host=LazyString(lambda: request.host),
        schemes=[LazyString(lambda: 'https' if request.is_secure else 'http')]
    )

    # Set the config even if Swagger is disabled
    current_app.config['SWAGGER'] = swagger_config

    Swagger(
        current_app,
        template=swagger_template,
        sanitizer=MK_SANITIZER
    )


# --- JWT Configuration ---
def configure_jwt(current_app: Flask) -> None:
    """
    Configures Flask-JWT-Extended for JWT authentication with Keycloak.

    This function sets up Flask-JWT-Extended to validate JWTs issued by Keycloak.
    It retrieves the Keycloak public key from the Keycloak server and configures
    the Flask application to use it for JWT verification.

    Args:
        current_app (Flask): The Flask application instance to configure.

    Returns:
        None: This function modifies the Flask application in place and does not return a value.
    """
    env = os.environ.get('APP_SETTINGS')
    if env == 'docker':
        logging.debug(
            'Running in development mode; retrying Keycloak certificate retrieval.'
        )
        certificate = get_keycloak_certificate_with_retry(max_retries=50)
    else:
        logging.debug(
            'Running in production or testing mode; infrastructure is ready, '
            'retrieving Keycloak certificate once.'
        )
        certificate = get_keycloak_certificate()

    if certificate:
        logger.debug('Retrieved Keycloak certificate successfully.')
        current_app.config['JWT_PUBLIC_KEY'] = certificate
        current_app.config['JWT_ALGORITHM'] = 'RS256'
        current_app.config['JWT_TOKEN_LOCATION'] = ['headers']
        current_app.config['JWT_HEADER_NAME'] = AUTHORIZATION_HEADER
        current_app.config['JWT_HEADER_TYPE'] = BEARER_HEADER
        JWTManager(current_app)
        logger.debug(
            'Flask-JWT-Extended configured successfully.'
        )
    else:
        logger.error(
            'Failed to retrieve Keycloak certificate. JWT configuration skipped.'
        )


# --- Cache Configuration ---
def configure_cache(current_app: Flask) -> Cache:
    """Configures caching for the Flask application using Redis.

    This function sets up the Flask-Caching extension with Redis as the
    backend, using configuration values from the application's config.

    Args:
        current_app (Flask): The Flask application instance to configure.

    Returns:
        Cache: The initialized Cache instance.
    """
    current_app.config['CACHE_TYPE'] = CACHE_TYPE
    current_app.config['CACHE_REDIS_HOST'] = CACHE_REDIS_HOST
    current_app.config['CACHE_REDIS_PORT'] = CACHE_REDIS_PORT
    current_app.config['CACHE_REDIS_DB'] = CACHE_REDIS_DB
    current_app.config[
        'CACHE_REDIS_URL'
    ] = f"redis://{CACHE_REDIS_HOST}:{CACHE_REDIS_PORT}/{CACHE_REDIS_DB}"

    # Initialize Flask-Caching with Redis
    return Cache(current_app)


# --- Audit Configuration ---
def configure_audit(current_app: Flask) -> None:
    """Configures and initializes the audit logging system for the Flask app.

    Reads configuration from environment variables (with defaults), sets up
    a KafkaProducerManager, an AuditLogger, and a FlaskAuditAdapter if
    audit logging is enabled via the AUDIT_ENABLED environment variable.

    If AUDIT_ENABLED is not 'true' (case-insensitive), this function logs
    an informational message and returns early, ensuring audit components
    on `current_app` are None.

    If initialization fails at any step (e.g., Kafka connection issues,
    missing dependencies, configuration errors), it logs an error, disables
    audit logging by setting `current_app.config['AUDIT_ENABLED'] = False`,
    and cleans up partially initialized components on `current_app`.

    Args:
         current_app (Flask): The Flask application instance to configure.
    """
    bootstrap_servers_str = os.environ.get(
        'KAFKA_AUDIT_BOOTSTRAP_SERVERS',
        'kafka:9093'
    )
    current_app.config["KAFKA_AUDIT_BOOTSTRAP_SERVERS"] = [
        s.strip() for s in bootstrap_servers_str.split(',') if s.strip()
    ] if bootstrap_servers_str else []
    current_app.config["KAFKA_AUDIT_TOPIC"] = os.environ.get(
        'KAFKA_AUDIT_TOPIC',
        'audit-events'
    )
    current_app.config["KAFKA_AUDIT_ACKS"] = get_int_from_env(
        'KAFKA_AUDIT_ACKS',
        1
    )
    current_app.config["KAFKA_AUDIT_RETRIES"] = get_int_from_env(
        'KAFKA_AUDIT_RETRIES',
        5
    )
    current_app.config["KAFKA_AUDIT_LINGER_MS"] = get_int_from_env(
        'KAFKA_AUDIT_LINGER_MS',
        100
    )
    current_app.config["KAFKA_AUDIT_BATCH_SIZE"] = get_int_from_env(
        'KAFKA_AUDIT_BATCH_SIZE',
        16384
    )
    current_app.config["KAFKA_AUDIT_COMPRESSION"] = os.environ.get(
        'KAFKA_AUDIT_COMPRESSION',
        'gzip'
    )
    current_app.config[
        "KAFKA_AUDIT_HEALTH_CHECK_INTERVAL"] = get_int_from_env(
        'KAFKA_AUDIT_HEALTH_CHECK_INTERVAL',
        60
    )

    try:
        # pylint: disable=C0415
        from cba_core_lib.audit.configs import AuditConfig
        from cba_core_lib.audit.adapters import FlaskAuditAdapter
        from cba_core_lib.audit.core import AuditLogger
        from cba_core_lib.kafka.configs import KafkaProducerConfig
        from cba_core_lib.kafka.producer import KafkaProducerManager
        from cba_core_lib.kafka.utils import (
            safe_string_serializer,
            safe_json_serializer,
        )
    except ImportError as err:
        logger.exception(
            "Failed to import required audit/Kafka library components. "
            "Disabling audit logging. Error: %s",
            err
        )
        current_app.config['AUDIT_ENABLED'] = False
        return

    try:
        kafka_producer_config = KafkaProducerConfig(
            bootstrap_servers=current_app.config[
                'KAFKA_AUDIT_BOOTSTRAP_SERVERS'
            ],
            acks=current_app.config['KAFKA_AUDIT_ACKS'],
            retries=current_app.config['KAFKA_AUDIT_RETRIES'],
            linger_ms=current_app.config['KAFKA_AUDIT_LINGER_MS'],
            batch_size=current_app.config['KAFKA_AUDIT_BATCH_SIZE'],
            compression_type=current_app.config['KAFKA_AUDIT_COMPRESSION'],
            health_check_interval=current_app.config[
                'KAFKA_AUDIT_HEALTH_CHECK_INTERVAL'
            ],
        )

        # Instantiate and attach the Kafka producer manager (Audit)
        current_app.audit_producer_manager = KafkaProducerManager(
            config=kafka_producer_config,
            key_serializer=safe_string_serializer,
            value_serializer=safe_json_serializer
        )
        logger.info(
            "KafkaProducerManager for Audit initialized, "
            "target servers: %s.",
            kafka_producer_config.bootstrap_servers
        )

        # Create Audit Configuration
        audit_config = AuditConfig(
            audit_topic=current_app.config['KAFKA_AUDIT_TOPIC'],
            event_source=NAME,
            user_identifier_func=get_current_user_id,
        )

        # Create the core Audit Logger
        audit_logger = AuditLogger(
            config=audit_config,
            producer_manager=current_app.audit_producer_manager
        )
        logger.info(
            "AuditLogger initialized (Topic: '%s', Source: '%s').",
            audit_config.audit_topic,
            audit_config.event_source
        )

        # Create and attach the Flask Adapter
        flask_adapter = FlaskAuditAdapter(audit_logger)
        current_app.flask_audit_adapter = flask_adapter
        logger.info(
            'FlaskAuditAdapter initialized and attached successfully.'
        )

    except Exception as err:  # pylint: disable=W0703
        logger.exception(
            "Failed to initialize audit components "
            "(Kafka/AuditLogger/Adapter). Disabling audit logging. "
            "Error: %s", err
        )
        current_app.config['AUDIT_ENABLED'] = False

        if hasattr(
                current_app,
                'audit_producer_manager'
        ) and current_app.audit_producer_manager:
            try:
                if hasattr(
                        current_app.audit_producer_manager,
                        'shutdown'
                ):
                    current_app.audit_producer_manager.shutdown()
                logger.info(
                    'Complete termination of the KafkaProducerManager (Audit).'
                )
            except Exception as close_err:  # pylint: disable=W0703
                logger.error(
                    "Error during KafkaProducerManager (Audit) shutdown: %s",
                    close_err
                )

        current_app.audit_producer_manager = None
        current_app.flask_audit_adapter = None


# --- Flask Application Setup ---
def create_app() -> Flask:
    """
    Creates and configures a Flask application instance.

    This factory function initializes a Flask application, applies configuration
    settings from the specified configuration object, and returns the configured
    application.

    Returns:
        Flask: A configured Flask application instance.
    """
    current_app = Flask(__name__)

    # Configure app.logger
    init_logging(current_app.logger, log_level=app_config.log_level)

    # Configure app settings
    current_app.config.from_object(app_config)
    current_app.config['SQLALCHEMY_DATABASE_URI'] = \
        app_config.sqlalchemy_database_uri
    current_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = \
        app_config.sqlalchemy_track_modifications

    # Define a shutdown handler that captures the current_app via closure.
    def shutdown_handler(
            signum: int,
            frame: Optional[FrameType]
    ) -> None:
        """Handles SIGTERM/SIGINT signals for graceful shutdown.

        Logs the shutdown event and attempts to close both the Kafka Consumer
        and the Kafka Producer (for auditing) associated with the Flask app.

        Args:
            signum: The signal number that triggered the handler.
            frame: The current stack frame (optional).
        """
        logger.info(
            'Application shutting down. Signal received: %s, '
            'Frame: %s. Attempting graceful shutdown of Kafka resources...',
            signum,
            frame
        )

        # --- Shutdown Kafka Consumer ---
        try:
            consumer_manager = getattr(
                current_app,
                'kafka_consumer_manager',
                None
            )
            if consumer_manager:
                logger.info('Shutdown KafkaConsumerManager...')
                consumer_manager.shutdown()
                logger.info('KafkaConsumerManager closed successfully.')
            else:
                logger.info(
                    'KafkaConsumerManager not found on app context, '
                    'skipping closure.'
                )

        except Exception as err:  # pylint: disable=W0703
            # pylint: disable=R0801
            logger.error(
                'Error shutting down KafkaConsumerManager: %s',
                err,
                exc_info=True
            )

        # Close Kafka Producer (for Audit)
        try:
            audit_producer_manager = getattr(
                current_app,
                'audit_producer_manager',
                None
            )
            if audit_producer_manager:
                logger.info('Shutdown KafkaProducerManager (Audit)...')
                audit_producer_manager.shutdown()
                logger.info(
                    'KafkaProducerManager (Audit) closed successfully.'
                )
            else:
                logger.info(
                    'KafkaProducerManager (Audit) not found on app context, '
                    'skipping closure.'
                )

        except Exception as err:  # pylint: disable=W0703
            logger.error(
                'Error shutting down KafkaProducerManager (Audit): %s',
                err,
                exc_info=True
            )

        logger.info('Graceful shutdown sequence finished.')
        # pylint: disable=R0801
        sys.exit(0)

    # Register shutdown_app as the handler for SIGTERM and SIGINT.
    # pylint: disable=R0801
    signal.signal(
        signal.SIGTERM,
        shutdown_handler
    )  # For Docker shutdown signals (or other system signals)
    signal.signal(
        signal.SIGINT,
        shutdown_handler
    )  # For keyboard interrupts (Ctrl+C)

    # Configure Security and Monitoring
    configure_security(current_app)

    # Initialize Swagger documentation if enabled
    # Conditionally initialize Swagger
    if SWAGGER_ENABLED:
        configure_swagger(current_app)
        current_app.logger.info('Swagger UI is enabled.')
    else:
        current_app.logger.info('Swagger UI is disabled.')

    # Configure JWT with Keycloak public certificate
    configure_jwt(current_app)

    # Conditionally initialize Audit
    current_app.config["AUDIT_ENABLED"] = AUDIT_ENABLED
    if current_app.config["AUDIT_ENABLED"]:
        configure_audit(current_app)
        current_app.logger.info('Audit is enabled.')
    else:
        current_app.logger.info('Audit is disabled.')

    # Instantiate the KafkaConsumerManager
    kafka_consumer_manager = get_kafka_consumer_manager()
    # Attach the manager to the app instance
    current_app.kafka_consumer_manager = kafka_consumer_manager

    # Record the application start time before handling the first request
    @current_app.before_first_request
    def startup() -> None:
        """Records the application's start time.

        This function is executed only once, before the first request is
        handled. It records the current time as the application's start time,
        which can then be used to calculate uptime.
        """
        current_app.start_time = datetime.datetime.now()
        current_app.logger.info(
            'Account microservice starting up with KafkaConsumerManager active...'
        )

    current_app.logger.info(70 * '*')
    current_app.logger.info(
        "  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, '*')
    )
    current_app.logger.info(70 * '*')

    return current_app


# --- Application Initialization ---

app = create_app()

# Registering error handlers
# pylint:disable=C0413
from service.common.error_handlers import register_error_handlers

register_error_handlers(app)

# Configure monitoring with Prometheus
metrics = configure_monitoring(app)

# Configure cache with Redis
cache = configure_cache(app)

# pylint:disable=C0413
from service.common.utils import is_flask_cli_alternative
# pylint:disable=C0413
from service import models

if not is_flask_cli_alternative():
    # Import the routes After the Flask app is created
    # pylint: disable=wrong-import-position, cyclic-import, wrong-import-order
    from service import routes  # noqa: F401 E402

try:
    models.init_db(app)  # make our database tables
except Exception as error:  # pylint: disable=broad-except
    app.logger.critical("%s: Cannot continue", error)
    # gunicorn requires exit code 4 to stop spawning workers when they die
    sys.exit(4)

app.logger.info('Service initialized!')

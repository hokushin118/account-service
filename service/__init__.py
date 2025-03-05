"""
Package: service
Package for the application models and service routes
This module creates and configures the Flask app and sets up the logging
and SQL database
"""
import datetime
import logging
import os
import sys

from dotenv import load_dotenv
from flasgger import Swagger, LazyString, LazyJSONEncoder, MK_SANITIZER
from flask import Flask, request
from flask_caching import Cache
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_talisman import Talisman
from prometheus_flask_exporter import PrometheusMetrics

from service import config
from service.common import log_handlers
from service.common.constants import (
    NAME_MAX_LENGTH,
    NAME_MIN_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH,
    AUTHORIZATION_HEADER,
    BEARER_HEADER
)
from service.common.keycloak_utils import (
    KEYCLOAK_URL,
    KEYCLOAK_REALM,
    get_keycloak_certificate,
    get_keycloak_certificate_with_retry
)

logger = logging.getLogger(__name__)


# --- Configuration and Environment Setup ---

def load_environment_variables() -> None:
    """
    Loads environment variables from a .env file into the operating system's environment.

    This function uses the `dotenv` library to load key-value pairs from a
    .env file located in the current working directory and sets them as
    environment variables. This allows the application to access configuration
    settings without hardcoding them in the source code.

    Returns:
        None: This function modifies the operating system's environment and does not return a value.
    """
    # Load the correct .env file based on APP_SETTINGS
    # export APP_SETTINGS=docker  # Or production, etc.
    env = os.environ.get('APP_SETTINGS')
    logging.debug("Environment variables: %s", env)
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

# Retrieving Information (Environment Variables Example):
# This is a common way to manage configuration, especially in containerized environments.
VERSION = os.environ.get('VERSION', '0.0.1')  # Default if not set
NAME = os.environ.get('NAME', 'account-service')
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'
SWAGGER_ENABLED = os.environ.get('SWAGGER_ENABLED', 'false').lower() == 'true'
CACHE_TYPE = os.environ.get('CACHE_TYPE', 'redis')
CACHE_REDIS_HOST = os.environ.get('CACHE_REDIS_HOST', 'localhost')
CACHE_REDIS_PORT = int(os.environ.get('CACHE_REDIS_PORT', 6379))
CACHE_REDIS_DB = int(os.environ.get('CACHE_REDIS_DB', 0))


# --- Security and Monitoring ---
def configure_security(current_app: Flask) -> None:
    """
    Configures security and monitoring for the Flask application.

    This function sets up various security measures and monitoring tools for the
    Flask application. This may include, but is not limited to, configuring
    security headers, enabling rate limiting, setting up logging, and integrating
    with monitoring services.

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
        'connect-src': ['\'self\''],
    }

    # Enable Talisman
    Talisman(
        current_app,
        content_security_policy=csp,
        force_https=FORCE_HTTPS
    )
    # Enable CORS for all routes and origins
    CORS(current_app)
    # initialize Prometheus metrics
    metrics = PrometheusMetrics.for_app_factory()
    metrics.init_app(current_app)


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
        'openapi': "3.0.3",
        'title': NAME,
        'headers': [
            ('Access-Control-Allow-Origin', '*'),
            (
                'Access-Control-Allow-Methods',
                'GET, POST, PUT, DELETE, OPTIONS'
            ),
            ('Access-Control-Allow-Credentials', 'true'),
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
        'securityDefinitions': {  # If you use authentication
            'bearerAuth': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'Authorization',
                'description': 'JWT Authorization header'
            }
        },
        'components': {
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
                    },
                    'required': ['id', 'name', 'email', 'date_joined']
                },
                'CreateUpdateAccountDTO': {
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
                    },
                    'required': ['name', 'email', 'date_joined']
                },
                'ListOfAccountDTO': {
                    'type': 'array',
                    'items': {
                        '$ref': '#/components/schemas/AccountDTO'
                    }
                }
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
                        "partially updating an account, and deleting an account."),
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
    """
    Configures caching for the Flask application using Redis.

    This function sets up the Flask-Caching extension with Redis as the backend,
    using configuration values from the application's config.

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
    redis_cache = Cache(current_app)
    redis_cache.init_app(current_app)
    return redis_cache


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
    current_app.config.from_object(config)

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

    # Record the application start time before handling the first request
    @current_app.before_first_request
    def before_first_request() -> None:
        """Records the application's start time.

        This function is executed only once, before the first request is
        handled. It records the current time as the application's start time,
        which can then be used to calculate uptime.
        """
        current_app.start_time = datetime.datetime.now()

    # Set up logging for production
    log_handlers.init_logging(current_app, 'gunicorn.error')

    current_app.logger.info(70 * '*')
    current_app.logger.info(
        "  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, '*')
    )
    current_app.logger.info(70 * '*')

    return current_app


# --- Application Initialization ---

app = create_app()

# Configure cache with Redis
cache = configure_cache(app)

# Import the routes After the Flask app is created
# pylint: disable=wrong-import-position, cyclic-import, wrong-import-order
from service import routes, models  # noqa: F401 E402

try:
    models.init_db(app)  # make our database tables
except Exception as error:  # pylint: disable=broad-except
    app.logger.critical("%s: Cannot continue", error)
    # gunicorn requires exit code 4 to stop spawning workers when they die
    sys.exit(4)

app.logger.info('Service initialized!')

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
from flask_cors import CORS
from flask_talisman import Talisman

logger = logging.getLogger('account-service')

# Load the correct .env file based on FLASK_ENV
# export FLASK_ENV=docker  # Or production, etc.
env = os.environ.get('FLASK_ENV').strip()

if not env:
    dotenv_path = os.path.join(
        os.path.dirname(__file__),
        '.env'
    )  # Path to .env
else:
    dotenv_path = os.path.join(
        os.path.dirname(__file__),
        f'.env.{env}'
    )  # Path to .env.{env}

try:
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)
except FileNotFoundError as error:
    logging.error("Dotenv file not found: %s: %s", dotenv_path, error)
except UnicodeDecodeError as error:
    logging.error("Encoding error in dotenv file: %s: %s", dotenv_path, error)
except OSError as error:
    logging.error("OS error reading dotenv file: %s: %s", dotenv_path, error)
except SyntaxError as error:
    logging.error("Syntax error in dotenv file: %s: %s", dotenv_path, error)
except TypeError as error:
    logging.error(
        "Type error while loading dotenv file: %s: %s", dotenv_path,
        error
    )

# Retrieving Information (Environment Variables Example):
# This is a common way to manage configuration, especially in containerized environments.
VERSION = os.environ.get('VERSION', '0.0.1')  # Default if not set
NAME = os.environ.get('NAME')
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'
SWAGGER_ENABLED = os.environ.get('SWAGGER_ENABLED', 'false').lower() == 'true'

# pylint: disable=wrong-import-position
from flask import Flask, request
from prometheus_flask_exporter import PrometheusMetrics

# pylint: disable=wrong-import-position
from service.common import log_handlers
from service.common.constants import (
    NAME_MAX_LENGTH,
    NAME_MIN_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH
)

# Create Flask application
app = Flask(__name__)

# Import the routes After the Flask app is created
# pylint: disable=wrong-import-position, cyclic-import, wrong-import-order
from service import routes, config, models  # noqa: F401 E402

app.config.from_object(config)

# Define your CSP (adjust as needed for your application)
# Allow inline styles (often needed by Swagger UI) and CDNs
# Add Google Fonts
# Add any CDNs needed by your app
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
    'style-src': ['\'self\'', '\'unsafe-inline\'', 'https://cdn.jsdelivr.net',
                  'https://fonts.googleapis.com'],
    'img-src': ["'self'", "data:"],
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],
    # Important for Google Fonts
    'connect-src': ['\'self\''],
}

# Enable Talisman
talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=FORCE_HTTPS
)
# Enable CORS for all routes and origins
cors = CORS(app)
# initialize PrometheusMetrics
metrics = PrometheusMetrics.for_app_factory()
metrics.init_app(app)

# Set the custom Encoder (Inherit it if you need to customize)
app.json_encoder = LazyJSONEncoder

# Customize Swagger default configurations (important: define before Talisman)
swagger_config = {
    'openapi': "3.0.3",
    'title': NAME,
    'headers': [
        ('Access-Control-Allow-Origin', '*'),
        ('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS'),
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
                        'type': 'integer',
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
app.config['SWAGGER'] = swagger_config

# Conditionally initialize Swagger
if SWAGGER_ENABLED:
    swagger = Swagger(app, template=swagger_template, sanitizer=MK_SANITIZER)
    app.logger.info('Swagger UI is enabled.')
else:
    app.logger.info('Swagger UI is disabled.')


@app.before_first_request
def before_first_request() -> None:
    """Records the application's start time.

    This function is executed only once, before the first request is
    handled. It records the current time as the application's start time,
    which can then be used to calculate uptime.
    """
    app.start_time = datetime.datetime.now()


# Set up logging for production
log_handlers.init_logging(app, 'gunicorn.error')

app.logger.info(70 * '*')
app.logger.info(
    "  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, '*'))
app.logger.info(70 * '*')

try:
    models.init_db(app)  # make our database tables
except Exception as error:  # pylint: disable=broad-except
    app.logger.critical("%s: Cannot continue", error)
    # gunicorn requires exit code 4 to stop spawning workers when they die
    sys.exit(4)

app.logger.info('Service initialized!')

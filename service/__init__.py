"""
Package: service
Package for the application models and service routes
This module creates and configures the Flask app and sets up the logging
and SQL database
"""
import datetime
import os

from dotenv import load_dotenv

# Load the correct .env file based on FLASK_ENV
env = os.getenv('FLASK_ENV')

# Retrieving Information (Environment Variables Example):
# This is a common way to manage configuration, especially in containerized environments.
VERSION = os.environ.get('VERSION', '0.0.1')  # Default if not set
NAME = os.environ.get('NAME')

if env == 'development':
    load_dotenv('.env.development')
elif env == 'testing':
    load_dotenv('.env.testing')
else:  # Production or default
    load_dotenv()  # Loads .env in the current directory

# pylint: disable=wrong-import-position
from flask import Flask

# pylint: disable=wrong-import-position
from service.common import log_handlers

# Create Flask application
app = Flask(__name__)

# Import the routes After the Flask app is created
# pylint: disable=wrong-import-position, cyclic-import, wrong-import-order
from service import routes  # noqa: F401 E402


@app.before_first_request
def before_first_request():
    """
    Record the start time
    :return: None
    """
    app.start_time = datetime.datetime.now()


# Set up logging for production
log_handlers.init_logging(app, 'gunicorn.error')

app.logger.info(70 * '*')
app.logger.info(
    "  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, '*'))
app.logger.info(70 * '*')

app.logger.info('Service initialized!')

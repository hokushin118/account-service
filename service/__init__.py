"""
Package: service
Package for the application models and service routes
This module creates and configures the Flask app and sets up the logging
and SQL database
"""
from flask import Flask

# pylint: disable=wrong-import-position
from service.common import log_handlers

# Create Flask application
app = Flask(__name__)

# Set up logging for production
log_handlers.init_logging(app, "gunicorn.error")

app.logger.info(70 * "*")
app.logger.info("  A C C O U N T   S E R V I C E   R U N N I N G  ".center(70, "*"))
app.logger.info(70 * "*")

app.logger.info("Service initialized!")

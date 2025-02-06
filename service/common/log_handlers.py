"""
Log Handlers.

This module contains utility functions to set up logging
consistently.
"""
import logging

from flask import Flask


def init_logging(app: Flask, logger_name: str) -> None:
    """Sets up logging for production, integrating with Gunicorn if available.

    This function configures the Flask app's logger to propagate messages to
    the Gunicorn logger (if Gunicorn is being used).  It also sets a consistent
    log format.

    Args:
        app: The Flask application instance.
        logger_name: The name of the logger (e.g., "gunicorn.error").
    """
    app.logger.propagate = False  # Prevent duplicate logs
    gunicorn_logger = logging.getLogger(logger_name)
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    # Make all log formats consistent
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(module)s] %(message)s",
        "%Y-%m-%d %H:%M:%S %z"
    )
    for handler in app.logger.handlers:
        handler.setFormatter(formatter)
    app.logger.info('Logging handler established')

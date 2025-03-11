"""
Log Handlers.

This module contains utility functions to set up logging
consistently for containerized environments.
"""
import logging
import sys

from flask import Flask

# Constants for log formatting
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(pathname)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S %z"


def init_logging(app: Flask, log_level: int = logging.INFO) -> None:
    """Sets up logging for containerized environments (stdout/stderr).

    This method configures the Flask app's logger so that logs appear on
    stdout for INFO and lower-level messages and stderr for ERROR and CRITICAL
    messages. This separation enables container orchestrators (such as Docker or Kubernetes)
    to correctly capture and route log output. The log format includes timestamp, log level,
    module, and message for consistency.

    Args:
        app (Flask): The Flask application instance.
        log_level (int): The logging level to use (default: logging.INFO).
    """
    # Define a consistent log formatter
    formatter = logging.Formatter(
        LOG_FORMAT,
        LOG_DATE_FORMAT
    )

    # Configure logging to stdout for log_level and below, flush immediately
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(log_level)
    stdout_handler.setFormatter(formatter)
    stdout_handler.flush = sys.stdout.flush  # Ensure unbuffered writes

    # Configure logging to stderr for ERROR and CRITICAL messages
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)
    stderr_handler.flush = sys.stderr.flush  # Ensure immediate flush

    # Remove any existing handlers to ensure logs are not duplicated
    if app.logger.hasHandlers():
        app.logger.handlers.clear()
        app.logger.propagate = False

    # Add the new handlers to the app logger
    app.logger.addHandler(stdout_handler)
    app.logger.addHandler(stderr_handler)

    # Set the overall log level for the application logger
    app.logger.setLevel(log_level)
    app.logger.info(
        'Logging handler established for containerized environment.'
    )

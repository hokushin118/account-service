"""
Package: tests
Package for the application tests.
"""
import logging
import os
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
# pylint: disable=E0401
from sqlalchemy_utils import (
    database_exists,
    create_database
)

logger = logging.getLogger(__name__)

os.environ['APP_SETTINGS'] = 'testing'


def create_db_if_not_exists(database_uri: str) -> Optional[Engine]:
    """Create and return a SQLAlchemy Engine for the PostgreSQL database specified by the given URI.

    This function checks if the database exists, and if not, attempts to create it.
    If an OperationalError occurs indicating the database does not exist, it creates the database
    by connecting to the "postgres" maintenance database.

    Args:
        database_uri (str): The full database URI including the target database name.

    Returns:
        Optional[Engine]: A SQLAlchemy Engine instance for the target database if successful,
                          or None if creation or connection fails.
    """
    try:
        engine = create_engine(database_uri)
        if not database_exists(engine.url):
            create_database(engine.url)
        return engine
    except OperationalError as err:
        err_msg = str(err).lower()
        if "database does not exist" in err_msg:
            # Extract the database name from the URI
            db_name = database_uri.split("/")[-1]
            # Extract the URI without the database name
            base_uri = database_uri.rsplit("/", 1)[0]
            # Create a temporary engine without the database name
            # and connect to the postgres database to create a new database
            temp_engine = create_engine(f"{base_uri}/postgres")
            try:
                with temp_engine.connect() as conn:
                    conn.execute(f"CREATE DATABASE {db_name}")
                # return the engine that connects to the newly created database.
                return create_engine(database_uri)
            except Exception as creation_error:  # pylint: disable=W0703
                logger.error('Error creating database: %s', creation_error)
                return None
        else:
            logger.error("Operational error: %s", err)
            return None
    except Exception as err:  # pylint: disable=W0703
        logger.error("Error checking/creating database: %s", err)
        return None

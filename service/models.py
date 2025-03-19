"""
Models for Account

All the models are stored in this module
"""
import logging
import uuid
from datetime import date
from typing import Any, Dict, List, Optional

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import text, desc
from sqlalchemy.sql.sqltypes import TIMESTAMP

from service.common.constants import (
    NAME_MAX_LENGTH,
    ADDRESS_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    PHONE_MAX_LENGTH, GENDER_MAX_LENGTH
)
from service.common.utils import account_to_dict

logger = logging.getLogger(__name__)

# Create the SQLAlchemy object to be initialized later in init_db()
db = SQLAlchemy()


class DataValidationError(Exception):
    """Used for data validation errors during deserialization."""


def init_db(app: Flask) -> None:
    """Initializes the SQLAlchemy database.

    This function initializes the database by calling the init_db method of the
    Account model.

    Args:
        app: The Flask application instance.
    """
    Account.init_db(app)


######################################################################
#  P E R S I S T E N T   B A S E   M O D E L
######################################################################
class PersistentBase:
    """Base class for persistent models, providing common database methods."""

    def __init__(self):
        """Initializes a new object.

        The ID is initially set to None. It will be assigned by the database
        when the object is persisted.
        """
        self.id = None  # pylint: disable=invalid-name

    def create(self) -> 'PersistentBase':
        """Creates a new record in the database.

        This method adds the current object to the database session and attempts
        to commit the changes.  If an integrity error occurs (e.g., duplicate key),
        the session is rolled back, and a DataValidationError exception is raised.

        Returns:
            The created object (self).

        Raises:
            DataValidationError: If an error occurs during record creation, such as
                               an integrity error.
        """
        logger.info("Creating %s", self)
        db.session.add(self)
        try:
            db.session.commit()
            logger.debug("Successfully created %s", self)
        except IntegrityError as err:
            db.session.rollback()
            logger.error(
                "Integrity error during creation of %s: {%s}",
                self,
                err
            )
            raise DataValidationError(
                f"Integrity error creating record: {err}"
            ) from err
        except Exception as err:  # pylint: disable=W0703
            db.session.rollback()
            logger.error(
                "Unexpected error during creation of %s: %s",
                self,
                err
            )
            raise DataValidationError(
                f"Unexpected error creating record: {err}"
            ) from err
        return self

    def partial_update(self, data: Dict[str, Any]) -> None:
        """Partially updates the object with the given data.

        This method iterates through the provided data dictionary and updates
        the corresponding attributes of the Account object.  It raises a
        DataValidationError if the data is invalid (e.g., type mismatches,
        invalid attributes, attempts to update the primary key).

        Args:
            data: A dictionary containing the data to update.

        Returns:
            The updated Account object (self).

        Raises:
            DataValidationError: If the data is invalid.
        """
        logger.info("Partially updating %s", data)
        for key, value in data.items():
            if value is not None:
                # Check if attribute exists and is not the primary key
                if hasattr(self, key) and key != 'id':
                    try:
                        setattr(self, key, value)
                    except ValueError as error:  # Handle type mismatches
                        raise DataValidationError(
                            f"Invalid value for {key}: {error}"
                        ) from error
                elif key == 'id':
                    raise DataValidationError("Cannot update primary key 'id'")
                else:
                    raise DataValidationError(
                        f"Attribute '{key}' is not valid for Account"
                    )

    def update(self) -> 'PersistentBase':
        """Updates an existing record in the database.

        This method attempts to commit changes to the database. If an integrity
        error occurs (e.g., a foreign key constraint violation), the session is
        rolled back, and a DataValidationError is raised.

        Returns:
            The updated object (self).

        Raises:
            DataValidationError: If an error occurs during the update, such as an
                               integrity error.
        """
        logger.info("Updating %s", self)
        try:
            db.session.commit()
            logger.debug("Successfully updated %s", self)
        except IntegrityError as err:
            db.session.rollback()
            logger.error(
                "Integrity error during update of %s: {%s}",
                self,
                err
            )
            raise DataValidationError(
                f"Integrity error updating record: {err}"
            ) from err
        except Exception as err:  # pylint: disable=W0703
            db.session.rollback()
            logger.error(
                "Unexpected error during update of %s: %s",
                self,
                err
            )
            raise DataValidationError(
                f"Unexpected error updating record: {err}"
            ) from err
        return self

    def delete(self) -> 'PersistentBase':
        """Removes a record from the data store.

        This method deletes the current object from the database session and
        attempts to commit the change. If an integrity error occurs (e.g., a
        foreign key constraint violation), the session is rolled back, and a
        DataValidationError is raised.

        Returns:
            The deleted object (self).

        Raises:
            DataValidationError: If an error occurs during deletion, such as an
                               integrity error.
        """
        logger.info("Deleting %s", self)
        db.session.delete(self)
        try:
            db.session.commit()
            logger.debug("Successfully deleted %s", self)
        except IntegrityError as err:
            db.session.rollback()
            logger.error(
                "Integrity error during delete of %s: {%s}",
                self,
                err
            )
            raise DataValidationError(
                f"Integrity error deleting record: {err}"
            ) from err
        except Exception as err:  # pylint: disable=W0703
            db.session.rollback()
            logger.error(
                "Unexpected error during delete of %s: %s",
                self,
                err
            )
            raise DataValidationError(
                f"Unexpected error deleting record: {err}"
            ) from err
        return self

    @classmethod
    def init_db(cls, app: Flask) -> None:
        """Initializes the database.

        This class method initializes the SQLAlchemy database by associating it
        with the Flask application and creating all necessary tables.

        Args:
            app: The Flask application instance.
        """
        logger.info('Initializing database...')
        cls.app = app
        # This is where we initialize SQLAlchemy from the Flask app
        db.init_app(app)
        app.app_context().push()
        # db.create_all()  # make our sqlalchemy tables (use only if NOT using migrations)
        logger.info('Database initialized...')  # More concise message

    @classmethod
    def all(cls) -> List['PersistentBase']:
        """Retrieves all records from the database.

        Returns:
            A list of all records of this model type. Returns an empty list if
            no records are found.
        """
        logger.info('Retrieving all records...')
        return cls.query.all()

    @classmethod
    def all_paginated(
            cls,
            page: int = 1,
            per_page: int = 10
    ) -> List['PersistentBase']:
        """Retrieves all records from the database with pagination.

        Args:
            page: The page number (default: 1).
            per_page: The number of items per page (default: 10).

        Returns:
            A list of Account objects for the specified page.
        """
        logger.info(
            'Retrieving all records (page %d, per_page %d)...',
            page,
            per_page
        )
        paginated_accounts = cls.query.order_by(
            desc(
                cls.created_at
            )).paginate(
            page=page,
            per_page=per_page
        )
        return paginated_accounts.items

    @classmethod
    def find(cls, by_id: UUID) -> Optional['PersistentBase']:
        """Finds and returns a record by its ID.

        Args:
            by_id: The ID of the record to find.

        Returns:
            The record object if found, otherwise None.
        """
        logger.info("Finding record by ID: %s ...", by_id)
        return cls.query.get(by_id)


######################################################################
#  A C C O U N T   M O D E L
######################################################################
class Account(db.Model, PersistentBase):
    """
    Class that represents a User Account.
    """
    __tablename__ = 'accounts'  # Explicitly set the table name

    # Table Schema
    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        index=True,  # we are indexing for search optimization
        nullable=False,
        server_default=text('gen_random_uuid()')
    )
    created_at = db.Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now()  # pylint: disable=not-callable
    )
    updated_at = db.Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now()  # pylint: disable=not-callable
    )
    name = db.Column(
        db.String(NAME_MAX_LENGTH),
        nullable=False
    )
    email = db.Column(
        db.String(EMAIL_MAX_LENGTH),
        nullable=False,
        unique=True
    )
    gender = db.Column(
        db.String(GENDER_MAX_LENGTH),
        nullable=True
    )
    address = db.Column(
        db.String(ADDRESS_MAX_LENGTH)
    )
    phone_number = db.Column(
        db.String(PHONE_MAX_LENGTH)
    )
    date_joined = db.Column(
        db.Date(),
        nullable=False,
        default=date.today()
    )
    user_id = db.Column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        index=True
    )

    def __repr__(self) -> str:
        """Returns a string representation of the Account object.

        This representation is intended for debugging and logging purposes.
        It includes the account's name and ID.

        Returns:
            A string representation of the Account object.
        """
        return f"<Account {self.name} id=[{self.id}]>"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the Account object into a dictionary.

        This method uses the account_to_dict helper function to perform the
        serialization.

        Returns:
            A dictionary representation of the Account object.
        """
        return account_to_dict(self)

    def deserialize(self, data: Dict[str, Any]) -> 'Account':
        """Deserializes an Account object from a dictionary.

        Args:
            data: A dictionary containing the account data.

        Returns:
            The deserialized Account object (self).

        Raises:
            DataValidationError: If the data is invalid or missing required fields.
        """
        try:
            self.name = data['name']
            self.email = data['email']
            self.gender = data.get('gender')
            self.address = data.get('address')  # Address is optional
            self.phone_number = data.get('phone_number')
            user_id_data = data['user_id']
            if isinstance(user_id_data, uuid.UUID):
                self.user_id = user_id_data
            elif isinstance(user_id_data, str):
                self.user_id = uuid.UUID(user_id_data)
            else:
                raise DataValidationError(
                    'Invalid user_id format. Must be a UUID or string.'
                )
        except KeyError as error:
            raise DataValidationError(
                f"Invalid Account: missing {error.args[0]}"
            ) from error
        except (ValueError, TypeError) as error:
            raise DataValidationError(
                f"Invalid Account data: {error}"
            ) from error
        return self

    @classmethod
    def find_by_name(cls, name: str) -> List['Account']:
        """Finds and returns all Accounts with the given name.

        Args:
            name: The name to search for.

        Returns:
            A list of Account objects matching the given name.  Returns an empty
            list if no matching accounts are found.
        """
        logger.info("Finding accounts by name: %s ...", name)
        return cls.query.filter(cls.name == name).all()

    @classmethod
    def find_by_user_id(cls, user_id: uuid.UUID) -> Optional['Account']:
        """Finds and returns an Account by its user_id.

        Args:
            user_id: The user_id to search for.

        Returns:
            An Account object matching the given user_id, or None if not found.
        """
        logger.info("Finding account by user_id: %s ...", user_id)
        return cls.query.filter(cls.user_id == user_id).first()

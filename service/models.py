"""
Models for Account

All the models are stored in this module
"""
import logging
from datetime import date

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger('account-service')

# Create the SQLAlchemy object to be initialized later in init_db()
db = SQLAlchemy()


class DataValidationError(Exception):
    """Used for data validation errors during deserialization."""


def init_db(app):
    """Initializes the SQLAlchemy database."""
    Account.init_db(app)


######################################################################
#  P E R S I S T E N T   B A S E   M O D E L
######################################################################
class PersistentBase:
    """Base class for persistent models, providing common database methods."""

    def __init__(self):
        self.id = None  # pylint: disable=invalid-name

    def create(self):
        """Creates a new record in the database."""
        logger.info("Creating %s", self)
        db.session.add(self)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise DataValidationError(
                f"Error creating record: {error}"
            ) from error
        return self

    def partial_update(self, data):
        """Partially updates the Account object with the given data."""
        logger.info("Partially updating %s", data)
        for key, value in data.items():
            # Check if attribute exists and is not the primary key
            if hasattr(self,
                       key) and key != 'id':
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

    def update(self):
        """Updates an existing record in the database."""
        logger.info("Updating %s", self)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise DataValidationError(
                f"Error updating record: {error}"
            ) from error
        return self

    def delete(self):
        """Removes a record from the data store."""
        logger.info("Deleting %s", self)
        db.session.delete(self)
        try:
            db.session.commit()
        except IntegrityError as error:
            db.session.rollback()
            raise DataValidationError(
                f"Error deleting record: {error}"
            ) from error
        return self

    @classmethod
    def init_db(cls, app):
        """Initializes the database session."""
        logger.info('Initializing database...')
        cls.app = app
        # This is where we initialize SQLAlchemy from the Flask app
        db.init_app(app)
        app.app_context().push()
        db.create_all()  # make our sqlalchemy tables
        logger.info('Database initialized...')  # More concise message

    @classmethod
    def all(cls):
        """Returns all the records from the database."""
        logger.info('Retrieving all records...')
        return cls.query.all()

    @classmethod
    def find(cls, by_id):
        """Finds a record by its ID."""
        logger.info("Finding record by ID: %s ...", by_id)
        return cls.query.get(by_id)


######################################################################
#  A C C O U N T   M O D E L
######################################################################
class Account(db.Model, PersistentBase):
    """
    Class that represents a User Account.
    """

    app = None

    # Table Schema
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False, unique=True)
    address = db.Column(db.String(256))
    phone_number = db.Column(db.String(32))
    date_joined = db.Column(db.Date(), nullable=False, default=date.today())

    def __repr__(self):
        return f"<Account {self.name} id=[{self.id}]>"

    def serialize(self):
        """Serializes an Account into a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'address': self.address,
            'phone_number': self.phone_number,
            'date_joined': self.date_joined.isoformat()
        }

    def deserialize(self, data):
        """
        Deserializes an Account from a dictionary.

        Args:
            data (dict): A dictionary containing the resource data
        """
        try:
            self.name = data['name']
            self.email = data['email']
            self.address = data.get('address')  # Address is optional
            self.phone_number = data.get('phone_number')
            self.date_joined = date.fromisoformat(
                data.get('date_joined', date.today().isoformat())
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
    def find_by_name(cls, name):
        """Returns all Accounts with the given name.

        Args:
            name (string): the name of the Accounts you want to match
        """
        logger.info("Finding accounts by name: %s ...", name)
        return cls.query.filter(cls.name == name)

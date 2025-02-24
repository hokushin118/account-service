"""
Account service CLI.

Flask CLI Command Extensions.
"""
import logging

import click
from flask_migrate import Migrate  # pylint: disable=E0401

from service import app
from service.models import db

logger = logging.getLogger(__name__)

# Flask-Migrate exposes one class called Migrate.
# This class contains all the functionality of the extension
migrate = Migrate(app, db)


######################################################################
# Command to initialize migration
# Usage:
#   flask db-init
######################################################################
@app.cli.command('db-init')
def db_init() -> None:
    """Initializes the Flask-Migrate migration repository.

    This command sets up the necessary directory structure and files for managing
    database migrations using Flask-Migrate.  It creates the 'migrations'
    directory (if it doesn't exist) and initializes the Alembic environment.

    Usage:
        flask db-init

    Returns:
        None
    """
    # Import inside the function to avoid circular imports
    import flask_migrate  # pylint: disable=E0401, C0415

    with app.app_context():  # The crucial application context
        flask_migrate.init()


######################################################################
# Command to generate an initial migration
# Usage:
#   flask db-migrate -m "20250224 - Init message"
#   flask db-migrate --message "20250224 - Init message"
######################################################################
@app.cli.command('db-migrate')
@click.option(
    '-m', '--message',
    prompt='Enter migration message',
    help='Migration message'
)
def db_migrate(message: str) -> None:
    """Generates a new migration script.

    This command creates a new migration script based on the changes to your
    database models. The migration script captures the differences between
    the current state of your models and the previous state, allowing you to
    apply these changes to your database schema.

    Args:
        message (str): A descriptive message for the migration. This message
            should summarize the changes made to the models.

    Usage:
        flask db-migrate -m "20250224 - Init message"
        flask db-migrate --message "20250224 - Init message"

    Returns:
        None
    """
    import flask_migrate  # pylint: disable=E0401, C0415

    logger.debug(
        "Migration message: %s", message
    )

    with app.app_context():
        flask_migrate.migrate(message=message)


######################################################################
# Command to create a new database migration
# Usage:
#   flask db-revision -m "20250224 - Added comment field"
#   flask db-revision -m "20250224 - Added comment field" --autogenerate
#   flask db-revision --message "20250224 - Added comment field"
#   flask db-revision --message "20250224 - Added comment field" --autogenerate
######################################################################
@app.cli.command('db-revision')
@click.option(
    '-m', '--message',
    prompt='Enter migration message',
    help='Migration message'
)
@click.option(
    '--autogenerate',
    is_flag=True,
    help='Autogenerate the migration script'
)
def db_revision(message: str, autogenerate: bool = False) -> None:
    """Create a new migration script.

    This command generates a new revision script based on the current state of your
    database models.  You can provide a message to describe the changes in the
    migration.

    Args:
        message (str): The message describing the migration.  This is typically a short,
            descriptive string.
        autogenerate (bool): If True, Alembic will attempt to automatically generate the
            migration operations based on the changes to your models.  If False
            (the default), you will need to edit the migration script manually.

    Usage:
        flask db-revision -m "20250224 - Added comment field"
        flask db-revision --message "20250224 - Added comment field"
        flask db-revision -m "20250224 - Added comment field" --autogenerate
        flask db-revision --message "20250224 - Added comment field" --autogenerate

    Returns:
        None
    """
    import flask_migrate  # pylint: disable=E0401, C0415

    logger.debug(
        "Revision message: %s", message
    )
    logger.debug(
        "Autogenerate: %s", autogenerate
    )

    with app.app_context():
        flask_migrate.revision(
            message=message,
            autogenerate=autogenerate
        )


######################################################################
# Command to appy database migration
# Usage:
#   flask db-upgrade
######################################################################
@app.cli.command('db-upgrade')
def db_upgrade() -> None:
    """Applies pending migration scripts to the database.

    This command upgrades the database schema to the latest version by applying
    any pending migration scripts. It ensures that the database schema matches
    the structure defined in your models.

    Usage:
        flask db-upgrade

    Returns:
        None
    """
    import flask_migrate  # pylint: disable=E0401, C0415

    with app.app_context():
        flask_migrate.upgrade()


######################################################################
# Command to revert database migration
# Usage:
#   flask db-downgrade
#   flask db-downgrade 2
######################################################################
@app.cli.command('db-downgrade')
@click.argument(
    'steps',
    type=int,
    default=1
)
def db_downgrade(steps: int) -> None:
    """Downgrades the database to a previous migration.

    This command reverts the database schema to an earlier state by applying
    previous migration scripts in reverse order.  You specify the number of
    steps to downgrade.

    Args:
        steps (int): The number of migration steps to downgrade.  This must be a
            positive integer.

    Usage:
        flask db-downgrade
        flask db-downgrade <number_of_steps>  (e.g., flask db-downgrade 2)

    Returns:
        None
    """
    import flask_migrate  # pylint: disable=E0401, C0415

    logger.debug("Downgrading %s steps.", steps)

    with app.app_context():
        flask_migrate.downgrade(revision=f'-{steps}')


######################################################################
# Command to force tables to be rebuilt
# Usage:
#   flask db-create
######################################################################
@app.cli.command("db-create")
def db_create() -> None:
    """Recreates the local database.

    Usage:
        flask db-create

    Returns:
        None

    WARNING: This function should *never* be used in a production environment.
    It drops all tables and recreates them, resulting in complete data loss.
    This function is intended for development and testing purposes only.
    """
    db.drop_all()
    db.create_all()
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)

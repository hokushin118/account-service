"""
Account service CLI.

Flask CLI Command Extensions.
"""
from service import app
from service.models import db


######################################################################
# Command to force tables to be rebuilt
# Usage:
#   flask db-create
######################################################################
@app.cli.command("db-create")
def db_create() -> None:
    """Recreates the local database.

    WARNING: This function should *never* be used in a production environment.
    It drops all tables and recreates them, resulting in complete data loss.
    This function is intended for development and testing purposes only.
    """
    db.drop_all()
    db.create_all()
    db.session.commit()


if __name__ == "__main__":
    app.run(debug=True)

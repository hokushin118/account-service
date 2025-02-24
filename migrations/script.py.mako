"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade():
    """
    This function is used to apply the database schema changes.
    It contains the logic for upgrading the database to a new schema.
    """
    ${upgrades if upgrades else "pass"}


def downgrade():
    """
    This function is used to revert the database schema changes.
    It contains the logic for downgrading the database to the previous schema.
    """
    ${downgrades if downgrades else "pass"}

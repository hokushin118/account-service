"""20250224 - initial

Revision ID: 8703e9e4b972
Revises: e1b33b1cbf6b
Create Date: 2025-02-24 13:17:02.968517

"""
from datetime import date

from alembic import op
from sqlalchemy import (
    Date,
    Column,
    String,
    text,
    PrimaryKeyConstraint,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID

from service.common.constants import (
    NAME_MAX_LENGTH,
    EMAIL_MAX_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH
)
from service.common.utils import timestamps

# revision identifiers, used by Alembic.
revision = '8703e9e4b972'
down_revision = None
branch_labels = None
depends_on = None


def create_updated_at_trigger() -> None:
    """Creating a last updated function.

       Returns:
           None.
    """
    op.execute(
        """
        CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS
        $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$ language 'plpgsql';
        """
    )


def create_accounts_table() -> None:
    """Creating the 'accounts' table.

       Returns:
           None.
    """
    op.create_table(
        'accounts',
        Column(
            'id',
            UUID(as_uuid=True),
            nullable=False,
            index=True,
            server_default=text('gen_random_uuid()')
        ),
        Column(
            'name',
            String(NAME_MAX_LENGTH),
            nullable=False
        ),
        Column(
            'email',
            String(EMAIL_MAX_LENGTH),
            nullable=False,
            unique=True
        ),
        Column(
            'address',
            String(ADDRESS_MAX_LENGTH)
        ),
        Column(
            'phone_number',
            String(PHONE_MAX_LENGTH)
        ),
        Column(
            'date_joined',
            Date,
            nullable=False,
            default=date.today()
        ),
        *timestamps(is_indexed=True),
        PrimaryKeyConstraint('id'),
        UniqueConstraint('email')
    )
    op.execute(
        """
        CREATE TRIGGER update_accounts_modtime
            BEFORE UPDATE
            ON accounts
            FOR EACH ROW
        EXECUTE PROCEDURE update_updated_at_column();
        """
    )


def upgrade() -> None:
    """Creating a function for the last update and
    the 'accounts' table in the database.

    Returns:
        Nothing.
    """
    create_updated_at_trigger()
    create_accounts_table()


def downgrade() -> None:
    """Deleting the 'accounts' table from the database.

       Returns:
           None.
    """
    op.drop_table('accounts')
    op.execute('DROP FUNCTION update_updated_at_column')

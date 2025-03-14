"""20250313 - add_user_id_field

Revision ID: f2d5897879ee
Revises: 334821f1fe44
Create Date: 2025-03-13 22:04:51.673881

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = 'f2d5897879ee'
down_revision = '334821f1fe44'
branch_labels = None
depends_on = None


def upgrade():
    """Adds the user_id field to the account table."""
    op.add_column('accounts',
                  sa.Column(
                      'user_id',
                      UUID(as_uuid=True),
                      nullable=False,
                      unique=True,
                      index=True
                  ))


def downgrade():
    """Removes the user_id field from the account table."""
    op.drop_column('accounts', 'user_id')

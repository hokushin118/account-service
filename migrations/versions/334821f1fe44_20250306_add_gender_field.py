"""20250306 - add gender field

Revision ID: 334821f1fe44
Revises: 0747d1ee9835
Create Date: 2025-03-06 17:39:30.270837

"""
import sqlalchemy as sa
from alembic import op

from service.common.constants import GENDER_MAX_LENGTH

# revision identifiers, used by Alembic.
revision = '334821f1fe44'
down_revision = '0747d1ee9835'
branch_labels = None
depends_on = None


def upgrade():
    """Adds the gender field to the account table."""
    op.add_column('accounts',
                  sa.Column(
                      'gender',
                      sa.String(GENDER_MAX_LENGTH),
                      nullable=True
                  ))


def downgrade():
    """Removes the gender field from the account table."""
    op.drop_column('accounts', 'gender')

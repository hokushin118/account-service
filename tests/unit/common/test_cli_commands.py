"""
CLI Command Extensions for Flask Unit Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from unittest import TestCase
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from service import app
from service.common.cli_commands import db_create


######################################################################
#  ACCOUNT CLI TEST CASES
######################################################################
class TestFlaskCLI(TestCase):
    """Test Flask CLI Commands."""

    def setUp(self):
        self.runner = CliRunner()

    @patch('flask_migrate.init')
    def test_db_init(self, mock_init):
        """It should call the db-init command."""
        result = self.runner.invoke(app.cli, ['db-init'])
        self.assertEqual(result.exit_code, 0)
        mock_init.assert_called_once()

    @patch('flask_migrate.migrate')
    def test_db_migrate(self, mock_migrate):
        """It should call the db-migrate command with migration message."""
        migration_message = 'Test migration message'
        # Simulate entering the migration message at the prompt.
        result = self.runner.invoke(
            app.cli,
            ['db-migrate'],
            input=migration_message + "\n"
        )
        self.assertEqual(result.exit_code, 0)
        mock_migrate.assert_called_once_with(message=migration_message)

    @patch('flask_migrate.revision')
    def test_db_revision_without_autogenerate(self, mock_revision):
        """It should call the db-revision command with defaults."""
        revision_message = 'Test revision message'
        result = self.runner.invoke(
            app.cli, ['db-revision'],
            input=revision_message + "\n"
        )
        self.assertEqual(result.exit_code, 0)
        mock_revision.assert_called_once_with(
            message=revision_message,
            autogenerate=False
        )

    @patch('flask_migrate.revision')
    def test_db_revision_with_autogenerate(self, mock_revision):
        """It should call the db-revision command with flag."""
        revision_message = 'Test revision message'
        result = self.runner.invoke(
            app.cli, ['db-revision', '--autogenerate'],
            input=revision_message + "\n"
        )
        self.assertEqual(result.exit_code, 0)
        mock_revision.assert_called_once_with(
            message=revision_message,
            autogenerate=True
        )

    @patch('flask_migrate.upgrade')
    def test_db_upgrade(self, mock_upgrade):
        """It should call the db-upgrade command."""
        result = self.runner.invoke(app.cli, ['db-upgrade'])
        self.assertEqual(result.exit_code, 0)
        mock_upgrade.assert_called_once()

    @patch('flask_migrate.downgrade')
    def test_db_downgrade_default(self, mock_downgrade):
        """It should call the db-downgrade command with default revision '-1'."""
        result = self.runner.invoke(app.cli, ['db-downgrade'])
        self.assertEqual(result.exit_code, 0)
        mock_downgrade.assert_called_once_with(revision='-1')

    @patch('flask_migrate.downgrade')
    def test_db_downgrade_with_revision(self, mock_downgrade):
        """It should call the db-downgrade command with provided revision."""
        revision = 'abc123'
        result = self.runner.invoke(
            app.cli, ['db-downgrade', revision]
        )
        self.assertEqual(result.exit_code, 0)
        mock_downgrade.assert_called_once_with(revision=revision)

    @patch('flask_migrate.history')
    def test_db_history(self, mock_history):
        """It should call the db-history command."""
        result = self.runner.invoke(
            app.cli,
            ['db-history', '-v', '--rev-range', 'base:head']
        )
        self.assertEqual(result.exit_code, 0)
        mock_history.assert_called_once_with(
            verbose=True,
            rev_range='base:head'
        )

    @patch('service.common.cli_commands.db')
    def test_db_create(self, db_mock):
        """It should call the db-create command."""
        db_mock.return_value = MagicMock()
        with patch.dict(os.environ, {'FLASK_APP': 'service:app'}, clear=True):
            result = self.runner.invoke(db_create)
            self.assertEqual(result.exit_code, 0)

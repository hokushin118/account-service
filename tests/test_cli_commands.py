"""
CLI Command Extensions for Flask.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import os
from unittest import TestCase
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from service import app
from service.common.cli_commands import db_create, db_init


class TestFlaskCLI(TestCase):
    """Test Flask CLI Commands."""

    def setUp(self):
        self.runner = CliRunner()
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    @patch('flask_migrate.init')
    def test_db_init(self, db_mock):
        """It should call the db-init command."""
        db_mock.return_value = MagicMock()
        with patch.dict(os.environ, {'FLASK_APP': 'service:app'}, clear=True):
            result = self.runner.invoke(db_init)
            self.assertEqual(result.exit_code, 0)
            db_mock.assert_called_once()

    @patch('service.common.cli_commands.db')
    def test_db_create(self, db_mock):
        """It should call the db-create command."""
        db_mock.return_value = MagicMock()
        with patch.dict(os.environ, {'FLASK_APP': 'service:app'}, clear=True):
            result = self.runner.invoke(db_create)
            self.assertEqual(result.exit_code, 0)

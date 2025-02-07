"""
Utils Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import hashlib
from unittest import TestCase

from flask import Flask

from service.common.utils import (
    generate_etag_hash,
    count_requests
)


######################################################################
#  U T I L S   T E S T   C A S E S
######################################################################
class TestUtils(TestCase):
    """The Decorated Function Tests."""

    def setUp(self):
        self.app = Flask(__name__)  # Create a test Flask app
        self.app_context = self.app.app_context()
        self.app_context.push()  # Push the context so request works

    def tearDown(self):
        self.app_context.pop()  # Pop the context

    def test_count_requests_wraps(self):
        """It should preserve function metadata."""

        @count_requests
        def test_route():
            """Test route docstring"""
            return 'Test Route'

        self.assertEqual(
            test_route.__name__,
            'test_route'
        )  # Check if name is preserved
        self.assertEqual(
            test_route.__doc__,
            'Test route docstring'
        )  # Check if docstring is preserved

    def test_count_requests_no_request_context(self):
        """It should raise an error when called outside of context."""

        @count_requests
        def test_route():
            return "Test Route"

        with self.assertRaises(RuntimeError) as context:
            test_route()
        self.assertIn(
            'Working outside of request context',
            str(context.exception)
        )


class TestGenerateETagHash(TestCase):
    """Generate ETag Hash Tests."""

    def test_valid_input(self):
        """It should produce the correct MD5 hash."""
        data = {
            'id': 1,
            'name': 'John Doe',
            'email': 'john.doe@example.com',
            'address': '124 Main St',
            'phone_number': '123-456-7890',
            'date_joined': '2024-07-26'
        }
        expected_hash = hashlib.md5(str(data).encode('utf-8')).hexdigest()
        actual_hash = generate_etag_hash(data)
        self.assertEqual(actual_hash, expected_hash)

    def test_empty_dictionary(self):
        """It should produce the same MD5 hashes."""
        data = {}
        expected_hash = hashlib.md5(str(data).encode('utf-8')).hexdigest()
        actual_hash = generate_etag_hash(data)
        self.assertEqual(actual_hash, expected_hash)

    def test_unicode_characters(self):
        """It should produce the correct MD5 hash with unicode characters."""
        data = {'name': '茜', 'address': '東京'}  # Contains unicode
        expected_hash = hashlib.md5(str(data).encode('utf-8')).hexdigest()
        actual_hash = generate_etag_hash(data)
        self.assertEqual(actual_hash, expected_hash)

    def test_keys_order(self):
        """It should produce the different MD5 hashes."""
        data1 = {
            'name': 'John Doe',
            'email': 'john.doe@example.com'
        }
        data2 = {
            'email': 'john.doe@example.com',
            'name': 'John Doe'
        }  # Key order is different

        expected_hash1 = hashlib.md5(str(data1).encode('utf-8')).hexdigest()
        expected_hash2 = hashlib.md5(str(data2).encode('utf-8')).hexdigest()

        self.assertNotEqual(
            expected_hash1,
            expected_hash2
        )  # Different order = different hashes

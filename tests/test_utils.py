"""
Utils Test Suite.

Test cases can be run with the following:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import hashlib
from unittest import TestCase

from service.common.utils import generate_etag_hash


######################################################################
#  U T I L S   T E S T   C A S E S
######################################################################
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

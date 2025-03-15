"""
Account Service Test Suite.

Test cases can be run with:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch

from service.common.constants import ACCOUNT_CACHE_KEY
from service.services import AccountService
from tests.factories import AccountFactory
from tests.test_constants import (
    TEST_ETAG,
    NEW_ETAG,
    TEST_PAGE,
    TEST_PER_PAGE,
    TEST_TOTAL
)


######################################################################
#  ACCOUNT SERVICE TEST CASES
######################################################################
class TestAccountService(TestCase):
    """Account Service Tests."""

    def setUp(self):
        self.cache_key = f"{ACCOUNT_CACHE_KEY}:{TEST_PAGE}:{TEST_PER_PAGE}"

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('service.services.cache')
    @patch("service.services.generate_etag_hash")
    def test_list_accounts_with_cache(
            self,
            mock_generate_etag_hash,
            mock_cache
    ):
        """It should return a list of accounts from cache."""
        mock_generate_etag_hash.return_value = TEST_ETAG
        mock_cache.get.return_value = (
            {'items': [{'id': 1}],
             'page': TEST_PAGE,
             'per_page': TEST_PER_PAGE,
             'total': TEST_TOTAL},
            TEST_ETAG
        )
        mock_cache.set.return_value = None
        # Retrieve all accounts
        result, etag = AccountService.list_accounts(TEST_PAGE, TEST_PER_PAGE)
        self.assertEqual(result['items'], [{'id': 1}])
        self.assertEqual(etag, TEST_ETAG)
        mock_cache.get.assert_called_once_with(self.cache_key)

    @patch('service.services.cache')
    @patch("service.services.Account")
    @patch("service.services.generate_etag_hash")
    def test_list_accounts_cache_miss(
            self,
            mock_generate_etag_hash,
            mock_account,
            mock_cache
    ):
        """It should return a list of accounts from database."""
        account1 = AccountFactory()
        account2 = AccountFactory()
        accounts = [account1, account2]
        total = len(accounts)
        mock_account.all_paginated.return_value = accounts
        mock_account.query.count.return_value = total
        mock_generate_etag_hash.return_value = NEW_ETAG
        mock_cache.get.return_value = None
        mock_cache.set.return_value = None

        result, etag = AccountService.list_accounts(TEST_PAGE, TEST_PER_PAGE)

        self.assertEqual(result['page'], TEST_PAGE)
        self.assertEqual(result['per_page'], TEST_PER_PAGE)
        self.assertEqual(result['total'], total)
        self.assertEqual(etag, NEW_ETAG)
        mock_cache.get.assert_called_once_with(self.cache_key)
        mock_cache.set.assert_called_once()
        mock_account.all_paginated.assert_called_once_with(
            page=TEST_PAGE,
            per_page=TEST_PER_PAGE
        )
        mock_account.query.count.assert_called_once()

    @patch("service.services.cache")
    @patch("service.services.Account")
    @patch("service.services.generate_etag_hash")
    def test_list_accounts_empty_list(
            self,
            mock_generate_etag_hash,
            mock_account,
            mock_cache
    ):
        """It should return an empty list."""
        mock_cache.get.return_value = None
        mock_account.all_paginated.return_value = []
        mock_account.query.count.return_value = 0
        mock_generate_etag_hash.return_value = TEST_ETAG

        result, etag = AccountService.list_accounts(TEST_PAGE, TEST_PER_PAGE)

        self.assertEqual(result['items'], [])
        self.assertEqual(etag, TEST_ETAG)
        mock_cache.get.assert_called_once_with(self.cache_key)
        mock_cache.set.assert_called_once()
        mock_account.all_paginated.assert_called_once_with(
            page=TEST_PAGE,
            per_page=TEST_PER_PAGE
        )
        mock_account.query.count.assert_called_once()

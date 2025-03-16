"""
Account Service Test Suite.

Test cases can be run with:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
from unittest import TestCase
from unittest.mock import patch
from uuid import UUID, uuid4

from service.common.constants import ACCOUNT_CACHE_KEY
from service.schemas import AccountDTO
from service.services import AccountService
from tests.factories import AccountFactory
from tests.test_constants import (
    TEST_ETAG,
    NEW_ETAG,
    TEST_PAGE,
    TEST_PER_PAGE,
    TEST_TOTAL,
    TEST_USER_ID, TEST_ACCOUNT_ID
)


######################################################################
#  ACCOUNT SERVICE TEST CASES
######################################################################
class TestAccountService(TestCase):
    """Account Service Tests."""

    account = None

    def setUp(self):
        self.account = AccountFactory()
        self.test_account_dto = AccountDTO.from_orm(self.account)
        self.cache_key = f"{ACCOUNT_CACHE_KEY}:{TEST_PAGE}:{TEST_PER_PAGE}"

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('service.services.cache')
    @patch('service.services.generate_etag_hash')
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
    @patch('service.services.Account')
    @patch('service.services.generate_etag_hash')
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

    @patch('service.services.cache')
    @patch('service.services.Account')
    @patch('service.services.generate_etag_hash')
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

    ######################################################################
    # READ AN ACCOUNT
    ######################################################################
    @patch('service.services.cache')
    def test_get_account_by_id_with_cache(self, mock_cache):
        """It should return cached account data if available."""
        account = AccountFactory()
        cached_value = account, TEST_ETAG
        mock_cache.get.return_value = cached_value

        data, etag = AccountService.get_account_by_id(TEST_ACCOUNT_ID)

        self.assertEqual(data, account)
        self.assertEqual(etag, TEST_ETAG)

    @patch('service.services.generate_etag_hash')
    @patch('service.services.AccountService')
    @patch('service.services.cache')
    def test_get_account_by_id_cache_miss(self,
                                          mock_cache,
                                          mock_account_service,
                                          mock_generate_etag_hash):
        """It should fetch the account from the database if not cached and return its data."""
        mock_cache.get.return_value = None
        mock_account_service.get_account_or_404.return_value = self.account
        mock_generate_etag_hash.return_value = TEST_ETAG

        _, etag = AccountService.get_account_by_id(TEST_ACCOUNT_ID)

        mock_account_service.get_account_or_404.assert_called_once_with(
            TEST_ACCOUNT_ID
        )

        mock_generate_etag_hash.assert_called_once()
        mock_cache.set.assert_called_once()
        self.assertEqual(etag, TEST_ETAG)


######################################################################
# HELPER METHODS
######################################################################
class DummyAccount:
    """
    DummyAccount is a simple class used for testing purposes.

    It should encapsulate basic account attributes needed during tests,
    including an account identifier and a test user identifier.
    """

    def __init__(self, account_id: UUID) -> None:
        self.id = account_id  # pylint: disable=C0103:
        self.user_id = TEST_USER_ID


class TestGetAccountOr404(TestCase):
    """The get_account_or_404 Function Tests."""

    def setUp(self):
        """It should set up a dummy account ID for testing."""
        self.account_id = uuid4()

    @patch('service.services.Account')
    def test_get_account_success(self, mock_account):
        """It should return the account when a matching account is found."""
        dummy_account = DummyAccount(self.account_id)
        mock_account.find.return_value = dummy_account

        result = AccountService.get_account_or_404(self.account_id)

        self.assertEqual(result, dummy_account)
        mock_account.find.assert_called_once_with(self.account_id)

    @patch('flask.abort')
    @patch('service.services.Account')
    def test_get_account_not_found(self, mock_account, mock_abort):
        """It should abort with a 404 error when the indicated account is not found."""
        mock_account.find.return_value = None
        error_message = f"Account with id {self.account_id} could not be found."
        mock_abort.side_effect = Exception(error_message)

        with self.assertRaises(Exception) as context:
            AccountService.get_account_or_404(self.account_id)

        self.assertIn(error_message, str(context.exception))
        mock_account.find.assert_called_once_with(self.account_id)

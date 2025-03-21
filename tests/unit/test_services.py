# pylint: disable=C0302
"""
Account Service Unit Test Suite.

Test cases can be run with:
  nosetests -v --with-spec --spec-color
  coverage report -m
"""
import logging
from unittest import TestCase
from unittest.mock import patch, MagicMock
from uuid import UUID, uuid4

from service.common.constants import (
    ACCOUNT_CACHE_KEY,
    ROLE_ADMIN, ROLE_USER
)
from service.errors import (
    AccountError,
    AccountNotFoundError,
    AccountAuthorizationError
)
from service.schemas import (
    AccountDTO,
    UpdateAccountDTO,
    PartialUpdateAccountDTO, CreateAccountDTO
)
from service.services import (
    AccountService,
    FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE
)
from tests.utils.constants import (
    TEST_ETAG,
    NEW_ETAG,
    TEST_PAGE,
    TEST_PER_PAGE,
    TEST_TOTAL,
    TEST_USER_ID,
    TEST_ACCOUNT_ID, ACCOUNT_DATA
)
from tests.utils.factories import AccountFactory

logger = logging.getLogger(__name__)


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

        self.updated_account = AccountFactory()
        self.updated_account_dto = AccountDTO.from_orm(self.updated_account)

    ######################################################################
    # CREATE A NEW ACCOUNT TEST CASES
    ######################################################################
    @patch('service.services.AccountService.invalidate_all_account_pages')
    @patch('service.services.AccountDTO')
    @patch('service.services.Account')
    @patch('service.services.get_jwt_identity')
    @patch('service.services.app')
    def test_create_success(
            self,
            mock_app,
            mock_get_jwt_identity,
            mock_account,
            mock_account_dto,
            mock_invalidate
    ):
        """It should create a new user account."""
        fake_user_id = TEST_USER_ID
        mock_get_jwt_identity.return_value = fake_user_id

        # Create a dummy account instance with spy methods.
        dummy_account_instance = MagicMock()
        # Ensure the instance has a deserialize method
        dummy_account_instance.deserialize = MagicMock()
        # account.create should complete without exception.
        dummy_account_instance.create.return_value = dummy_account_instance
        # When Account() is called, return our dummy instance.
        mock_account.return_value = dummy_account_instance

        # Set up the AccountDTO.from_orm method to return an object with a to_dict method.
        dummy_account_dto_instance = MagicMock()
        dummy_account_dto_instance.id = TEST_ACCOUNT_ID
        dummy_account_dto_instance.to_dict.return_value = {
            "id": TEST_USER_ID,
            "status": "created"
        }
        mock_account_dto.model_validate.return_value = dummy_account_dto_instance

        # Create a DTO instance.
        create_account_dto = CreateAccountDTO(**ACCOUNT_DATA)

        result = AccountService.create(create_account_dto)

        # 1. Ensure the current user ID was retrieved.
        mock_get_jwt_identity.assert_called_once()
        # 2. Check that the Account instance was created and deserialized with the DTO data.
        dummy_account_instance.deserialize.assert_called_once_with(
            create_account_dto.to_dict()
        )
        # 3. Ensure the account's user_id was set to the current user id.
        self.assertEqual(dummy_account_instance.user_id, fake_user_id)
        # 4. Ensure the create method on the account instance was called.
        dummy_account_instance.create.assert_called_once()
        # 5. Verify that the cache invalidation method was called.
        mock_invalidate.assert_called_once()
        # 6. Verify that a debug log for cache invalidation included the ACCOUNT_CACHE_KEY.
        # (This examines the debug log calls on the app logger.)
        debug_calls = [call_arg[0] for call_arg in
                       mock_app.logger.debug.call_args_list]
        self.assertTrue(
            any(ACCOUNT_CACHE_KEY in message for message in debug_calls)
        )
        # 7. Ensure that AccountDTO.from_orm was called with the account instance.
        mock_account_dto.model_validate.assert_called_once_with(
            dummy_account_instance
        )
        # 8. The result should match the output of dummy_account_dto_instance.
        self.assertEqual(result.id, TEST_ACCOUNT_ID)

    ######################################################################
    #  LIST ALL ACCOUNTS TEST CASES
    ######################################################################
    @patch('service.services.cache')
    @patch('service.services.generate_etag_hash')
    @patch('service.services.get_jwt_identity')
    def test_list_accounts_with_cache(
            self,
            mock_get_jwt_identity,
            mock_generate_etag_hash,
            mock_cache
    ):
        """It should return a list of accounts from cache."""
        mock_get_jwt_identity.return_value = TEST_USER_ID
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
    @patch('service.services.get_jwt_identity')
    def test_list_accounts_cache_miss(
            self,
            mock_get_jwt_identity,
            mock_generate_etag_hash,
            mock_account,
            mock_cache
    ):
        """It should return a list of accounts from database."""
        account1 = AccountFactory()
        account2 = AccountFactory()
        accounts = [account1, account2]
        total = len(accounts)
        mock_get_jwt_identity.return_value = TEST_USER_ID
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
    @patch('service.services.get_jwt_identity')
    def test_list_accounts_empty_list(
            self,
            mock_get_jwt_identity,
            mock_generate_etag_hash,
            mock_account,
            mock_cache
    ):
        """It should return an empty list."""
        mock_get_jwt_identity.return_value = TEST_USER_ID
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
    @patch('service.services.AccountService')
    @patch('service.services.get_jwt_identity')
    def test_get_account_by_id_with_cache(
            self,
            mock_cache,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should return cached account data if available."""
        mock_get_jwt_identity.get_jwt_identity.return_value = TEST_USER_ID

        account = AccountFactory()
        account_dto = AccountDTO.model_validate(account)
        data = account_dto.model_dump()

        cached_value = data, TEST_ETAG
        mock_cache.get.return_value = cached_value
        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = cached_value

        data, etag = AccountService.get_account_by_id(TEST_ACCOUNT_ID)

        mock_account_service._get_cached_data.assert_called_once()
        self.assertEqual(data, account_dto)
        self.assertEqual(etag, TEST_ETAG)

    @patch('service.services.generate_etag_hash')
    @patch('service.services.AccountService')
    @patch('service.services.get_jwt_identity')
    def test_get_account_by_id_cache_miss(
            self,
            mock_get_jwt_identity,
            mock_account_service,
            mock_generate_etag_hash
    ):
        """It should fetch the account from the database if not cached and return its data."""
        mock_get_jwt_identity.get_jwt_identity.return_value = TEST_USER_ID

        # pylint: disable=W0212
        mock_account_service._get_cached_data.return_value = None
        mock_account_service.get_account_or_404.return_value = self.account
        mock_generate_etag_hash.return_value = TEST_ETAG

        _, etag = AccountService.get_account_by_id(TEST_ACCOUNT_ID)

        mock_account_service.get_account_or_404.assert_called_once_with(
            TEST_ACCOUNT_ID
        )

        mock_generate_etag_hash.assert_called_once()
        # pylint: disable=W0212
        mock_account_service._get_cached_data.assert_called_once()
        self.assertEqual(etag, TEST_ETAG)

    ######################################################################
    # UPDATE AN EXISTING ACCOUNT
    ######################################################################
    @patch('service.services.AccountService.invalidate_all_account_pages')
    @patch('service.services.AccountDTO')
    @patch('service.services.AccountService')
    @patch('service.services.get_jwt_identity')
    def test_update_by_id_success(
            self,
            mock_account_dto,
            mock_account_service,
            mock_get_jwt_identity,
            mock_invalidate_cache
    ):
        """It should update an account’s attributes and return its dict representation."""
        account_id = uuid4()
        dummy_account = DummyAccount(account_id, account_id)
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate the current user retrieved from the JWT token
        mock_get_jwt_identity.return_value = TEST_USER_ID

        update_dto = UpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        # Call the method under test.
        result = AccountService.update_by_id(self.account.id, update_dto)

        self.assertIsNotNone(result)

        # Verify that the account is existed
        mock_account_service.get_account_or_404.assert_called_once()
        # Verify that the user is authorized
        mock_account_service.authorize_account.assert_called_once()
        # Verify that the cache invalidation function was called
        mock_account_service.invalidate_all_account_pages.assert_called_once()
        # Verify that AccountDTO.from_orm was called with the updated account
        mock_account_dto.assert_called_once()
        # Verify that cache invalidation was called
        mock_invalidate_cache.assert_called_once()

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_update_by_id_account_not_found(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should raise an AccountNotFoundError if the account is not found."""
        account_id = uuid4()

        # Simulate that get_account_or_404 raises an AccountNotFoundError
        mock_account_service.get_account_or_404.side_effect = (
            AccountNotFoundError(
                account_id,
                f"Account with id {account_id} could not be found."
            )
        )
        mock_get_jwt_identity.return_value = TEST_USER_ID

        update_dto = UpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        with self.assertRaises(AccountNotFoundError):
            AccountService.update_by_id(
                account_id,
                update_dto
            )

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_update_by_id_unauthorized(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should raise an AccountAuthorizationError if the user is not
        authorized to update the account."""
        account_id = uuid4()
        account_user_id = uuid4()
        dummy_account = DummyAccount(account_id, account_user_id)
        # Simulate successful account retrieval.
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate current user with an id that does not match the account's owner
        mock_get_jwt_identity.return_value = TEST_USER_ID

        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {account_user_id} is not authorized to perform this action."
            ))

        update_dto = UpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        with self.assertRaises(AccountAuthorizationError):
            AccountService.update_by_id(
                account_id,
                update_dto
            )

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )
        mock_account_service.authorize_account.assert_called_once_with(
            TEST_USER_ID,
            dummy_account.user_id
        )

    ######################################################################
    # PARTIAL UPDATE AN EXISTING ACCOUNT
    ######################################################################
    @patch('service.services.AccountService.invalidate_all_account_pages')
    @patch('service.services.AccountDTO')
    @patch('service.services.AccountService')
    @patch('service.services.get_jwt_identity')
    def test_partial_update_by_id_success(
            self,
            mock_account_dto,
            mock_account_service,
            mock_get_jwt_identity,
            mock_invalidate_cache
    ):
        """It should partially update an account’s attributes and return its
        dict representation."""
        account_id = uuid4()
        dummy_account = DummyAccount(account_id, account_id)
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate the current user retrieved from the JWT token
        mock_get_jwt_identity.return_value = TEST_USER_ID

        mock_account_dto.from_orm.return_value = self.updated_account_dto

        partial_update_dto = PartialUpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        # Call the method under test.
        result = AccountService.partial_update_by_id(
            self.account.id,
            partial_update_dto
        )

        self.assertIsNotNone(result)

        # Verify that the account is existed
        mock_account_service.get_account_or_404.assert_called_once()
        # Verify that the user is authorized
        mock_account_service.authorize_account.assert_called_once()
        # Verify that the cache invalidation function was called
        mock_account_service.invalidate_all_account_pages.assert_called_once()
        # Verify that AccountDTO.from_orm was called with the updated account
        mock_account_dto.assert_called_once()
        # Verify that cache invalidation was called
        mock_invalidate_cache.assert_called_once()

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_partial_update_by_id_account_not_found(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should raise an AccountNotFoundError if the account is not found."""
        account_id = uuid4()

        # Simulate that get_account_or_404 raises an AccountNotFoundError
        mock_account_service.get_account_or_404.side_effect = (
            AccountNotFoundError(
                account_id,
                f"Account with id {account_id} could not be found."
            )
        )
        mock_get_jwt_identity.return_value = TEST_USER_ID

        partial_update_dto = PartialUpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        with self.assertRaises(AccountNotFoundError):
            AccountService.partial_update_by_id(
                account_id,
                partial_update_dto
            )

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_partial_update_by_id_unauthorized(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should raise an AccountAuthorizationError if the user is not
        authorized to partially update the account."""
        account_id = uuid4()
        account_user_id = uuid4()
        dummy_account = DummyAccount(account_id, account_user_id)
        # Simulate successful account retrieval.
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate current user with an id that does not match the account's owner
        mock_get_jwt_identity.return_value = TEST_USER_ID

        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {account_user_id} is not authorized to perform this action."
            ))

        partial_update_dto = PartialUpdateAccountDTO(
            name=self.updated_account.name,
            email=self.updated_account.email,
            address=self.updated_account.address,
            gender=self.updated_account.gender,
            phone_number=self.updated_account.phone_number
        )

        with self.assertRaises(AccountAuthorizationError):
            AccountService.partial_update_by_id(
                account_id,
                partial_update_dto
            )

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )
        mock_account_service.authorize_account.assert_called_once_with(
            TEST_USER_ID,
            dummy_account.user_id
        )

    ######################################################################
    # DELETE AN ACCOUNT
    ######################################################################
    @patch('service.services.AccountService.invalidate_all_account_pages')
    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_delete_by_id_success(
            self,
            mock_account_service,
            mock_get_jwt_identity,
            mock_invalidate_cache
    ):
        """It should delete the account if the user is authorized and invalidate the cache."""
        # Create a dummy account id and dummy account instance
        account_id = uuid4()
        dummy_account = DummyAccount(account_id, account_id)
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate the current user retrieved from the JWT token
        mock_get_jwt_identity.return_value = TEST_USER_ID

        # Call the delete_by_id static method
        AccountService.delete_by_id(account_id)

        # Verify that the JWT identity was obtained
        mock_get_jwt_identity.assert_called_once()

        # Verify that get_account_or_404 was called with the correct account_id
        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )

        # Verify that the account authorization was performed
        mock_account_service.authorize_account.assert_called_once_with(
            TEST_USER_ID,
            dummy_account.user_id
        )

        # Verify that the delete() method was called on the dummy account
        self.assertTrue(dummy_account.deleted)

        # Verify that cache invalidation was called
        mock_invalidate_cache.assert_called_once()

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_delete_by_id_account_not_found(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should not raise an AccountNotFoundError if the account is not
        found."""
        account_id = uuid4()

        # Simulate that get_account_or_404 raises an AccountNotFoundError
        mock_account_service.get_account_or_404.side_effect = (
            AccountNotFoundError(
                account_id,
                f"Account with id {account_id} could not be found."
            )
        )
        mock_get_jwt_identity.return_value = TEST_USER_ID

        # Call the delete_by_id static method
        AccountService.delete_by_id(account_id)

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )

    @patch('service.services.get_jwt_identity')
    @patch('service.services.AccountService')
    def test_delete_by_id_unauthorized(
            self,
            mock_account_service,
            mock_get_jwt_identity
    ):
        """It should raise an AccountAuthorizationError if the user is not authorized to delete
        the account."""
        account_id = uuid4()
        account_user_id = uuid4()
        dummy_account = DummyAccount(account_id, account_user_id)
        # Simulate successful account retrieval.
        mock_account_service.get_account_or_404.return_value = dummy_account

        # Simulate current user with an id that does not match the account's owner
        mock_get_jwt_identity.return_value = TEST_USER_ID

        # Simulate that authorize_account raises an AccountAuthorizationError
        mock_account_service.authorize_account.side_effect = (
            AccountAuthorizationError(
                f"Account with user id {account_user_id} is not authorized to perform this action."
            ))

        with self.assertRaises(AccountAuthorizationError):
            AccountService.delete_by_id(account_id)

        mock_account_service.get_account_or_404.assert_called_once_with(
            account_id
        )
        mock_account_service.authorize_account.assert_called_once_with(
            TEST_USER_ID,
            dummy_account.user_id
        )


######################################################################
# HELPER METHODS
######################################################################
class DummyAccount:
    """DummyAccount is a simple class used for testing purposes.

    It should encapsulate basic account attributes needed during tests,
    including an account identifier and a test user identifier.
    """

    def __init__(
            self,
            account_id: UUID,
            user_id: UUID
    ) -> None:
        """Initializes a new DummyAccount instance.

        Args:
            account_id (UUID): The unique identifier for the dummy account.
            user_id (UUID): The unique identifier for the test user associated with the account.
        """
        self.id = account_id  # pylint: disable=C0103:
        self.user_id = user_id
        self.partial_updated = False
        self.updated = False
        self.deleted = False

    def partial_update(
            self,
            data: dict
    ) -> None:
        """Simulates the partial update of the dummy account.

        Sets the `partial_updated` flag to True to indicate that the account has been
        partially updated. Logs the data used for the update.

        Args:
            data (dict): A dictionary containing the data used for the partial update.
        """
        logger.debug("Partial update called with data: %s", data)
        self.partial_updated = True

    def update(self) -> None:
        """Simulates the update of the dummy account.

        Sets the `updated` flag to True to indicate that the account has been updated.
        """
        self.updated = True

    def delete(self) -> None:
        """Simulates the deletion of the dummy account.

        Sets the `deleted` flag to True to indicate that the account has been deleted.
        """
        self.deleted = True


class TestGetAccountOr404(TestCase):
    """The get_account_or_404 Function Tests."""

    def setUp(self):
        """It should set up a dummy account ID for testing."""
        test_id = uuid4()
        self.account_id = test_id
        self.account_user_id = test_id

    @patch('service.services.Account')
    def test_get_account_success(self, mock_account):
        """It should return the account when a matching account is found."""
        dummy_account = DummyAccount(self.account_id, self.account_user_id)
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

        with self.assertRaises(AccountNotFoundError) as context:
            AccountService.get_account_or_404(self.account_id)

        self.assertIn(error_message, str(context.exception))
        mock_account.find.assert_called_once_with(self.account_id)

    @patch('service.services.Account')
    def test_get_account_invalid_uuid(self, mock_account):
        """It should raise an AccountError when an invalid UUID format is provided."""
        invalid_account_id = 'invalid-uuid-format'
        mock_account.find.side_effect = ValueError('Invalid UUID format')
        with self.assertRaises(AccountError) as context:
            AccountService.get_account_or_404(invalid_account_id)
        self.assertIn(
            f"Invalid account ID format: {invalid_account_id}",
            str(context.exception)
        )
        mock_account.find.assert_called_once_with(invalid_account_id)


class TestHandleCacheError(TestCase):
    """The _handle_cache_error Function Tests."""

    def test_handle_cache_error_raises_account_error(self):
        """It should log the error and raise an AccountError with the appropriate error message."""
        error_message = 'cache failure occurred'
        test_exception = Exception(error_message)
        error_type = "type error"

        # Assert that AccountError is raised when the static method is called.
        with self.assertRaises(AccountError) as context:
            # pylint: disable=W0212
            AccountService._handle_cache_error(
                test_exception,
                error_type
            )

        self.assertEqual(str(context.exception), error_message)


class TestGetCachedData(TestCase):
    """The _get_cached_data Function Tests."""

    def test_get_cached_data_success(self):
        """It should return the cached data when cache.get succeeds."""
        expected_value = 'cached_result'

        with patch("service.services.cache") as mock_cache:
            mock_cache.get.return_value = expected_value

            # pylint: disable=W0212
            result = AccountService._get_cached_data(ACCOUNT_CACHE_KEY)

            self.assertEqual(result, expected_value)
            mock_cache.get.assert_called_once_with(ACCOUNT_CACHE_KEY)

    def test_get_cached_data_error(self):
        """It should log an error and raise AccountError when cache.get raises an exception."""
        exception_message = "Simulated cache failure"

        with patch("service.services.cache") as mock_cache, \
                patch("service.services.app") as mock_app:
            # Configure cache.get to raise an exception.
            mock_cache.get.side_effect = AccountError(exception_message)

            with self.assertRaises(AccountError) as context:
                # pylint: disable=W0212
                AccountService._get_cached_data(ACCOUNT_CACHE_KEY)

            self.assertIn(exception_message, str(context.exception))

            mock_app.logger.error.assert_called_once()
            log_call_arg = mock_app.logger.error.call_args[0][0]
            self.assertIn(exception_message, log_call_arg)


class TestCheckIfUserIsOwner(TestCase):
    """The check_if_user_is_owner Function Tests."""

    #
    # def setUp(self):
    #     """It should set up valid user IDs for testing."""
    #     # Prepare a valid UUID string for tests.
    #     self.valid_uuid_str = str(uuid4())
    #     self.valid_uuid = UUID(self.valid_uuid_str)
    #
    # def test_is_owner_true(self):
    #     """It should return True when the account exists and the user_id matches
    #     the account's user_id."""
    #     # Create a dummy account with the same user_id.
    #     dummy_account = DummyAccount(self.valid_uuid, self.valid_uuid)
    #     with patch(
    #             'service.models.Account.find_by_user_id',
    #             return_value=dummy_account
    #     ):
    #         is_owner = AccountService.check_if_user_is_owner(
    #             self.valid_uuid_str,
    #             self.valid_uuid
    #         )
    #         self.assertTrue(is_owner)
    #
    # def test_is_owner_false_due_to_different_account(self):
    #     """It should return False when the account exists but the user_id does not match."""
    #     # Create a dummy account with a different user_id.
    #     dummy_account = DummyAccount(
    #         self.valid_uuid,
    #         uuid4()
    #     )  # Different UUID
    #     with patch(
    #             'service.models.Account.find_by_user_id',
    #             return_value=dummy_account
    #     ):
    #         is_owner = AccountService.check_if_user_is_owner(
    #             self.valid_uuid_str,
    #             self.valid_uuid
    #         )
    #         self.assertFalse(is_owner)

    ######################################################################

    @patch('service.services.Account')
    def test_user_is_owner(self, mock_account):
        """It should return True when the account exists and the user_id matches
         the account's user_id."""
        test_account_user_id = uuid4()
        valid_user_id_str = str(uuid4())  # a valid UUID string for the user
        account_obj = MagicMock()
        account_obj.user_id = test_account_user_id
        mock_account.find_by_user_id.return_value = account_obj

        result = AccountService.check_if_user_is_owner(
            valid_user_id_str,
            test_account_user_id
        )

        self.assertTrue(result)
        mock_account.find_by_user_id.assert_called_once_with(
            UUID(valid_user_id_str)
        )

    @patch('service.services.Account')
    def test_user_not_owner_due_to_different_user_id(self, mock_account):
        """It should return False when the account exists but the user_id does not match."""
        expected_account_user_id = uuid4()
        valid_user_id_str = str(uuid4())
        account_obj = MagicMock()
        # Set the account object's user_id to a different UUID than expected.
        account_obj.user_id = uuid4()
        mock_account.find_by_user_id.return_value = account_obj

        result = AccountService.check_if_user_is_owner(
            valid_user_id_str,
            expected_account_user_id
        )

        self.assertFalse(result)
        mock_account.find_by_user_id.assert_called_once_with(
            UUID(valid_user_id_str))

    @patch('service.services.Account')
    def test_account_not_found_returns_false(self, mock_account):
        """It should return False when no account is found."""
        valid_user_id_str = str(uuid4())
        account_user_id = uuid4()
        # Simulate no account found.
        mock_account.find_by_user_id.return_value = None

        result = AccountService.check_if_user_is_owner(
            valid_user_id_str,
            account_user_id
        )

        self.assertFalse(result)
        mock_account.find_by_user_id.assert_called_once_with(
            UUID(valid_user_id_str))

    @patch('service.services.Account')
    def test_invalid_uuid_raises_account_error(self, mock_account):
        """It should raise an AccountError when an invalid user UUID string is provided."""
        invalid_user_id = 'not-a-valid-uuid'
        account_user_id = uuid4()

        with self.assertRaises(AccountError) as context:
            AccountService.check_if_user_is_owner(
                invalid_user_id,
                account_user_id
            )
        self.assertIn('Invalid user ID format', str(context.exception))
        mock_account.find_by_user_id.assert_not_called()

    @patch('service.services.Account')
    def test_unexpected_exception_raises_account_error(self, mock_account):
        """It should raise an AccountError when an unexpected exception occurs during
        the ownership check."""
        valid_user_id_str = str(uuid4())
        account_user_id = uuid4()
        # Simulate an unexpected exception when calling Account.find_by_user_id.
        mock_account.find_by_user_id.side_effect = Exception(
            'Unexpected error'
        )

        with self.assertRaises(AccountError) as context:
            AccountService.check_if_user_is_owner(
                valid_user_id_str,
                account_user_id
            )
        self.assertIn(
            'Error checking ownership for user ID',
            str(context.exception)
        )
        mock_account.find_by_user_id.assert_called_once_with(
            UUID(valid_user_id_str)
        )


class TestAuthorizeAccount(TestCase):
    """The authorize_account Function Tests."""

    def setUp(self):
        self.current_user_id = TEST_USER_ID
        self.account_user_id = uuid4()

    @patch('service.services.get_user_roles')
    @patch('service.services.AccountService.check_if_user_is_owner')
    def test_authorize_account_as_admin(
            self,
            mock_check_owner,
            mock_get_roles
    ):
        """It should authorize an admin user regardless of ownership."""
        # Simulate that get_user_roles returns a list including admin role.
        mock_get_roles.return_value = [ROLE_ADMIN, ROLE_USER]
        # Even if owner check returns False, admin should pass.
        mock_check_owner.return_value = False

        # Should not raise an exception
        try:
            AccountService.authorize_account(
                self.current_user_id,
                self.account_user_id
            )
        except Exception as err:  # pylint: disable=W0703
            self.fail(f"Authorization failed unexpectedly for admin: {err}")

        # Ensure get_user_roles was called, owner check might not even be needed
        # (depending on implementation).
        mock_get_roles.assert_called_once()
        # In our implementation, if ROLE_ADMIN exists, check_if_user_is_owner is not called.
        mock_check_owner.assert_not_called()

    @patch('service.services.get_user_roles')
    @patch('service.services.AccountService.check_if_user_is_owner')
    def test_authorize_account_as_owner(
            self,
            mock_check_owner,
            mock_get_roles
    ):
        """It should authorize a non-admin if they are the owner."""
        # Simulate that get_user_roles returns roles without admin.
        mock_get_roles.return_value = [ROLE_USER]
        # Simulate that the user is the owner.
        mock_check_owner.return_value = True

        try:
            AccountService.authorize_account(
                self.current_user_id,
                self.account_user_id
            )
        except Exception as err:  # pylint: disable=W0703
            self.fail(f"Authorization failed unexpectedly for owner: {err}")

        mock_get_roles.assert_called_once()
        mock_check_owner.assert_called_once_with(
            self.current_user_id,
            self.account_user_id
        )

    @patch('service.services.get_user_roles')
    @patch('service.services.AccountService.check_if_user_is_owner')
    def test_authorize_account_not_authorized(
            self,
            mock_check_owner,
            mock_get_roles
    ):
        """It should not authorize a non-admin user if they are not the owner."""
        # Return roles that do not include admin.
        mock_get_roles.return_value = [ROLE_USER]
        # Simulate that the user is not the owner.
        mock_check_owner.return_value = False

        with self.assertRaises(AccountAuthorizationError) as context:
            AccountService.authorize_account(
                self.current_user_id,
                self.account_user_id
            )

        # Check that the exception message includes the forbidden update message.
        self.assertIn(
            FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE,
            str(context.exception)
        )
        mock_get_roles.assert_called_once()
        mock_check_owner.assert_called_once_with(
            self.current_user_id,
            self.account_user_id
        )


class TestInvalidateAllAccountPages(TestCase):
    """The invalidate_all_account_pages Function Tests."""

    @patch('service.services.cache')
    @patch('service.services.app')
    def test_invalidate_all_success(self, mock_app, mock_cache):
        """It should ensure that cache.clear() is called successfully and that two debug messages
        are logged: one before and one after the cache clearing."""
        AccountService.invalidate_all_account_pages()

        # Assert that the debug log messages were called
        mock_app.logger.debug.assert_any_call(
            'Invalidating all cached results...'
        )
        mock_app.logger.debug.assert_any_call(
            'All cache has been successfully invalidated.'
        )
        # Assert that cache.clear() was called once.
        mock_cache.clear.assert_called_once()

    @patch('service.services.cache')
    @patch('service.services.app')
    def test_invalidate_all_connection_error(self, mock_app, mock_cache):
        """It should log the appropriate error message if cache.clear()
        raises a ConnectionError."""
        connection_error = ConnectionError('Redis down')
        mock_cache.clear.side_effect = connection_error

        AccountService.invalidate_all_account_pages()

        # Verify that the connection error was logged via logger.error
        mock_app.logger.error.assert_called_once_with(
            'Redis connection error during cache invalidation: %s',
            connection_error
        )
        # The initial debug should still be logged.
        mock_app.logger.debug.assert_any_call(
            'Invalidating all cached results...'
        )

    @patch('service.services.cache')
    @patch('service.services.app')
    def test_invalidate_all_unexpected_exception(self, mock_app, mock_cache):
        """It should log the error with the proper message if cache.clear() raises
        an unexpected exception."""
        unexpected_error = Exception('Unknown error')
        mock_cache.clear.side_effect = unexpected_error

        AccountService.invalidate_all_account_pages()

        # Verify that the error message for unexpected errors is logged.
        mock_app.logger.error.assert_called_once_with(
            'Error invalidating cache: %s',
            unexpected_error
        )
        mock_app.logger.debug.assert_any_call(
            'Invalidating all cached results...'
        )

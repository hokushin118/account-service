"""
Account Service.

This module provides the AccountService class, which encapsulates the business logic
for handling Account operations. It includes functionality for listing accounts
with pagination, utilizing caching for improved performance, and generating ETag
hashes for cache validation.
"""
import logging
import os
from typing import Any, Dict, Tuple, Optional
from uuid import UUID

from flask_jwt_extended import get_jwt_identity

from service import app, cache
from service.common.constants import ACCOUNT_CACHE_KEY, ROLE_ADMIN
from service.common.keycloak_utils import get_user_roles
from service.common.utils import generate_etag_hash
from service.errors import (
    AccountNotFoundError,
    AccountError,
    AccountAuthorizationError
)
from service.models import Account
from service.schemas import (
    AccountDTO,
    UpdateAccountDTO,
    PartialUpdateAccountDTO, CreateAccountDTO
)

logger = logging.getLogger(__name__)

CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 3600))
FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE = 'You are not authorized to modify this resource.'


class AccountService:
    """Service class for handling Account operations."""

    ######################################################################
    # HELPER METHODS
    ######################################################################
    @staticmethod
    def get_account_or_404(account_id: UUID) -> Account:
        """Retrieves an account by its UUID or aborts the request with a 404 error if not found.

        This method attempts to find an account in the database using the provided `account_id`.
        If the account is found, it is returned. If not, the request is immediately aborted
        with an HTTP 404 Not Found status, and an error message is displayed indicating
        that the account could not be found.

        Args:
            account_id (UUID): The unique identifier of the account to retrieve.

        Returns:
            Account: The found account object.

        Raises:
            AccountNotFoundError: If the account with the given `account_id` does not exist.
            AccountError: if the UUID format is invalid.
        """
        try:
            account = Account.find(account_id)

            if not account:
                app.logger.warning(
                    f"Account with id {account_id} could not be found."
                )
                raise AccountNotFoundError(account_id)
            return account
        except ValueError as err:
            logger.error("Invalid UUID %s provided: %s", account_id, err)
            raise AccountError(
                f"Invalid account ID format: {account_id}"
            ) from err

    @staticmethod
    def check_if_user_is_owner(
            user_id: str,
            account_user_id: UUID
    ) -> bool:
        """Checks if the given user ID matches the account's user ID, indicating ownership.

        This method efficiently determines if a user, identified by their user ID, is the
        owner of an account. It retrieves the account associated with the
        provided user ID and directly compares the account's user ID with the
        provided account user ID.

        Args:
            user_id (str): The user ID of the potential owner (as a string).
            account_user_id (UUID): The UUID of the account's user ID to verify ownership.

        Returns:
            bool: True if the user is the owner of the account, False otherwise.

        Raises:
            AccountError: If an error occurs during the ownership check.
        """
        try:
            user_uuid = UUID(user_id)
            account = Account.find_by_user_id(user_uuid)
            return account is not None and account.user_id == account_user_id
        except ValueError as err:
            logger.error("Invalid UUID %s string provided: %s", user_id, err)
            raise AccountError(f"Invalid user ID format: {user_id}") from err
        except Exception as err:  # pylint: disable=W0703
            logger.error(
                "An unexpected error occurred during ownership check: %s", err
            )
            raise AccountError(
                f"Error checking ownership for user ID: {user_id}"
            ) from err

    @staticmethod
    def authorize_account(
            current_user_id: str,
            account_user_id: UUID
    ) -> None:
        """Authorizes a user to access and modify an account.

        This function checks if the user has the necessary permissions to access
        and modify the specified account. It first checks for the 'admin' role.
        If the user is not an admin, it checks if the user is the owner of the account.

        Args:
            current_user_id (str): The ID of the currently logged-in user.
            account_user_id (UUID): The ID of the account's owner.

        Raises:
            AccountAuthorizationError: If the user does not have permission.
        """
        # Retrieve user roles
        roles = get_user_roles()
        app.logger.debug('Roles: %s', roles)

        if ROLE_ADMIN not in roles:
            # If not ROLE_ADMIN, check ownership шf admin, then skip ownership check.
            # Check if the logged-in user is the owner of the resource
            if not AccountService.check_if_user_is_owner(
                    current_user_id,
                    account_user_id
            ):
                app.logger.warning(
                    "User %s does not have permission to access resource %s for modification.",
                    current_user_id,
                    account_user_id
                )
                raise AccountAuthorizationError(
                    current_user_id,
                    FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE,
                    roles
                )

    @staticmethod
    def invalidate_all_account_pages() -> None:
        """Invalidate all cached results.

        This function clears the cache and logs the process. If a Redis connection error occurs,
        it logs an error message indicating the connection issue. Any unexpected
        exceptions will also be logged.
        """
        app.logger.debug('Invalidating all cached results...')

        try:
            cache.clear()
            app.logger.debug('All cache has been successfully invalidated.')
        except ConnectionError as err:
            app.logger.error(
                'Redis connection error during cache invalidation: %s',
                err
            )
        except Exception as err:  # pylint: disable=W0703
            app.logger.error('Error invalidating cache: %s', err)

    @staticmethod
    def _get_cached_data(cache_key: str) -> Optional[Any]:
        """Retrieves data from the cache, handling potential errors.

        Args:
            cache_key (str): The key to retrieve from the cache.

        Returns:
            Optional[Any]: The cached data if successful, or None if an error occurred.

        Raises:
            AccountError: If there's an issue retrieving data from the cache.
        """
        try:
            return cache.get(cache_key)
        except Exception as err:  # pylint: disable=W0703
            error_message = f"Failed to retrieve cached account data due to: {err}"
            app.logger.error(error_message)
            raise AccountError(
                error_message
            ) from err

    @staticmethod
    def _handle_cache_error(err: Exception, error_type: str) -> None:
        """Handles and logs cache-related errors, then raises an AccountError.

        Args:
            err (Exception): The exception that occurred.
            error_type (str): A string describing the type of error (e.g., 'type error').
        Raises:
            AccountError: An exception indicating a caching failure.
        """
        error_message = str(err)
        app.logger.error(
            "Failed to cache account due to %s: %s",
            error_type,
            error_message
        )
        raise AccountError(error_message)

    ######################################################################
    # CREATE A NEW ACCOUNT
    ######################################################################
    @staticmethod
    def create(create_account_dto: CreateAccountDTO) -> Dict[str, str]:
        """Creates a new account using the given data and current user ID.

        Args:
            create_account_dto (CreateAccountDTO): The data transfer object containing
                the account creation data.

        Returns:
            Dict[str, str]: A dictionary representing the created account.

        Raises:
            ValidationError: If the provided data is invalid.
            DatabaseError: If an error occurs while creating the account in the database.
        """
        app.logger.info('Service - Request to create an Account...')

        # Get the user identity from the JWT token
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Create account with provided JSON payload
        account = Account()
        account.deserialize(create_account_dto.to_dict())
        account.user_id = current_user_id
        account.create()

        app.logger.info(
            'Account created successfully.'
        )

        # Invalidate specific cache key(s)
        AccountService.invalidate_all_account_pages()
        app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

        return AccountDTO.from_orm(account).to_dict()

    ######################################################################
    # LIST ALL ACCOUNTS
    ######################################################################
    @staticmethod
    def list_accounts(page: int, per_page: int) -> Tuple[Dict[str, Any], str]:
        """Lists accounts with pagination and returns data together with an ETag hash.

        This method retrieves a paginated list of accounts, either from the cache
        or from the database. It validates the JWT token, obtains the user identity,
        and generates an ETag hash for the data.

        Args:
            page (int): The page number for pagination.
            per_page (int): The number of items per page.

        Returns:
            Tuple[Dict[str, Any], str]: A tuple containing:
                - A dictionary with paginated account data:
                    - 'items': A list of account dictionaries.
                    - 'page': The current page number.
                    - 'per_page': The number of items per page.
                    - 'total': The total number of accounts.
                - The ETag hash as a string.

        Raises:
            AccountError: If there's an issue retrieving data from the cache or database.
        """
        app.logger.info('Service - Request to list Accounts...')

        # Validate JWT token and obtain user identity.
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Cache key for paginated results (include page and per_page)
        cache_key = f"{ACCOUNT_CACHE_KEY}:{page}:{per_page}"

        # Attempt to retrieve cached data
        cached_data = AccountService._get_cached_data(cache_key)

        if cached_data:
            app.logger.debug('Retrieving Accounts (page %d) from cache.', page)
            paginated_data, etag_hash = cached_data
        else:
            app.logger.debug(
                "Fetching Accounts (page %d) from database.",
                page
            )

            accounts = Account.all_paginated(page=page, per_page=per_page)
            account_list = [
                AccountDTO.from_orm(account).to_dict() for account in accounts
            ]

            total_accounts = Account.query.count()

            # Paginate the results
            paginated_data = {
                'items': account_list,
                'page': page,
                'per_page': per_page,
                'total': total_accounts
            }

            # Generate the ETag:
            etag_hash = generate_etag_hash(paginated_data)
            cache.set(
                cache_key,
                (paginated_data, etag_hash),
                timeout=CACHE_DEFAULT_TIMEOUT
            )

        if paginated_data['items']:
            app.logger.debug(
                "Returning %d accounts (page %d)",
                len(paginated_data['items']),
                page
            )
        return paginated_data, etag_hash

    ######################################################################
    # READ AN ACCOUNT
    ######################################################################
    @staticmethod
    def get_account_by_id(account_id: UUID) -> Tuple[AccountDTO, str]:
        """Retrieves an account by its ID, using cache if available.

        This method first validates the JWT token and obtains the user identity.
        It then attempts to retrieve the account data from the cache. If the data
        is not found in the cache, it fetches the account from the database,
        converts it to a DTO, generates an ETag hash, and caches the data.

        Args:
            account_id (UUID): The ID of the account to retrieve.

    Returns:
        Tuple[AccountDTO, str]: A tuple containing:
            - AccountDTO: The account data in DTO format.
            - str: The generated ETag hash corresponding to the account data.

        Raises:
            AccountNotFound: If the account with the given ID is not found in the database.
            CacheError: If an error occurs while interacting with the cache.
        """
        app.logger.info(
            "Service - Request to read an Account with id: %s", account_id
        )

        # Validate JWT token and obtain user identity.
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        cache_key = f"{ACCOUNT_CACHE_KEY}:{account_id}"

        # Attempt to retrieve cached data
        cached_data = AccountService._get_cached_data(cache_key)

        if cached_data:
            app.logger.debug('Retrieving Account from cache...')
            data, etag_hash = cached_data
            account_dto = AccountDTO.model_validate(data)
        else:
            app.logger.debug('Fetching Account from database...')
            account = AccountService.get_account_or_404(account_id)

            # Convert SQLAlchemy model to DTO
            account_dto = AccountDTO.model_validate(account)
            data = account_dto.model_dump()

            # Generate the ETag
            etag_hash = generate_etag_hash(data)

        # Cache the data
        try:
            cache.set(
                cache_key,
                (data, etag_hash),
                timeout=CACHE_DEFAULT_TIMEOUT
            )
        except (TypeError, ValueError, AttributeError) as err:
            AccountService._handle_cache_error(err, type(err).__name__)
        except Exception as err:  # pylint: disable=W0703
            AccountService._handle_cache_error(err, 'unknown error')

        app.logger.debug(f"Account returned: {account_dto.model_dump()}")

        return account_dto, etag_hash

    ######################################################################
    # UPDATE AN EXISTING ACCOUNT
    ######################################################################
    @staticmethod
    def update_by_id(
            account_id: UUID,
            update_account_dto: UpdateAccountDTO
    ) -> AccountDTO:
        """Updates an existing account with the provided data payload.

        Retrieves the account, authorizes the user, updates the account
        with the data from the DTO, invalidates the cache, and returns
        the updated account as a dictionary.

        Args:
            account_id (UUID): The ID of the account to update.
            update_account_dto (UpdateAccountDTO): The DTO containing the update data.

        Returns:
            AccountDTO: The updated account in DTO format.

        Raises:
            AccountNotFound: If the account with the given ID is not found.
            AccountAuthorizationError: If the user is not authorized to update the account.
            DataValidationError: If there's an error updating the account in the database.
        """
        app.logger.info(
            "Service - Request to update an Account with id: %s",
            account_id
        )

        # Get the user identity from the JWT token
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Retrieve the account to be updated or return a 404 error if not found
        account = AccountService.get_account_or_404(account_id)

        # Authorizes a user to access and modify an account
        AccountService.authorize_account(
            current_user_id,
            account.user_id
        )

        # Update account with provided JSON payload
        account.name = update_account_dto.name
        account.email = update_account_dto.email
        account.address = update_account_dto.address
        account.gender = update_account_dto.gender
        account.phone_number = update_account_dto.phone_number

        # Persist the updated account to the database
        account.update()

        # Convert the persisted model into a DTO
        account_dto = AccountDTO.model_validate(account)

        app.logger.info(
            "Account with id %s updated successfully.",
            account_id
        )

        # Invalidate specific cache key(s)
        AccountService.invalidate_all_account_pages()
        app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

        return account_dto

    ######################################################################
    # PARTIAL UPDATE AN EXISTING ACCOUNT
    ######################################################################
    @staticmethod
    def partial_update_by_id(
            account_id: UUID,
            update_account_dto: PartialUpdateAccountDTO
    ) -> Dict[str, str]:
        """Partially updates an existing account with the provided data payload.

        Retrieves the account, authorizes the user, updates the account
        with the data from the DTO, invalidates the cache, and returns
        the updated account as a dictionary.

        Args:
            account_id (UUID): The ID of the account to update.
            update_account_dto (PartialUpdateAccountDTO): The DTO containing
            the update data.

        Returns:
            Dict[str, str]: A dictionary representation of the updated account.

        Raises:
            AccountNotFound: If the account with the given ID is not found.
            AccountAuthorizationError: If the user is not authorized to update the account.
            DataValidationError: If there's an error updating the account in the database.
        """
        app.logger.info(
            "Service - Request to partially update an Account with id: %s",
            account_id
        )

        # Get the user identity from the JWT token
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Retrieve the account to be updated or return a 404 error if not found
        account = AccountService.get_account_or_404(account_id)

        # Authorizes a user to access and modify an account
        AccountService.authorize_account(
            current_user_id,
            account.user_id
        )

        account.partial_update(update_account_dto.to_dict())
        account.update()
        app.logger.info(
            "Account with id %s updated successfully.",
            account_id
        )

        # Invalidate specific cache key(s)
        AccountService.invalidate_all_account_pages()
        app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

        return AccountDTO.from_orm(account).to_dict()

    ######################################################################
    # DELETE AN ACCOUNT
    ######################################################################
    @staticmethod
    def delete_by_id(account_id: UUID) -> None:
        """Deletes an existing account if the user is authorized.

        Returns:
            None: If the account is deleted successfully or if an error occurs.

        Raises:
            AccountNotFoundError: If the account with the given ID is not found.
            AuthorizationError: If the user is not authorized to delete the account.
        """
        app.logger.info(
            "Service - Request to delete an Account with id: %s",
            account_id
        )

        # Get the user identity from the JWT token
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Retrieve the account to be updated or return a 404 error if not found
        try:
            account = AccountService.get_account_or_404(account_id)
        except AccountNotFoundError:
            return None

        # Authorizes a user to access and modify an account
        AccountService.authorize_account(
            current_user_id,
            account.user_id
        )

        account.delete()
        app.logger.info(
            "Account with id %s deleted successfully.",
            account_id
        )

        # Invalidate specific cache key(s)
        AccountService.invalidate_all_account_pages()
        app.logger.debug("Cache key %s invalidated.", ACCOUNT_CACHE_KEY)

        return None

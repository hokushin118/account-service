"""
Account Service.

This module provides the AccountService class, which encapsulates the business logic
for handling Account operations. It includes functionality for listing accounts
with pagination, utilizing caching for improved performance, and generating ETag
hashes for cache validation.
"""
import logging
import os
from typing import Any, Dict, Tuple
from uuid import UUID

from flask_jwt_extended import get_jwt_identity

from service import app, cache
from service.common.constants import ACCOUNT_CACHE_KEY
from service.common.utils import generate_etag_hash
from service.errors import AccountNotFoundError, AccountError
from service.models import Account
from service.schemas import AccountDTO

logger = logging.getLogger(__name__)

CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 3600))


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
        """
        account = Account.find(account_id)
        if not account:
            app.logger.warning(
                f"Account with id {account_id} could not be found."
            )
            raise AccountNotFoundError(account_id)
        return account

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
    # LIST ALL ACCOUNTS
    ######################################################################
    @staticmethod
    def list_accounts(page: int, per_page: int) -> Tuple[Dict[str, Any], str]:
        """Lists accounts with pagination and returns data together with an ETag hash.

        Args:
            page (int): The page number for pagination.
            per_page (int): The number of items per page.

        Returns:
            Tuple[Dict[str, Any], str]: A tuple containing the paginated data as a dictionary
            and the ETag hash as a string.
        """
        app.logger.info('Service - Request to list Accounts...')

        # Validate JWT token and obtain user identity.
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        # Cache key for paginated results (include page and per_page)
        cache_key = f"{ACCOUNT_CACHE_KEY}:{page}:{per_page}"

        # Attempt to retrieve cached data
        cached_data = cache.get(cache_key)

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
                AccountDTO.from_orm(account).dict() for account in accounts
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
    def get_account_by_id(account_id: UUID) -> (Dict, str):
        """Retrieves an account by its ID, using cache if available."""
        app.logger.info(
            "Service - Request to read an Account with id: %s", account_id
        )

        # Validate JWT token and obtain user identity.
        current_user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', current_user_id)

        cache_key = f"{ACCOUNT_CACHE_KEY}:{account_id}"

        # Attempt to retrieve cached data
        cached_data = cache.get(cache_key)

        if cached_data:
            app.logger.debug('Retrieving Account from cache...')
            data, etag_hash = cached_data
        else:
            app.logger.debug('Fetching Account from database...')
            account = AccountService.get_account_or_404(account_id)

            # Convert SQLAlchemy model to DTO
            account_dto = AccountDTO.from_orm(account)
            data = account_dto.dict()

            # Generate the ETag:
            etag_hash = generate_etag_hash(data)

        # Cache the data
        try:
            cache.set(
                cache_key,
                (data, etag_hash),
                timeout=CACHE_DEFAULT_TIMEOUT
            )
        except TypeError as err:
            AccountService._handle_cache_error(
                err,
                'type error'
            )
        except ValueError as err:
            AccountService._handle_cache_error(
                err,
                'value error'
            )
        except AttributeError as err:
            AccountService._handle_cache_error(
                err,
                'attribute error'
            )
        except Exception as err:  # pylint: disable=W0703
            AccountService._handle_cache_error(
                err,
                'unknown error'
            )

        app.logger.debug(f"Account returned: {data}")

        return data, etag_hash

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

from service import app, cache
from service.common.constants import ACCOUNT_CACHE_KEY
from service.common.utils import generate_etag_hash
from service.models import Account
from service.schemas import AccountDTO

logger = logging.getLogger(__name__)

CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 3600))


class AccountService:
    """Service class for handling Account operations."""

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

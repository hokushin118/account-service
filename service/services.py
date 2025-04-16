"""
Account Service.

This module provides the AccountService class, which encapsulates the business logic
for handling Account operations. It includes functionality for listing accounts
with pagination, utilizing caching for improved performance, and generating ETag
hashes for cache validation.
"""
import logging
from typing import Any, Tuple, Optional, Callable
from uuid import UUID

from cba_core_lib.utils import generate_etag_hash
from cba_core_lib.utils.enums import UserRole
from cba_core_lib.utils.env_utils import get_int_from_env
from flask_jwt_extended import get_jwt_identity
from pybreaker import CircuitBreaker, CircuitBreakerError
from redis.exceptions import ConnectionError as RedisConnectionError
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

from service import app, cache
from service.common.constants import ACCOUNT_CACHE_KEY
from service.common.keycloak_utils import get_user_roles
from service.errors import (
    AccountNotFoundError,
    AccountError,
    AccountAuthorizationError
)
from service.models import Account
from service.schemas import (
    AccountDTO,
    UpdateAccountDTO,
    PartialUpdateAccountDTO,
    CreateAccountDTO,
    AccountPagedListDTO
)

logger = logging.getLogger(__name__)

CACHE_DEFAULT_TIMEOUT = get_int_from_env('CACHE_DEFAULT_TIMEOUT', 3600)
FORBIDDEN_UPDATE_THIS_RESOURCE_ERROR_MESSAGE = 'You are not authorized to modify this resource.'

# Maximum retry attempts
CACHE_RETRY_ATTEMPTS = get_int_from_env(
    'CACHE_RETRY_ATTEMPTS',
    3
)
# Initial delay in seconds
CACHE_RETRY_BASE_DELAY = get_int_from_env(
    'CACHE_RETRY_BASE_DELAY',
    1
)
# Maximum delay in seconds
CACHE_RETRY_MAX_DELAY = get_int_from_env(
    'CACHE_RETRY_MAX_DELAY',
    10
)
# Maximum consecutive failures before opening the circuit
CIRCUIT_BREAKER_FAIL_MAX = get_int_from_env(
    'CIRCUIT_BREAKER_FAIL_MAX',
    5
)
# Time (in seconds) the circuit breaker stays open before attempting to close
CIRCUIT_BREAKER_RESET_TIMEOUT = get_int_from_env(
    'CIRCUIT_BREAKER_RESET_TIMEOUT',
    30
)


class AccountServiceCache:
    """Handles caching logic for AccountService."""

    @staticmethod
    def get_cached_data(cache_key: str) -> Optional[Any]:
        """Retrieves data from the cache, handling potential errors.

        Args:
            cache_key (str): The key to retrieve from the cache.

        Returns:
            Optional[Any]: The cached data if successful, or None if an error occurred.
        """
        app.logger.debug('Retrieving account data...')
        try:
            cached_data = AccountServiceCache._cache_operation(
                cache.get,
                cache_key
            )
            if cached_data and isinstance(cached_data, tuple) and len(
                    cached_data
            ) == 2:
                return cached_data
            return None
        except Exception as err:  # pylint: disable=W0703
            error_message = f"Failed to retrieve cached account data due to: {err}"
            app.logger.error(error_message)
            return None

    @staticmethod
    def cache_account(cache_key: str, data: dict, etag_hash: str) -> None:
        """Caches account data in Redis with retry logic for transient errors.

        This method attempts to store account data in the Redis cache. It uses
        the `_cache_operation` helper function to apply retry logic in case of
        transient errors like network issues or temporary Redis unavailability.

        Args:
            cache_key (str): The key under which to store the account data.
            data (dict): The account data to be cached.
            etag_hash (str): The ETag hash associated with the account data.

        Returns:
            None: This method does not return a value.

        Raises:
            AccountError: If there's an error during the caching process, even after retries.

        Example:
            To cache account data:

           AccountServiceCache.cache_account(
               'account:123', {'name': 'Test Account'}, 'some_etag_hash'
           )
        """
        app.logger.debug('Caching account data...')
        try:
            AccountServiceCache._cache_operation(
                cache.set,
                cache_key,
                (data, etag_hash),
                timeout=CACHE_DEFAULT_TIMEOUT
            )
        except Exception as err:  # pylint: disable=W0703
            AccountServiceCache._handle_cache_error(err, 'unknown error')

    @staticmethod
    def invalidate_all_account_pages() -> None:
        """Invalidates all cached account pages in Redis with retry logic.

        This method clears the entire Redis cache, effectively invalidating all
        cached account data. It uses the `_cache_operation` helper function to
        apply retry logic in case of transient errors, such as network issues
        or temporary Redis unavailability.

        If a Redis connection error occurs during the invalidation process,
        it logs an error message indicating the connection issue. Any unexpected
        exceptions will also be logged.

        Returns:
            None: This method does not return a value.

        Example:
            To invalidate all cached account pages:

            AccountServiceCache.invalidate_all_account_pages()
        """
        app.logger.debug('Invalidating all cached results...')
        try:
            AccountServiceCache._cache_operation(cache.clear)
            app.logger.debug('All cache has been successfully invalidated.')
        except RedisConnectionError as err:
            app.logger.error(
                'Redis connection error during cache invalidation: %s',
                err
            )
        except Exception as err:  # pylint: disable=W0703
            app.logger.error('Error invalidating cache: %s', err)

    @staticmethod
    @retry(
        stop=stop_after_attempt(CACHE_RETRY_ATTEMPTS),
        wait=wait_exponential(
            multiplier=1,
            min=CACHE_RETRY_BASE_DELAY,
            max=CACHE_RETRY_MAX_DELAY
        ),
        retry=retry_if_exception_type(
            (
                    TypeError,
                    ValueError,
                    AttributeError,
                    RedisConnectionError
            )
        ),
        reraise=True,
    )
    def _cache_operation(
            func: Callable[..., Any],
            *args: Any,
            **kwargs: Any
    ) -> Any:
        """Applies retry logic to cache operations using the tenacity library.

        This helper function wraps a given function (`func`) that interacts with the
        cache, applying a retry strategy to handle transient errors. It uses exponential
        backoff to increase the delay between retries, ensuring that the system doesn't
        overwhelm the cache server during periods of instability.

        Args:
            func (callable): The function to execute, typically a cache operation
                             (e.g., `cache.get`, `cache.set`, `cache.clear`).
            *args: Variable length argument list to pass to `func`.
            **kwargs: Arbitrary keyword arguments to pass to `func`.

        Returns:
            Any: The result of the wrapped function `func` if successful.

        Raises:
            TypeError, ValueError, AttributeError, RedisConnectionError:
                If any of these exceptions occur during the cache operation, the function
                will be retried up to 3 times. If all retries fail, the last exception
                is re-raised.

        Retry Strategy:
            - Maximum 3 retry attempts.
            - Exponential backoff with a base delay of 1 second, increasing up to a maximum
              of 10 seconds between retries.
            - Retries are triggered by `TypeError`, `ValueError`, `AttributeError`, or
              `RedisConnectionError` exceptions.

        Example:
            To retry a cache get operation:

            result = _cache_operation(cache.get, 'my_key')

            To retry a cache set operation:

            _cache_operation(cache.set, 'my_key', 'my_value', timeout=3600)
        """
        return func(*args, **kwargs)

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


class AccountServiceHelper:
    """Helper methods for AccountService.

    This class provides static methods to assist the AccountService with common tasks,
    such as retrieving user IDs from JWTs and fetching account data with ETags.
    """

    @staticmethod
    def get_user_id_from_jwt() -> str:
        """Retrieves the user ID from the JWT token.

        This method extracts the user's identity from the JSON Web Token (JWT)
        present in the request's authorization header. It logs the retrieved
        user ID for debugging purposes.

        Returns:
            str: The user ID extracted from the JWT.

        Raises:
            JWTError: If there is an issue with the JWT processing.
        """
        user_id = get_jwt_identity()
        app.logger.debug('Current user ID: %s', user_id)
        return user_id

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
    def get_account_dto_and_etag(account_id: UUID) -> Tuple[AccountDTO, str]:
        """Fetches an account from the database, converts it to a DTO, and generates an ETag.

        This method retrieves an account from the database using the provided account ID.
        It then converts the account object into an AccountDTO (Data Transfer Object)
        and generates an ETag based on the DTO's data.

        Args:
            account_id (UUID): The unique ID of the account to retrieve.

        Returns:
            Tuple[AccountDTO, str]: A tuple containing the AccountDTO and the generated ETag.

        Raises:
            HTTPException 404: if the account is not found.
            Any other exception that AccountService.get_account_or_404 may raise.
        """
        account = AccountServiceHelper.get_account_or_404(account_id)
        # Convert SQLAlchemy model to DTO
        account_dto = AccountDTO.model_validate(account)
        data = account_dto.model_dump()
        # Generate the ETag
        etag_hash = generate_etag_hash(data)
        return account_dto, etag_hash

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

        if UserRole.ADMIN.value not in roles:
            # If not ROLE_ADMIN, check ownership шf admin, then skip ownership check.
            # Check if the logged-in user is the owner of the resource
            if not AccountServiceHelper._check_if_user_is_owner(
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
    def _check_if_user_is_owner(
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


class AccountService:
    """Service class for handling Account operations.

    This class provides an abstraction layer between the API routes and the persistence layer.
    It includes a static CircuitBreaker instance to ensure that account creation is resilient to
    repeated failures.

    Attributes:
        db_circuit_breaker (CircuitBreaker): A static circuit breaker for database operations that
            trips after 5 consecutive failures and resets after 30 seconds.
    """

    db_circuit_breaker = CircuitBreaker(
        fail_max=CIRCUIT_BREAKER_FAIL_MAX,
        reset_timeout=CIRCUIT_BREAKER_RESET_TIMEOUT,
        name='DatabaseCircuitBreaker'
    )

    ######################################################################
    # CREATE A NEW ACCOUNT
    ######################################################################
    @staticmethod
    def create(create_account_dto: CreateAccountDTO) -> AccountDTO:
        """Creates a new account using the given data and current user ID.

        Args:
            create_account_dto (CreateAccountDTO): The data transfer object containing
                the account creation data.

        Returns:
            AccountDTO: The newly created account in DTO format.

        Raises:
            ValidationError: If the provided data is invalid.
            DatabaseError: If an error occurs while creating the account in the database.
        """
        app.logger.info('Service - Request to create an Account...')

        # Get the user identity from the JWT token
        current_user_id = AccountServiceHelper.get_user_id_from_jwt()

        # Create account with provided JSON payload
        account = Account()
        account.deserialize(create_account_dto.to_dict())
        account.user_id = current_user_id

        # Persist the account to the database
        try:
            # The circuit breaker monitors failures and, if necessary, prevents execution
            with AccountService.db_circuit_breaker.calling():
                account.create()
        except CircuitBreakerError as err:
            app.logger.error(
                'Database circuit breaker is open during create operation.'
            )
            raise AccountError(
                'Database is temporarily unavailable.'
            ) from err
        except Exception as err:  # pylint: disable=W0703
            error_message = f'An error occurred: {err}'
            logger.error(error_message)
            raise AccountError(error_message) from err

        # Convert the persisted model into a DTO
        account_dto = AccountDTO.model_validate(account)

        app.logger.info(
            'Account created successfully.'
        )

        # Invalidate all cache keys
        AccountServiceCache.invalidate_all_account_pages()

        return account_dto

    ######################################################################
    # LIST ALL ACCOUNTS
    ######################################################################
    @staticmethod
    def list_accounts(
            page: int,
            per_page: int
    ) -> Tuple[AccountPagedListDTO, str]:
        """Lists accounts with pagination and returns data together with an ETag hash.

        This method retrieves a paginated list of accounts, either from the cache
        or from the database. It validates the JWT token, obtains the user identity,
        and generates an ETag hash for the data.

        Args:
            page (int): The page number for pagination.
            per_page (int): The number of items per page.

        Returns:
            Tuple[AccountPagedListDTO, str]: A tuple containing:
                - AccountPagedListDTO: The paginated account data.
                - str: The generated ETag hash identifying the data state.

        Raises:
            AccountError: If there's an issue retrieving data from the cache or database.
        """
        app.logger.info('Service - Request to list Accounts...')

        # Validate JWT token and obtain user identity.
        AccountServiceHelper.get_user_id_from_jwt()

        # Cache key for paginated results (include page and per_page)
        cache_key = f"{ACCOUNT_CACHE_KEY}:{page}:{per_page}"

        # Attempt to retrieve cached data
        cached_data = AccountServiceCache.get_cached_data(cache_key)

        if cached_data:
            app.logger.debug('Retrieving Accounts (page %d) from cache.', page)
            data, etag_hash = cached_data
            account_paginated_list_dto = AccountPagedListDTO.model_validate(
                data)
        else:
            app.logger.debug(
                "Fetching Accounts (page %d) from database.",
                page
            )

            try:
                # The circuit breaker monitors failures and, if necessary, prevents execution
                with AccountService.db_circuit_breaker.calling():
                    accounts = Account.all_paginated(
                        page=page,
                        per_page=per_page
                    )
            except CircuitBreakerError as err:
                app.logger.error(
                    'Database circuit breaker is open during list operation.'
                )
                raise AccountError(
                    'Database is temporarily unavailable.'
                ) from err
            except Exception as err:  # pylint: disable=W0703
                error_message = f'An error occurred: {err}'
                logger.error(error_message)
                raise AccountError(error_message) from err

            account_list = [
                AccountDTO.model_validate(account) for account in accounts
            ]

            total_accounts = Account.query.count()

            # Paginate the results
            data = {
                'items': account_list,
                'page': page,
                'per_page': per_page,
                'total': total_accounts
            }

            # Convert SQLAlchemy model to DTO
            account_paginated_list_dto = AccountPagedListDTO(**data)

            # Generate the ETag:
            etag_hash = generate_etag_hash(data)

            # Cache the data
            AccountServiceCache.cache_account(cache_key, data, etag_hash)

        if data['items']:
            app.logger.debug(
                "Returning %d accounts (page %d)",
                len(data['items']),
                page
            )

        return account_paginated_list_dto, etag_hash

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
        AccountServiceHelper.get_user_id_from_jwt()

        cache_key = f"{ACCOUNT_CACHE_KEY}:{account_id}"

        # Attempt to retrieve cached data
        cached_data = AccountServiceCache.get_cached_data(cache_key)

        if cached_data:
            app.logger.debug('Retrieving Account from cache...')
            data, etag_hash = cached_data
            account_dto = AccountDTO.model_validate(data)
        else:
            app.logger.debug('Fetching Account from database...')

            try:
                # The circuit breaker monitors failures and, if necessary, prevents execution
                with AccountService.db_circuit_breaker.calling():
                    account = AccountServiceHelper.get_account_or_404(
                        account_id
                    )
            except CircuitBreakerError as err:
                app.logger.error(
                    'Database circuit breaker is open during get account by id operation.'
                )
                raise AccountError(
                    'Database is temporarily unavailable.'
                ) from err
            except AccountNotFoundError:
                raise
            except Exception as err:  # pylint: disable=W0703
                error_message = f'An error occurred: {err}'
                logger.error(error_message)
                raise AccountError(error_message) from err

            # Convert SQLAlchemy model to DTO
            account_dto = AccountDTO.model_validate(account)
            data = account_dto.model_dump()

            # Generate the ETag
            etag_hash = generate_etag_hash(data)

        # Cache the data
        AccountServiceCache.cache_account(cache_key, data, etag_hash)

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
        current_user_id = AccountServiceHelper.get_user_id_from_jwt()

        # Retrieve the account to be updated or return a 404 error if not found
        account = AccountServiceHelper.get_account_or_404(account_id)

        # Authorizes a user to access and modify an account
        AccountServiceHelper.authorize_account(
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
        try:
            # The circuit breaker monitors failures and, if necessary, prevents execution
            with AccountService.db_circuit_breaker.calling():
                account.update()
        except CircuitBreakerError as err:
            app.logger.error(
                'Database circuit breaker is open during update account by id operation.'
            )
            raise AccountError(
                'Database is temporarily unavailable.'
            ) from err
        except Exception as err:  # pylint: disable=W0703
            error_message = f'An error occurred: {err}'
            logger.error(error_message)
            raise AccountError(error_message) from err

        # Convert the persisted model into a DTO
        account_dto = AccountDTO.model_validate(account)

        app.logger.info(
            "Account with id %s updated successfully.",
            account_id
        )

        # Invalidate all cache keys
        AccountServiceCache.invalidate_all_account_pages()

        return account_dto

    ######################################################################
    # PARTIAL UPDATE AN EXISTING ACCOUNT
    ######################################################################
    @staticmethod
    def partial_update_by_id(
            account_id: UUID,
            update_account_dto: PartialUpdateAccountDTO
    ) -> AccountDTO:
        """Partially updates an existing account with the provided data payload.

        Retrieves the account, authorizes the user, updates the account
        with the data from the DTO, invalidates the cache, and returns
        the updated account as a dictionary.

        Args:
            account_id (UUID): The ID of the account to update.
            update_account_dto (PartialUpdateAccountDTO): The DTO containing
            the update data.

        Returns:
            AccountDTO: The updated account in DTO format.

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
        current_user_id = AccountServiceHelper.get_user_id_from_jwt()

        # Retrieve the account to be updated or return a 404 error if not found
        account = AccountServiceHelper.get_account_or_404(account_id)

        # Authorizes a user to access and modify an account
        AccountServiceHelper.authorize_account(
            current_user_id,
            account.user_id
        )

        # Persist the updated account to the database
        try:
            # The circuit breaker monitors failures and, if necessary, prevents execution
            with AccountService.db_circuit_breaker.calling():
                # Update account with provided JSON payload
                account.partial_update(update_account_dto.to_dict())
                account.update()
        except CircuitBreakerError as err:
            app.logger.error(
                'Database circuit breaker is open during partial update account by id operation.'
            )
            raise AccountError(
                'Database is temporarily unavailable.'
            ) from err
        except Exception as err:  # pylint: disable=W0703
            error_message = f'An error occurred: {err}'
            logger.error(error_message)
            raise AccountError(error_message) from err

        # Convert the persisted model into a DTO
        account_dto = AccountDTO.model_validate(account)

        app.logger.info(
            "Account with id %s updated successfully.",
            account_id
        )

        # Invalidate all cache keys
        AccountServiceCache.invalidate_all_account_pages()

        return account_dto

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
        current_user_id = AccountServiceHelper.get_user_id_from_jwt()

        # Retrieve the account to be updated or return a 404 error if not found
        try:
            # The circuit breaker monitors failures and, if necessary, prevents execution
            with AccountService.db_circuit_breaker.calling():
                account = AccountServiceHelper.get_account_or_404(account_id)
        except AccountNotFoundError:
            return None
        except CircuitBreakerError as err:
            app.logger.error(
                'Database circuit breaker is open during delete account by id operation.'
            )
            raise AccountError(
                'Database is temporarily unavailable.'
            ) from err
        except Exception as err:  # pylint: disable=W0703
            error_message = f'An error occurred: {err}'
            logger.error(error_message)
            raise AccountError(error_message) from err

        # Authorizes a user to access and modify an account
        AccountServiceHelper.authorize_account(
            current_user_id,
            account.user_id
        )

        try:
            # The circuit breaker monitors failures and, if necessary, prevents execution
            with AccountService.db_circuit_breaker.calling():
                account.delete()
        except CircuitBreakerError as err:
            app.logger.error(
                'Database circuit breaker is open during delete account by id operation.'
            )
            raise AccountError(
                'Database is temporarily unavailable.'
            ) from err
        except Exception as err:  # pylint: disable=W0703
            error_message = f'An error occurred: {err}'
            logger.error(error_message)
            raise AccountError(error_message) from err

        app.logger.info(
            "Account with id %s deleted successfully.",
            account_id
        )

        # Invalidate all cache keys
        AccountServiceCache.invalidate_all_account_pages()

        return None

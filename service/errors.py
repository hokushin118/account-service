"""
Custom errors for Account microservice.

This module defines custom exception classes for the account service.
"""
from typing import Optional, Dict, Any, List
from uuid import UUID


class AccountError(Exception):
    """General exception class for account-related errors.

    This serves as a base class for specific account exceptions,
    providing common functionality for error handling and representation.

    Attributes:
        message (Optional[str]): A detailed error message.
    """

    def __init__(
            self,
            message: Optional[str] = None
    ) -> None:
        """Initialize a new AccountError exception.

        Args:
            message (Optional[str]): An optional custom error message.
                If None, no message is provided.
        """
        self.message = message
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation of the exception.

        Returns:
            Dict[str, Any]: A dictionary containing the error message.
        """
        return {'error': self.message}

    def __str__(self) -> str:
        """Return the error message as a string.

        Returns:
            str: The error message.
        """
        return self.message or ''


class AccountNotFoundError(AccountError):
    """Exception raised when an account is not found.

    Indicates that an account with the specified ID could not be located.
    It encapsulates the account ID and an optional custom error message.

    Attributes:
        account_id (UUID): The ID of the account that was not found.
    """

    def __init__(
            self,
            account_id: UUID,
            message: Optional[str] = None
    ) -> None:
        """Initialize a new AccountNotFoundError exception.

        Args:
            account_id (UUID): The ID of the account that was not found.
            message (Optional[str]): An optional custom error message.
                If None, a default message is used.
        """
        if message is None:
            message = f"Account with id {account_id} could not be found."
        super().__init__(message)
        self.account_id = account_id

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation of the exception.

        Includes the error message and the account ID as a string.

        Returns:
            Dict[str, Any]: A dictionary containing the error message and account ID.
        """
        return {
            'error': self.message,
            'account_id': str(self.account_id)
        }


class AccountAuthorizationError(AccountError):
    """Exception raised when an account is not authorized to perform an action.

    Indicates that an account with the specified ID does not have sufficient
    permissions to execute a requested operation.

    Attributes:
        user_id (UUID): The user ID of the account that is not authorized.
        roles (Optional[List[str]]): A list of roles associated with the account,
            representing the permissions or roles needed for the action.
    """

    def __init__(
            self,
            user_id: str,
            message: Optional[str] = None,
            roles: Optional[List[str]] = None
    ) -> None:
        """Initialize a new AccountAuthorizationError exception.

        Args:
            user_id (str): The ID of the account that is not authorized.
            message (Optional[str]): An optional custom error message.
                If None, a default message is used.
            roles (Optional[List[str]]): An optional list of roles associated with the account.
                If provided, it indicates the roles required, permitted,
                or associated with this error.
        """
        if message is None:
            message = f"Account with user id {user_id} is not authorized to perform this action."
        super().__init__(message)
        self.user_id = user_id
        self.roles = roles

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation of the exception.

        Includes the error message, account ID as a string, and associated roles if provided.

        Returns:
            Dict[str, Any]: A dictionary containing the error message, user ID, and roles.
        """
        error_dict = {
            'error': self.message,
            'user_id': self.user_id
        }
        if self.roles is not None:
            error_dict['roles'] = self.roles
        return error_dict

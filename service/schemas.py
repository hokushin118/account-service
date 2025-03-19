"""
Schemas for Account microservice.

All schemas are stored in this module.
"""
from datetime import date
from typing import Optional
from uuid import UUID

from pydantic import (
    BaseModel,
    validator,
    EmailStr, constr
)

from service.common.constants import (
    NAME_MIN_LENGTH,
    NAME_MAX_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH, GENDER_MAX_LENGTH
)


class AccountDTO(BaseModel):
    """Data Transfer Object for an account."""
    id: UUID  # UUID
    name: constr(
        min_length=NAME_MIN_LENGTH,
        max_length=NAME_MAX_LENGTH
    )  # Constrained name
    email: EmailStr  # Validated email
    gender: Optional[constr(max_length=GENDER_MAX_LENGTH)] = None
    address: Optional[constr(max_length=ADDRESS_MAX_LENGTH)] = None
    phone_number: Optional[constr(max_length=PHONE_MAX_LENGTH)] = None
    date_joined: date
    user_id: UUID

    @validator('name')
    # pylint: disable=no-self-argument
    def validate_name(cls, value: str) -> str:
        """Validates the name.

        Args:
            value: The name string to validate.

        Returns:
            The validated name string.

        Raises:
            ValueError: If the name is blank (empty or None).
        """
        if not value:
            raise ValueError(
                'Name can not be blank'
            )
        return value

    @validator('date_joined')
    # pylint: disable=no-self-argument
    def validate_date_joined(cls, value: date) -> date:
        """Validates date_joined (ISO 8601 format).

        Args:
            value: The date string to validate.

        Returns:
            The validated date string.

        Raises:
            ValueError: If the date format is invalid.
        """
        try:
            date.fromisoformat(str(value))
            return value
        except ValueError as err:
            raise ValueError(
                'Invalid date format. Use ISO 8601 (YYYY-MM-DD).'
            ) from err

    def to_dict(self) -> dict:
        """Serializes an AccountDTO into a dictionary.

        This method converts the AccountDTO instance into a Python dictionary,
        omitting any fields that have a value of None. This is useful for
        generating clean JSON responses or for data serialization where
        null values are not desired.
        """
        return self.model_dump(exclude_none=True)

    class Config:
        """Config class."""
        # pylint: disable=too-few-public-methods
        from_attributes = True
        # Allows the DTO to be populated by aliases
        populate_by_name = True


class CreateAccountDTO(BaseModel):
    """Data Transfer Object for creating an account."""

    name: constr(
        min_length=NAME_MIN_LENGTH,
        max_length=NAME_MAX_LENGTH
    )  # Constrained name
    email: EmailStr  # Validated email
    gender: Optional[constr(max_length=GENDER_MAX_LENGTH)] = None
    address: Optional[constr(max_length=ADDRESS_MAX_LENGTH)] = None
    phone_number: Optional[constr(max_length=PHONE_MAX_LENGTH)] = None

    @validator('name')
    # pylint: disable=no-self-argument
    def validate_name(cls, value: str) -> str:
        """Validates the name.

        Args:
            value: The name string to validate.

        Returns:
            The validated name string.

        Raises:
            ValueError: If the name is blank (empty or None).
        """
        if not value:
            raise ValueError(
                'Name can not be blank'
            )
        return value

    def to_dict(self) -> dict:
        """Serializes an CreateAccountDTO into a dictionary.

        This method converts the CreateAccountDTO instance into a Python
        dictionary, omitting any fields that have a value of None. This is
        useful for generating clean JSON responses or for data serialization
        where null values are not desired.
        """
        return self.model_dump(exclude_none=True)

    class Config:
        """Config class."""
        # pylint: disable=too-few-public-methods
        from_attributes = True
        # Allows the DTO to be populated by aliases
        populate_by_name = True


class UpdateAccountDTO(BaseModel):
    """Data Transfer Object for updating an account."""
    name: constr(
        min_length=NAME_MIN_LENGTH,
        max_length=NAME_MAX_LENGTH
    )  # Constrained name
    email: EmailStr  # Validated email
    gender: Optional[constr(max_length=GENDER_MAX_LENGTH)] = None
    address: Optional[constr(max_length=ADDRESS_MAX_LENGTH)] = None
    phone_number: Optional[constr(max_length=PHONE_MAX_LENGTH)] = None

    @validator('name')
    # pylint: disable=no-self-argument
    def validate_name(cls, value: str) -> str:
        """Validates the name.

        Args:
            value: The name string to validate.

        Returns:
            The validated name string.

        Raises:
            ValueError: If the name is blank (empty or None).
        """
        if not value:
            raise ValueError(
                'Name can not be blank'
            )
        return value

    def to_dict(self) -> dict:
        """Serializes an UpdateAccountDTO into a dictionary.

        This method converts the UpdateAccountDTO instance into a Python
        dictionary, omitting any fields that have a value of None. This is
        useful for generating clean JSON responses or for data serialization
        where null values are not desired.
        """
        return self.model_dump(exclude_none=True)

    class Config:
        """Config class."""
        # pylint: disable=too-few-public-methods
        from_attributes = True
        # Allows the DTO to be populated by aliases
        populate_by_name = True


class PartialUpdateAccountDTO(BaseModel):
    """Data Transfer Object for partially updating an account."""
    name: Optional[constr(
        min_length=NAME_MIN_LENGTH,
        max_length=NAME_MAX_LENGTH
    )] = None  # Constrained name
    email: Optional[EmailStr] = None  # Validated email
    gender: Optional[constr(max_length=GENDER_MAX_LENGTH)] = None
    address: Optional[constr(max_length=ADDRESS_MAX_LENGTH)] = None
    phone_number: Optional[constr(max_length=PHONE_MAX_LENGTH)] = None

    def to_dict(self) -> dict:
        """Serializes an PartialUpdateAccountDTO into a dictionary.

        This method converts the PartialUpdateAccountDTO instance into a Python
        dictionary, omitting any fields that have a value of None. This is
        useful for generating clean JSON responses or for data serialization
        where null values are not desired.
        """
        return self.model_dump(exclude_none=True)

    class Config:
        """Config class."""
        # pylint: disable=too-few-public-methods
        from_attributes = True
        # Allows the DTO to be populated by aliases
        populate_by_name = True

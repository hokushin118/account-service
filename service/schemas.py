"""
Schemas for Account microservice.

All schemas are stored in this module.
"""
from datetime import date
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, validator, EmailStr, constr

from service.common.constants import (
    NAME_MIN_LENGTH,
    NAME_MAX_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH, GENDER_MAX_LENGTH
)
from service.common.utils import account_to_dict


class AccountDTO(BaseModel):
    """Account DTO."""
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
        except ValueError as error:
            raise ValueError(
                'Invalid date format. Use ISO 8601 (YYYY-MM-DD).'
            ) from error

    def to_dict(self) -> dict:
        """Serializes an AccountDTO into a dictionary."""
        return account_to_dict(self)

    class Config:
        """Config class."""
        # pylint: disable=too-few-public-methods
        from_attributes = True

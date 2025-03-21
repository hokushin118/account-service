"""
Schemas for Account microservice.

All schemas are stored in this module.
"""
from datetime import date
from typing import Optional, List
from uuid import UUID

from pydantic import (
    BaseModel,
    field_validator,
    EmailStr,
    constr,
    Field
)

from service.common.constants import (
    NAME_MIN_LENGTH,
    NAME_MAX_LENGTH,
    ADDRESS_MAX_LENGTH,
    PHONE_MAX_LENGTH, GENDER_MAX_LENGTH
)

ALLOWED_GENDERS = {'male', 'female', 'other'}


######################################################################
# VALIDATION METHODS
######################################################################
def validate_name_value(value: str) -> str:
    """Validates the name string, ensuring it is not blank.

    This function checks if the provided name string is empty or None.
    If the name is valid (not blank), it is returned as is.

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


def validate_gender_value(value: Optional[str]) -> Optional[str]:
    """Validates the gender field against a predefined set of allowed values (case-insensitive).

    This validator checks if the provided gender value is one of the allowed values
    defined in the `ALLOWED_GENDERS` set, ignoring case. If the value is `None`, it is
    considered valid and returned as is. If the value is not in the allowed set, a
    `ValueError` is raised.

    Args:
        value: The gender value to validate (can be `None`).

    Returns:
        The validated gender value (can be `None`).

    Raises:
        ValueError: If the gender value is not in the `ALLOWED_GENDERS` set.
    """
    if value is not None:
        lower_value = value.lower()
        lower_allowed_genders = {gender.lower() for gender in ALLOWED_GENDERS}
        if lower_value not in lower_allowed_genders:
            raise ValueError(
                f"Invalid gender value: '{value}'. Allowed values are: "
                f"{ALLOWED_GENDERS} (case-insensitive)"
            )
    return value


######################################################################
# SCHEMAS
######################################################################
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

    @field_validator('name')
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
        return validate_name_value(value)

    @field_validator('gender')
    # pylint: disable=E0213
    def validate_gender(
            cls,
            value: Optional[str]
    ) -> Optional[str]:
        """Validates the gender field against a predefined set of allowed values.

        Args:
            cls: The class itself (used for accessing class-level attributes).
            value: The gender value to validate (can be `None`).

        Returns:
            The validated gender value (can be `None`).

        Raises:
            ValueError: If the gender value is not in the `ALLOWED_GENDERS` set.
        """
        return validate_gender_value(value)

    @field_validator('date_joined')
    # pylint: disable=E0213
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


class AccountPagedListDTO(BaseModel):
    """Data Transfer Object for a paginated list of accounts.

    This DTO wraps a list of AccountDTO objects with pagination metadata, including
    the current page, the number of items per page, and the total number of
    available accounts.
    """
    items: List[AccountDTO] = Field(
        description='List of AccountDTO objects for the current page.'
    )
    page: int = Field(
        1, ge=1, description='Current page number (1-indexed, starts from 1).'
    )
    per_page: int = Field(
        1, ge=1, description='Number of AccountDTO objects per page.'
    )
    total: int = Field(
        0, ge=0, description='Total number of available AccountDTO objects.'
    )


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

    @field_validator('name')
    # pylint: disable=E0213
    def validate_name(cls, value: str) -> str:
        """Validates the name.

        Args:
            value: The name string to validate.

        Returns:
            The validated name string.

        Raises:
            ValueError: If the name is blank (empty or None).
        """
        return validate_name_value(value)

    @field_validator('gender')
    # pylint: disable=E0213
    def validate_gender(
            cls,
            value: Optional[str]
    ) -> Optional[str]:
        """Validates the gender field against a predefined set of allowed values.

        Args:
            cls: The class itself (used for accessing class-level attributes).
            value: The gender value to validate (can be `None`).

        Returns:
            The validated gender value (can be `None`).

        Raises:
            ValueError: If the gender value is not in the `ALLOWED_GENDERS` set.
        """
        return validate_gender_value(value)

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

    @field_validator('name')
    # pylint: disable=E0213
    def validate_name(cls, value: str) -> str:
        """Validates the name.

        Args:
            value: The name string to validate.

        Returns:
            The validated name string.

        Raises:
            ValueError: If the name is blank (empty or None).
        """
        return validate_name_value(value)

    @field_validator('gender')
    # pylint: disable=E0213
    def validate_gender(
            cls,
            value: Optional[str]
    ) -> Optional[str]:
        """Validates the gender field against a predefined set of allowed values.

        Args:
            cls: The class itself (used for accessing class-level attributes).
            value: The gender value to validate (can be `None`).

        Returns:
            The validated gender value (can be `None`).

        Raises:
            ValueError: If the gender value is not in the `ALLOWED_GENDERS` set.
        """
        return validate_gender_value(value)

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

    @field_validator('gender')
    # pylint: disable=E0213
    def validate_gender(
            cls,
            value: Optional[str]
    ) -> Optional[str]:
        """Validates the gender field against a predefined set of allowed values.

        Args:
            cls: The class itself (used for accessing class-level attributes).
            value: The gender value to validate (can be `None`).

        Returns:
            The validated gender value (can be `None`).

        Raises:
            ValueError: If the gender value is not in the `ALLOWED_GENDERS` set.
        """
        return validate_gender_value(value)

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

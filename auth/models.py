"""Collection of pydantic model."""
from datetime import datetime
from typing import Dict, Optional
from uuid import UUID

import phonenumbers
from pydantic import BaseModel, EmailStr, Field, validator

from . import pwned, validators
from .settings import SETTINGS


class SessionVariables(BaseModel):
    """Schema for session variables data."""

    x_hasura_role: str = Field(None, alias="x-hasura-role")


class HasuraAction(BaseModel):
    """Schema for hasura action data."""

    name: str


class HasuraData(BaseModel):
    """Schema for hasura data data."""

    session_variables: SessionVariables

    action: HasuraAction


class HasuraEventDate(BaseModel):
    """Schema for hasura event data."""

    old: Optional[Dict]

    new: Dict


class HasuraEvent(BaseModel):
    """Schema for hasura event data."""

    session_variables: SessionVariables

    data: HasuraEventDate


class HasuraEventTrigger(BaseModel):
    """Schema for hasura trigger event data."""

    event: HasuraEvent


class UserModel(BaseModel):
    """Schema for user table data."""

    id: Optional[UUID] = None

    username: Optional[str] = None

    email: Optional[str] = None

    password: Optional[str] = None

    first_name: Optional[str] = None

    last_name: Optional[str] = None

    phone_number: Optional[str] = None

    picture_url: Optional[str] = None

    role: Optional[str] = None

    employs: Optional[list[dict]] = None

    gender: Optional[str] = None

    is_active: Optional[bool] = None

    is_email_verified: Optional[bool] = None

    last_login: Optional[datetime] = None

    created_at: Optional[datetime] = None

    updated_at: Optional[datetime] = None


class SignupData(BaseModel):
    """Schema for signup data."""

    username: str

    email: EmailStr = ""

    password: str = Field(
        ...,
        min_length=SETTINGS.MINIMUM_PASSWORD_LENGTH,
        max_length=SETTINGS.MAXIMUM_PASSWORD_LENGTH,
    )

    first_name: str

    last_name: str

    phone_number: str

    gender: str

    @validator("username")
    def extra_validation_on_username(cls: "SignupData", value: str) -> str:  # noqa B902
        """Extra Validation for the username.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The username value from an input.

        Returns:
            The username if it is valid.
        """
        validators.validate_reserved_name(value=value, exception_class=ValueError)

        validators.validate_confusables(value=value, exception_class=ValueError)

        return value

    @validator("password")
    def extra_validation_on_password(cls: "SignupData", value: str) -> str:  # noqa B902
        """Extra Validation for the password.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The password value from an input.

        Returns:
            The password if it is valid.

        Raises:
            ValueError: If password is pwned or connection error it return 422 status.
        """
        result = pwned.pwned_password(password=value)

        if result is None:
            raise ValueError("Connection error, try again")

        if result > 0:
            raise ValueError(
                f"Oh no — pwned! This password has been seen {result} times before"
            )

        else:
            return value

    @validator("email")
    def extra_validation_on_email(
        cls: "SignupData", value: Optional[str]  # noqa B902
    ) -> str:
        """Extra Validation for the email.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The email value from an input.

        Returns:
            The email if it is valid.
        """
        if value:
            local_part, domain = value.split("@")

            validators.validate_reserved_name(
                value=local_part, exception_class=ValueError
            )

            validators.validate_confusables_email(
                domain=domain, local_part=local_part, exception_class=ValueError
            )

        return value

    @validator("phone_number")
    def extra_validation_on_phone_number(
        cls: "SignupData", value: str  # noqa B902
    ) -> str:
        """Extra Validation for the phone number.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The phone number value from an input.

        Returns:
            The phone number if it is valid.

        Raises:
            ValueError: If phone_number is invalid it return 422 status.
        """
        try:
            phone_number = phonenumbers.parse(value, None)
            if not phonenumbers.is_valid_number(
                phone_number
            ) or not phonenumbers.is_possible_number(phone_number):
                raise ValueError("Invalid phone number")
        except Exception as error:
            raise ValueError(error)

        return value


class SignupInput(BaseModel):
    """Schema for signup input data."""

    data: SignupData


class Signup(HasuraData):
    """Schema for signup data."""

    input: SignupInput


class SignInData(BaseModel):
    """Schema for sign in data."""

    username: str = ""

    phone_number: str = ""

    password: str


class SignInInput(BaseModel):
    """Schema for sign in input data."""

    data: SignInData


class SignIn(HasuraData):
    """Schema for sign in data."""

    input: SignInInput


class SignInOutput(BaseModel):
    """Schema for sign in outputs data."""

    access_token: str

    refresh_token: str

    token_type: str


class ChangePasswordData(BaseModel):
    """Schema for change password data."""

    old_password: str

    new_password: str = Field(
        ...,
        min_length=SETTINGS.MINIMUM_PASSWORD_LENGTH,
        max_length=SETTINGS.MAXIMUM_PASSWORD_LENGTH,
    )

    new_password_confirm: str

    @validator("new_password")
    def extra_validation_on_new_password(
        cls: "ChangePasswordData", value: str  # noqa B902
    ) -> str:
        """Extra Validation for the new_password.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The password value from an input.

        Returns:
            The new_password if it is valid.

        Raises:
            ValueError: If new_password is pwned or connection error it return 422 status
        """
        result = pwned.pwned_password(password=value)

        if result is None:
            raise ValueError("Connection error, try again")

        if result > 0:
            raise ValueError(
                f"Oh no — pwned! This password has been seen {result} times before"
            )

        else:
            return value

    @validator("new_password_confirm")
    def passwords_match(
        cls: "ChangePasswordData", value: str, values: Dict[str, str]  # noqa B902
    ) -> str:
        """Checking if the new_password and new_password_confirm are equal."""
        if "new_password" in values and value != values["new_password"]:
            raise ValueError("new_password do not match new_password_confirm")
        return value


class ChangePasswordInput(BaseModel):
    """Schema for change password input data."""

    data: ChangePasswordData


class ChangePassword(HasuraData):
    """Schema for change password."""

    input: ChangePasswordInput


class PasswordResetData(BaseModel):
    """Schema for password reset data."""

    email: EmailStr


class PasswordResetInput(BaseModel):
    """Schema for password reset input data."""

    data: PasswordResetData


class PasswordReset(HasuraData):
    """Schema for password reset."""

    input: PasswordResetInput


class PasswordResetConfirmData(BaseModel):
    """Schema for password reset confirm data."""

    token: str

    email: EmailStr

    password: str = Field(
        ...,
        min_length=SETTINGS.MINIMUM_PASSWORD_LENGTH,
        max_length=SETTINGS.MAXIMUM_PASSWORD_LENGTH,
    )

    @validator("password")
    def extra_validation_on_password(
        cls: "PasswordResetConfirmData", value: str  # noqa B902
    ) -> str:
        """Extra Validation for the password.

        Args:
            cls: It the same as self # noqa: DAR102
            value: The password value from an input.

        Returns:
            The password if it is valid.

        Raises:
            ValueError: If password is pwned or connection error it return 422 status
        """
        result = pwned.pwned_password(password=value)

        if result is None:
            raise ValueError("Connection error, try again")

        if result > 0:
            raise ValueError(
                f"Oh no — pwned! This password has been seen {result} times before"
            )

        else:
            return value


class PasswordResetConfirmInput(BaseModel):
    """Schema for password reset confirm input data."""

    data: PasswordResetConfirmData


class PasswordResetConfirm(HasuraData):
    """Schema for password reset confirm."""

    input: PasswordResetConfirmInput


class EmailVerifyConfirmData(BaseModel):
    """Schema for email verify data."""

    token: str


class EmailVerifyInput(BaseModel):
    """Schema for email verify input."""

    data: EmailVerifyConfirmData


class EmailVerifyConfirm(HasuraData):
    """Schema for email verify."""

    input: EmailVerifyInput


class ChangeEmailData(BaseModel):
    """Schema for change email data."""

    email: EmailStr


class ChangeEmailInput(BaseModel):
    """Schema for change email input."""

    data: ChangeEmailData


class ChangeEmail(HasuraData):
    """Schema for change email."""

    input: ChangeEmailInput


class CreateManagerData(SignupData):
    """Schema for create manager data."""

    organization: UUID


class CreateManagerInput(BaseModel):
    """Schema for create manager data."""

    data: CreateManagerData


class CreateManager(HasuraData):
    """Schema for create manager schema."""

    input: CreateManagerInput

import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.home_fields import (
    MAX_HOME_NAME_LENGTH,
    InvalidCurrencyError,
    InvalidHomeNameError,
    normalize_currency,
    normalize_home_name,
)
from app.models.home import Home

# Requests: unknown fields (user_id, id, name_key, timestamps) rejected; input never echoed.
_REQUEST_CONFIG = ConfigDict(extra="forbid", hide_input_in_errors=True)
# Generous enough for padding/combining marks; anything longer is refused before normalising.
_MAX_RAW_NAME = MAX_HOME_NAME_LENGTH * 4
_MAX_RAW_CURRENCY = 8
_RAW_NAME = Field(min_length=1, max_length=_MAX_RAW_NAME)
_RAW_CURRENCY = Field(min_length=1, max_length=_MAX_RAW_CURRENCY)


def _name(value: str) -> str:
    try:
        return normalize_home_name(value)
    except InvalidHomeNameError:
        raise ValueError("invalid home name") from None


def _currency(value: str) -> str:
    try:
        return normalize_currency(value)
    except InvalidCurrencyError:
        raise ValueError("invalid currency code") from None


class HomeCreate(BaseModel):
    model_config = _REQUEST_CONFIG

    name: str = _RAW_NAME
    currency: str = _RAW_CURRENCY

    @field_validator("name")
    @classmethod
    def _normalize_name(cls, value: str) -> str:
        return _name(value)

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        return _currency(value)


class HomeUpdate(BaseModel):
    """Partial update: omitted fields keep their stored value; null and `{}` are refused."""

    model_config = _REQUEST_CONFIG

    name: str | None = Field(default=None, min_length=1, max_length=_MAX_RAW_NAME)
    currency: str | None = Field(default=None, min_length=1, max_length=_MAX_RAW_CURRENCY)

    @field_validator("name", "currency", mode="before")
    @classmethod
    def _reject_null(cls, value: Any) -> Any:
        # Runs only for values actually sent: an explicit null is an error, absence is not.
        if value is None:
            raise ValueError("must not be null")
        return value

    @field_validator("name")
    @classmethod
    def _normalize_name(cls, value: str) -> str:
        return _name(value)

    @field_validator("currency")
    @classmethod
    def _normalize_currency(cls, value: str) -> str:
        return _currency(value)

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class HomeRead(BaseModel):
    """The only home shape the API returns: no owner id, no internal name key."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    name: str
    currency: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_home(cls, home: Home) -> HomeRead:
        return cls.model_validate(home)


class HomeList(BaseModel):
    # Wrapped so pagination can be added later without breaking clients.
    items: list[HomeRead]

from __future__ import annotations

from .errors import InvalidInputError

__all__ = [
    "require_positive_int",
    "require_bytes",
    "require_optional_bytes",
    "require_non_empty_bytes",
]


def require_positive_int(value: int, *, field_name: str) -> None:
    """
    Validate that a value is a strict positive integer.

    :param value: Integer value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not a strict positive integer.
    """
    if type(value) is not int or value <= 0:
        raise InvalidInputError(f"{field_name} must be a positive integer")


def require_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is bytes.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not bytes.
    """
    if not isinstance(value, bytes):
        raise InvalidInputError(f"{field_name} must be bytes")


def require_optional_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is bytes or None.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is neither bytes nor None.
    """
    if value is not None and not isinstance(value, bytes):
        raise InvalidInputError(f"{field_name} must be bytes or None")


def require_non_empty_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is non-empty bytes.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not bytes or is empty.
    """
    require_bytes(value, field_name = field_name)
    if value == b"":
        raise InvalidInputError(f"{field_name} must not be empty")

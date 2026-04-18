from __future__ import annotations

from typing import Type

from .errors import InvalidRecordError, NodeDBError

__all__ = [
    "require_instance",
    "require_optional_instance",
    "require_bytes",
    "require_non_empty_bytes",
    "require_str",
    "require_non_empty_str",
    "require_int",
    "require_positive_int",
    "require_non_negative_int",
    "require_optional_str",
    "require_limit",
    "require_offset",
]


def _type_name(expected_type: type | tuple[type, ...]) -> str:
    """
    Build a deterministic human-readable type name.

    :param expected_type: expected type or tuple of types
    :return: human-readable type name string
    """
    if isinstance(expected_type, tuple):
        return " | ".join(tp.__name__ for tp in expected_type)
    return expected_type.__name__


def require_instance(value: object, expected_type: type | tuple[type, ...],
                     *, field_name: str, error_cls: Type[NodeDBError] = InvalidRecordError) -> None:
    """
    Validate that a value is an instance of the expected type.

    :param value: value to validate
    :param expected_type: expected type or tuple of types
    :param field_name: field name used in error messages
    :param error_cls: exception class to raise on failure
    :raises InvalidRecordError: by default, if the value has the wrong type.
    """
    if not isinstance(value, expected_type):
        raise error_cls(f"{field_name} must be {_type_name(expected_type)}")


def require_optional_instance(value: object, expected_type: type | tuple[type, ...],
                              *, field_name: str, error_cls: Type[NodeDBError] = InvalidRecordError) -> None:
    """
    Validate that a value is either None or an instance of the expected type.

    :param value: value to validate
    :param expected_type: expected type or tuple of types
    :param field_name: field name used in error messages
    :param error_cls: exception class to raise on failure
    :raises InvalidRecordError: by default, if the value is neither None nor expected type.
    """
    if value is not None:
        require_instance(
            value,
            expected_type,
            field_name = field_name,
            error_cls = error_cls,
        )


def require_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is bytes.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not bytes.
    """
    require_instance(value, bytes, field_name = field_name)


def require_non_empty_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is non-empty bytes.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not bytes or is empty.
    """
    require_bytes(value, field_name = field_name)
    if value == b"":
        raise InvalidRecordError(f"{field_name} must not be empty")


def require_str(value: object, *, field_name: str) -> None:
    """
    Validate that a value is str.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not str.
    """
    require_instance(value, str, field_name = field_name)


def require_non_empty_str(value: object, *, field_name: str) -> None:
    """
    Validate that a value is non-empty str.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not str or is empty.
    """
    require_str(value, field_name = field_name)
    if value == "":
        raise InvalidRecordError(f"{field_name} must not be empty")


def require_int(value: object, *, field_name: str) -> None:
    """
    Validate that a value is a strict int.

    Boolean values are rejected even though bool is a subclass of int in Python.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not a strict int.
    """
    if type(value) is not int:
        raise InvalidRecordError(f"{field_name} must be int")


def require_positive_int(value: object, *, field_name: str) -> None:
    """
    Validate that a value is a strict positive int.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not a strict positive int.
    """
    require_int(value, field_name = field_name)
    if value <= 0:
        raise InvalidRecordError(f"{field_name} must be a positive integer")


def require_non_negative_int(value: object, *, field_name: str) -> None:
    """
    Validate that a value is a strict non-negative int.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not a strict non-negative int.
    """
    require_int(value, field_name = field_name)
    if value < 0:
        raise InvalidRecordError(f"{field_name} must be a non-negative integer")


def require_optional_str(value: object, *, field_name: str) -> None:
    """
    Validate that a value is either None or a non-empty str.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is neither None nor a non-empty str.
    """
    if value is None:
        return
    require_non_empty_str(value, field_name = field_name)


def require_limit(value: object, *, field_name: str = "limit",
                  max_value: int | None = None) -> None:
    """
    Validate bounded fetch size for list operations.

    :param value: value to validate
    :param field_name: field name used in error messages
    :param max_value: optional inclusive upper bound for the limit
    :raises InvalidRecordError: if the value is not a valid bounded limit.
    """
    require_positive_int(value, field_name = field_name)

    if max_value is not None:
        require_positive_int(max_value, field_name = "max_value")
        if value > max_value:
            raise InvalidRecordError(f"{field_name} must be <= {max_value}")


def require_offset(value: object, *, field_name: str = "offset") -> None:
    """
    Validate offset for list operations.

    :param value: value to validate
    :param field_name: field name used in error messages
    :raises InvalidRecordError: if the value is not a valid non-negative offset.
    """
    require_non_negative_int(value, field_name = field_name)

from __future__ import annotations

from typing import Any, Type

from ..errors import MalformedDataError, MeshCryptoError
from .validation import require_instance

__all__ = [
    "require_field_instance",
    "require_str_field",
    "require_int_field",
    "require_dict_field",
]


def require_field_instance(data: dict[str, Any], field_name: str,
                           expected_type: type | tuple[type, ...], *,
                           error_cls: Type[MeshCryptoError] = MalformedDataError) -> Any:
    """
    Extract and validate a required field of the expected type.

    :param data: Source mapping.
    :param field_name: Required field name.
    :param expected_type: Expected field type or tuple of types.
    :param error_cls: Exception class to raise on failure.
    :return: Field value.
    :raises MalformedDataError: By default, if the field is missing or invalid.
    """
    value = data.get(field_name)
    require_instance(value, expected_type,
                     field_name = field_name, error_cls = error_cls)
    return value


def require_str_field(data: dict[str, Any], field_name: str,
                      *, error_cls: Type[MeshCryptoError] = MalformedDataError) -> str:
    """
    Extract and validate a required string field.

    :param data: Source mapping.
    :param field_name: Required field name.
    :param error_cls: Exception class to raise on failure.
    :return: String field value.
    """
    return require_field_instance(data, field_name,
                                  str, error_cls = error_cls)


def require_int_field(data: dict[str, Any], field_name: str,
                      *, error_cls: Type[MeshCryptoError] = MalformedDataError) -> int:
    """
    Extract and validate a required strict integer field.

    Boolean values are rejected even though bool is a subclass of int in Python.

    :param data: Source mapping.
    :param field_name: Required field name.
    :param error_cls: Exception class to raise on failure.
    :return: Integer field value.
    """
    value = data.get(field_name)
    if type(value) is not int:
        raise error_cls(f"missing or invalid integer field '{field_name}'")
    return value


def require_dict_field(data: dict[str, Any], field_name: str,
                       *, error_cls: Type[MeshCryptoError] = MalformedDataError) -> dict[str, Any]:
    """
    Extract and validate a required dictionary field.

    :param data: Source mapping.
    :param field_name: Required field name.
    :param error_cls: Exception class to raise on failure.
    :return: Dictionary field value.
    """
    return require_field_instance(data, field_name,
                                  dict, error_cls = error_cls)

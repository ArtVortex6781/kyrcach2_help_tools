from __future__ import annotations

from typing import Any, Type

from ..errors import MalformedDataError, MeshCryptoError, UnsupportedFormatError
from .validation import require_instance

__all__ = [
    "require_field_instance",
    "require_str_field",
    "require_int_field",
    "require_dict_field",
    "require_required_keys",
    "require_allowed_keys",
    "require_exact_keys",
    "require_supported_version",
    "require_supported_type",
    "require_supported_algorithm",
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


def require_required_keys(data: dict[str, Any], required_keys: set[str], *, schema_name: str,
                          error_cls: Type[MeshCryptoError] = MalformedDataError) -> None:
    actual_keys = set(data.keys())
    missing = required_keys - actual_keys

    if missing:
        raise error_cls(f"{schema_name} missing keys: {sorted(missing)}")


def require_allowed_keys(data: dict[str, Any], allowed_keys: set[str], *, schema_name: str,
                         error_cls: Type[MeshCryptoError] = MalformedDataError) -> None:
    actual_keys = set(data.keys())
    extra = actual_keys - allowed_keys

    if extra:
        raise error_cls(f"{schema_name} contains unexpected keys: {sorted(extra)}")


def require_exact_keys(data: dict[str, Any], expected_keys: set[str], *, schema_name: str,
                       error_cls: Type[MeshCryptoError] = MalformedDataError) -> None:
    require_allowed_keys(
        data,
        expected_keys,
        schema_name = schema_name,
        error_cls = error_cls,
    )
    require_required_keys(
        data,
        expected_keys,
        schema_name = schema_name,
        error_cls = error_cls,
    )


def _allowed_int_values(allowed: int | set[int] | frozenset[int]) -> set[int] | frozenset[int]:
    """
    Normalize allowed integer values.

    :param allowed: Single allowed integer or set/frozenset of integers.
    :return: Allowed integer values.
    """
    if type(allowed) is int:
        return {allowed}
    return allowed


def _allowed_str_values(allowed: str | set[str] | frozenset[str]) -> set[str] | frozenset[str]:
    """
    Normalize allowed string values.

    :param allowed: Single allowed string or set/frozenset of strings.
    :return: Allowed string values.
    """
    if isinstance(allowed, str):
        return {allowed}
    return allowed


def require_supported_version(value: int, allowed: int | set[int] | frozenset[int], *,
                              field_name: str = "version",
                              error_cls: Type[MeshCryptoError] = UnsupportedFormatError) -> None:
    """
    Validate that a parsed version value is supported.

    Type validation should be performed before this helper, for example through
    require_int_field() or require_int().

    :param value: Parsed version value.
    :param allowed: Supported version or set/frozenset of supported versions.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on failure.
    :raises UnsupportedFormatError: By default, if version is unsupported.
    """
    allowed_values = _allowed_int_values(allowed)

    if value not in allowed_values:
        raise error_cls(
            f"unsupported {field_name}: {value}; expected one of {sorted(allowed_values)}"
        )


def require_supported_type(value: str, allowed: str | set[str] | frozenset[str], *,
                           field_name: str = "type",
                           error_cls: Type[MeshCryptoError] = UnsupportedFormatError) -> None:
    """
    Validate that a parsed envelope/message type is supported.

    Type validation should be performed before this helper, for example through
    require_str_field() or require_str().

    :param value: Parsed type value.
    :param allowed: Supported type or set/frozenset of supported types.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on failure.
    :raises UnsupportedFormatError: By default, if type is unsupported.
    """
    allowed_values = _allowed_str_values(allowed)

    if value not in allowed_values:
        raise error_cls(
            f"unsupported {field_name}: {value}; expected one of {sorted(allowed_values)}"
        )


def require_supported_algorithm(value: str, allowed: str | set[str] | frozenset[str], *,
                                field_name: str = "algorithm",
                                error_cls: Type[MeshCryptoError] = UnsupportedFormatError) -> None:
    """
    Validate that a parsed algorithm identifier is supported.

    Type validation should be performed before this helper, for example through
    require_str_field() or require_str().

    :param value: Parsed algorithm value.
    :param allowed: Supported algorithm or set/frozenset of supported algorithms.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on failure.
    :raises UnsupportedFormatError: By default, if algorithm is unsupported.
    """
    allowed_values = _allowed_str_values(allowed)

    if value not in allowed_values:
        raise error_cls(
            f"unsupported {field_name}: {value}; expected one of {sorted(allowed_values)}"
        )

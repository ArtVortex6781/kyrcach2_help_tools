from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .errors import InvalidInputError, WrongKeyTypeError

__all__ = [
    "require_instance",
    "require_optional_instance",
    "require_bytes",
    "require_non_empty_bytes",
    "require_str",
    "require_non_empty_str",
    "require_int",
    "require_positive_int",
    "require_exact_length_bytes",
    "require_min_length_bytes",
    "require_ed25519_private_key",
    "require_ed25519_public_key",
    "require_x25519_private_key",
    "require_x25519_public_key",
    "require_symmetric_key_bytes",
    "require_nonce_length",
    "require_aesgcm_key_length",
    "VALID_AES_KEY_LENGTHS",
    "SCRYPT_MIN_SALT_LEN"
]

VALID_AES_KEY_LENGTHS = {16, 24, 32}
SCRYPT_MIN_SALT_LEN = 16


# ==============================
# Base type validators
# ==============================

def _type_name(expected_type: type | tuple[type, ...]) -> str:
    """
    Build a deterministic human-readable type name.

    :param expected_type: Expected type or tuple of types.
    :return: Human-readable type name string.
    """
    if isinstance(expected_type, tuple):
        return " | ".join(tp.__name__ for tp in expected_type)
    return expected_type.__name__


def require_instance(value: object, expected_type: type | tuple[type, ...],
                     *, field_name: str, error_cls: type[Exception] = InvalidInputError) -> None:
    """
    Validate that a value is an instance of the expected type.

    :param value: Value to validate.
    :param expected_type: Expected type or tuple of types.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on failure.
    :raises InvalidInputError: By default, if the value has the wrong type.
    """
    if not isinstance(value, expected_type):
        raise error_cls(f"{field_name} must be {_type_name(expected_type)}")


def require_optional_instance(value: object, expected_type: type | tuple[type, ...], *,
                              field_name: str, error_cls: type[Exception] = InvalidInputError) -> None:
    """
    Validate that a value is either None or an instance of the expected type.

    :param value: Value to validate.
    :param expected_type: Expected type or tuple of types.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on failure.
    :raises InvalidInputError: By default, if the value is neither None nor expected type.
    """
    if value is not None:
        require_instance(
            value,
            expected_type,
            field_name = field_name,
            error_cls = error_cls,
        )


# ==============================
# Common value validators
# ==============================

def require_bytes(value: object, *, field_name: str) -> None:
    """
    Validate that a value is bytes.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not bytes.
    """
    require_instance(value, bytes, field_name = field_name)


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


def require_str(value: object, *, field_name: str) -> None:
    """
    Validate that a value is str.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not str.
    """
    require_instance(value, str, field_name = field_name)


def require_non_empty_str(value: object, *, field_name: str) -> None:
    """
    Validate that a value is non-empty str.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not str or is empty.
    """
    require_str(value, field_name = field_name)
    if value == "":
        raise InvalidInputError(f"{field_name} must not be empty")


def require_int(value: object, *, field_name: str) -> None:
    """
    Validate that a value is a strict int.

    Boolean values are rejected even though bool is a subclass of int in Python.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not a strict int.
    """
    if type(value) is not int:
        raise InvalidInputError(f"{field_name} must be int")


def require_positive_int(value: object, *, field_name: str) -> None:
    """
    Validate that a value is a strict positive int.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not a strict positive int.
    """
    require_int(value, field_name = field_name)
    if value <= 0:
        raise InvalidInputError(f"{field_name} must be a positive integer")


def require_exact_length_bytes(value: object, *, field_name: str, length: int) -> None:
    """
    Validate that a value is bytes of exact length.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :param length: Expected exact length in bytes.
    :raises InvalidInputError: If the value is not bytes or length does not match.
    """
    require_bytes(value, field_name = field_name)
    if len(value) != length:
        raise InvalidInputError(f"{field_name} must be exactly {length} bytes")


def require_min_length_bytes(value: object, *, field_name: str, min_length: int) -> None:
    """
    Validate that a value is bytes with at least the specified length.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :param min_length: Minimum allowed length in bytes.
    :raises InvalidInputError: If the value is not bytes or is too short.
    """
    require_bytes(value, field_name = field_name)
    require_positive_int(min_length, field_name = "min_length")

    if len(value) < min_length:
        raise InvalidInputError(f"{field_name} must be at least {min_length} bytes")


# ==============================
# Crypto-specific validators
# ==============================

def require_ed25519_private_key(value: object, *, field_name: str) -> None:
    """
    Validate that a value is Ed25519PrivateKey.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises WrongKeyTypeError: If the value is not Ed25519PrivateKey.
    """
    require_instance(
        value,
        Ed25519PrivateKey,
        field_name = field_name,
        error_cls = WrongKeyTypeError,
    )


def require_ed25519_public_key(value: object, *, field_name: str) -> None:
    """
    Validate that a value is Ed25519PublicKey.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises WrongKeyTypeError: If the value is not Ed25519PublicKey.
    """
    require_instance(
        value,
        Ed25519PublicKey,
        field_name = field_name,
        error_cls = WrongKeyTypeError,
    )


def require_x25519_private_key(value: object, *, field_name: str) -> None:
    """
    Validate that a value is X25519PrivateKey.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises WrongKeyTypeError: If the value is not X25519PrivateKey.
    """
    require_instance(
        value,
        X25519PrivateKey,
        field_name = field_name,
        error_cls = WrongKeyTypeError,
    )


def require_x25519_public_key(value: object, *, field_name: str) -> None:
    """
    Validate that a value is X25519PublicKey.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :raises WrongKeyTypeError: If the value is not X25519PublicKey.
    """
    require_instance(
        value,
        X25519PublicKey,
        field_name = field_name,
        error_cls = WrongKeyTypeError,
    )


def require_symmetric_key_bytes(value: object, *, field_name: str, min_length: int = 1) -> None:
    """
    Validate that a value is bytes suitable for symmetric key material.

    :param value: Value to validate.
    :param field_name: Field name used in error messages.
    :param min_length: Minimum acceptable key length in bytes.
    :raises InvalidInputError: If the value is not bytes or is too short.
    """
    require_bytes(value, field_name = field_name)
    if len(value) < min_length:
        raise InvalidInputError(f"{field_name} must be at least {min_length} bytes")


def require_nonce_length(value: object, *, field_name: str = "nonce", length: int = 12) -> None:
    """
    Validate nonce bytes of exact length.

    :param value: Nonce value to validate.
    :param field_name: Field name used in error messages.
    :param length: Required nonce length in bytes.
    :raises InvalidInputError: If the nonce is not bytes or has invalid length.
    """
    require_exact_length_bytes(value, field_name = field_name, length = length)


def require_aesgcm_key_length(value: object, *, field_name: str = "key") -> None:
    """
    Validate AES-GCM key bytes length.

    AES-GCM accepts only 16, 24, or 32 byte keys.

    :param value: Key value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the key is not bytes or has invalid length.
    """
    require_bytes(value, field_name = field_name)
    if len(value) not in VALID_AES_KEY_LENGTHS:
        raise InvalidInputError(f"{field_name} must be 16, 24, or 32 bytes")

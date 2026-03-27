from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import InvalidInputError, InvalidKeyError

__all__ = ["derive_key_scrypt", "derive_key_hkdf"]

_SCRYPT_MIN_SALT_LEN = 16


def _require_positive_int(value: int, *, field_name: str) -> None:
    """
    Validate that a value is a strict positive integer.

    :param value: Integer value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not a strict positive integer.
    """
    if type(value) is not int or value <= 0:
        raise InvalidInputError(f"{field_name} must be a positive integer")


def derive_key_scrypt(password: bytes, salt: bytes, *, length: int = 32,
                      n: int = 2 ** 16, r: int = 8, p: int = 1) -> bytes:
    """
    Derive key material from a password using scrypt.

    :param password: Password or passphrase bytes.
    :param salt: Salt bytes.
    :param length: Desired output key length in bytes.
    :param n: CPU/memory cost parameter.
    :param r: Block size parameter.
    :param p: Parallelization parameter.
    :return: Derived key bytes.
    :raises InvalidInputError: If API inputs or policy-level parameters are invalid.
    :raises InvalidKeyError: If key derivation fails after input validation.
    """
    if not isinstance(password, bytes):
        raise InvalidInputError("password must be bytes")
    if not isinstance(salt, bytes):
        raise InvalidInputError("salt must be bytes")
    if len(salt) < _SCRYPT_MIN_SALT_LEN:
        raise InvalidInputError(
            f"salt must be at least {_SCRYPT_MIN_SALT_LEN} bytes"
        )

    _require_positive_int(length, field_name = "length")
    _require_positive_int(n, field_name = "n")
    _require_positive_int(r, field_name = "r")
    _require_positive_int(p, field_name = "p")

    try:
        kdf = Scrypt(
            salt = salt,
            length = length,
            n = n,
            r = r,
            p = p,
        )
        return kdf.derive(password)
    except Exception as exc:
        raise InvalidKeyError("failed to derive key material with scrypt") from exc


def derive_key_hkdf(secret: bytes, *, salt: bytes | None = None,
                    info: bytes, length: int = 32) -> bytes:
    """
    Derive key material from input secret bytes using HKDF-SHA256.

    :param secret: Input keying material bytes.
    :param salt: Optional salt bytes.
    :param info: Required non-empty context/application-specific info bytes.
    :param length: Desired output key length in bytes.
    :return: Derived key bytes.
    :raises InvalidInputError: If API inputs or policy-level parameters are invalid.
    :raises InvalidKeyError: If key derivation fails after input validation.
    """
    if not isinstance(secret, bytes):
        raise InvalidInputError("secret must be bytes")
    if salt is not None and not isinstance(salt, bytes):
        raise InvalidInputError("salt must be bytes or None")
    if not isinstance(info, bytes):
        raise InvalidInputError("info must be bytes")
    if info == b"":
        raise InvalidInputError("info must not be empty")
    _require_positive_int(length, field_name = "length")

    try:
        kdf = HKDF(
            algorithm = hashes.SHA256(),
            length = length,
            salt = salt,
            info = info,
        )
        return kdf.derive(secret)
    except Exception as exc:
        raise InvalidKeyError("failed to derive key material with HKDF") from exc

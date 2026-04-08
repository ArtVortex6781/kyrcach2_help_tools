from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import InvalidKeyError
from .._internal import (require_positive_int, require_bytes,
                         require_optional_instance, require_non_empty_bytes, SCRYPT_MIN_SALT_LEN,
                         require_min_length_bytes)

__all__ = ["derive_key_scrypt", "derive_key_hkdf"]


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
    require_bytes(password, field_name = "password")
    require_min_length_bytes(salt, field_name = "salt", min_length = SCRYPT_MIN_SALT_LEN)
    require_positive_int(length, field_name = "length")
    require_positive_int(n, field_name = "n")
    require_positive_int(r, field_name = "r")
    require_positive_int(p, field_name = "p")

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
    require_bytes(secret, field_name = "secret")
    require_optional_instance(salt, expected_type = bytes, field_name = "salt")
    require_non_empty_bytes(info, field_name = "info")
    require_positive_int(length, field_name = "length")

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

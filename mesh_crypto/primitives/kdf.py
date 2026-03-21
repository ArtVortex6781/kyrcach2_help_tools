from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import InvalidKeyError

__all__ = ["derive_key_scrypt", "derive_key_hkdf"]


def derive_key_scrypt(password: bytes, salt: bytes, *, length: int = 32,
                      n: int = 16384, r: int = 8, p: int = 1) -> bytes:
    """
    Derive key material from a password using scrypt.

    :param password: Password or passphrase bytes.
    :param salt: Random salt bytes.
    :param length: Desired output key length in bytes.
    :param n: CPU/memory cost parameter.
    :param r: Block size parameter.
    :param p: Parallelization parameter.
    :return: Derived key bytes.
    :raises InvalidKeyError: If inputs or KDF parameters are invalid.
    """
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
                    info: bytes = b"", length: int = 32) -> bytes:
    """
    Derive key material from input secret bytes using HKDF-SHA256.

    :param secret: Input keying material.
    :param salt: Optional salt bytes.
    :param info: Optional context/application-specific info bytes.
    :param length: Desired output key length in bytes.
    :return: Derived key bytes.
    :raises InvalidKeyError: If inputs or HKDF parameters are invalid.
    """
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

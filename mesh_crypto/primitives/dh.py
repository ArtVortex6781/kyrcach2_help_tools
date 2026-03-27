from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..errors import InvalidInputError, InvalidKeyError, WrongKeyTypeError
from .kdf import derive_key_hkdf

__all__ = ["derive_session_key", "derive_raw_shared_secret"]


def _require_positive_int(value: int, *, field_name: str) -> None:
    """
    Validate that a value is a strict positive integer.

    :param value: Integer value to validate.
    :param field_name: Field name used in error messages.
    :raises InvalidInputError: If the value is not a strict positive integer.
    """
    if type(value) is not int or value <= 0:
        raise InvalidInputError(f"{field_name} must be a positive integer")


def derive_raw_shared_secret(sk: X25519PrivateKey, peer_pk: X25519PublicKey) -> bytes:
    """
    Derive a raw X25519 shared secret.

    This is a low-level helper. The returned value must not be used directly
    as a symmetric encryption key. Public callers should prefer
    derive_session_key(), which applies HKDF and enforces explicit context
    binding through the `info` parameter.

    :param sk: Local X25519 private key.
    :param peer_pk: Peer X25519 public key.
    :return: Raw shared secret bytes.
    :raises WrongKeyTypeError: If key objects are of the wrong type.
    :raises InvalidKeyError: If key exchange fails.
    """
    if not isinstance(sk, X25519PrivateKey):
        raise WrongKeyTypeError("sk must be an X25519PrivateKey")
    if not isinstance(peer_pk, X25519PublicKey):
        raise WrongKeyTypeError("peer_pk must be an X25519PublicKey")

    try:
        return sk.exchange(peer_pk)
    except Exception as exc:
        raise InvalidKeyError("failed to derive X25519 shared secret") from exc


def derive_session_key(sk: X25519PrivateKey, peer_pk: X25519PublicKey, *,
                       salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    """
    Derive a symmetric session key from X25519 shared secret material.

    This is the preferred public API. It performs X25519 key exchange and then
    applies HKDF-SHA256 with explicit non-empty context binding.

    :param sk: Local X25519 private key.
    :param peer_pk: Peer X25519 public key.
    :param salt: Optional HKDF salt bytes.
    :param info: Required non-empty HKDF context bytes.
    :param length: Desired output key length in bytes.
    :return: Derived session key bytes.
    :raises WrongKeyTypeError: If key objects are of the wrong type.
    :raises InvalidInputError: If HKDF-related inputs are invalid.
    :raises InvalidKeyError: If key exchange or derivation fails.
    """
    if salt is not None and not isinstance(salt, bytes):
        raise InvalidInputError("salt must be bytes or None")
    if not isinstance(info, bytes):
        raise InvalidInputError("info must be bytes")
    if info == b"":
        raise InvalidInputError("info must not be empty")
    _require_positive_int(length, field_name = "length")

    shared_secret = derive_raw_shared_secret(sk, peer_pk)

    return derive_key_hkdf(
        shared_secret,
        salt = salt,
        info = info,
        length = length,
    )

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..errors import IntegrityError, InvalidKeyError

__all__ = ["sign", "verify"]


def sign(data: bytes, sk: Ed25519PrivateKey) -> bytes:
    """
    Sign binary data with an Ed25519 private key.

    :param data: Binary payload to sign.
    :param sk: Ed25519 private key.
    :return: Signature bytes.
    :raises InvalidKeyError: If the key object is invalid or signing fails due
        to invalid key usage.
    """
    try:
        return sk.sign(data)
    except Exception as exc:
        raise InvalidKeyError("failed to sign data with Ed25519 private key") from exc


def verify(data: bytes, signature: bytes, pk: Ed25519PublicKey) -> None:
    """
    Verify an Ed25519 signature for binary data.

    :param data: Original binary payload.
    :param signature: Signature bytes to verify.
    :param pk: Ed25519 public key.
    :raises IntegrityError: If the signature is invalid.
    :raises InvalidKeyError: If the public key object is invalid or verification
        cannot be performed due to invalid key usage.
    """
    try:
        pk.verify(signature, data)
    except InvalidSignature as exc:
        raise IntegrityError("invalid Ed25519 signature") from exc
    except Exception as exc:
        raise InvalidKeyError("failed to verify Ed25519 signature") from exc

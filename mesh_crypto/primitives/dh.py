from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..errors import InvalidKeyError

__all__ = ["derive_shared_secret"]


def derive_shared_secret(sk: X25519PrivateKey, peer_pk: X25519PublicKey) -> bytes:
    """
    Derive a raw X25519 shared secret.

    :param sk: Local X25519 private key.
    :param peer_pk: Peer X25519 public key.
    :return: Raw shared secret bytes.
    :raises InvalidKeyError: If key objects are invalid or key exchange fails.
    """
    try:
        return sk.exchange(peer_pk)
    except Exception as exc:
        raise InvalidKeyError("failed to derive X25519 shared secret") from exc

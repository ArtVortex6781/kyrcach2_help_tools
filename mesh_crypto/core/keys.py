from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

__all__ = ["SigningKeyPair", "EncryptionKeyPair"]


@dataclass(frozen = True)
class SigningKeyPair:
    """
    Ed25519 key pair used for digital signatures.
    """

    sk: Ed25519PrivateKey
    pk: Ed25519PublicKey

    @staticmethod
    def generate() -> "SigningKeyPair":
        """
        Generate a new Ed25519 signing key pair.

        :return: Fresh signing key pair.
        """
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return SigningKeyPair(sk = sk, pk = pk)


@dataclass(frozen = True)
class EncryptionKeyPair:
    """
    X25519 key pair used for Diffie-Hellman key exchange.
    """

    sk: X25519PrivateKey
    pk: X25519PublicKey

    @staticmethod
    def generate() -> "EncryptionKeyPair":
        """
        Generate a new X25519 encryption key pair.

        :return: Fresh encryption key pair.
        """
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        return EncryptionKeyPair(sk = sk, pk = pk)

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..errors import KeyMismatchError
from .._validation import require_ed25519_private_key, require_x25519_private_key, require_ed25519_public_key, \
    require_x25519_public_key

__all__ = ["SigningKeyPair", "EncryptionKeyPair"]


def _export_public_key_raw(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    """
    Export a supported public key in raw form for internal key-pair consistency checks.

    :param key: Ed25519 or X25519 public key object.
    :return: Raw public key bytes.
    """
    return key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw,
    )


@dataclass(frozen = True)
class SigningKeyPair:
    """
    Ed25519 key pair used for digital signatures.
    """

    sk: Ed25519PrivateKey
    pk: Ed25519PublicKey

    def __post_init__(self) -> None:
        """
        Validate that the signing key pair has correct types and matching key material.

        :raises WrongKeyTypeError: If either key object has the wrong type.
        :raises KeyMismatchError: If the public key does not match the private key.
        """
        require_ed25519_private_key(self.sk, field_name = "Ed25519PrivateKey")
        require_ed25519_public_key(self.pk, field_name = "Ed25519PublicKey")

        expected_pk = self.sk.public_key()
        if _export_public_key_raw(self.pk) != _export_public_key_raw(expected_pk):
            raise KeyMismatchError("public key does not match the Ed25519 private key")

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

    def __post_init__(self) -> None:
        """
        Validate that the encryption key pair has correct types and matching key material.

        :raises WrongKeyTypeError: If either key object has the wrong type.
        :raises KeyMismatchError: If the public key does not match the private key.
        """
        require_x25519_private_key(self.sk, field_name = "X25519PrivateKey")
        require_x25519_public_key(self.pk, field_name = "X25519PublicKey")

        expected_pk = self.sk.public_key()
        if _export_public_key_raw(self.pk) != _export_public_key_raw(expected_pk):
            raise KeyMismatchError("public key does not match the X25519 private key")

    @staticmethod
    def generate() -> "EncryptionKeyPair":
        """
        Generate a new X25519 encryption key pair.

        :return: Fresh encryption key pair.
        """
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        return EncryptionKeyPair(sk = sk, pk = pk)

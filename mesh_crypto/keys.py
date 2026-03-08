from __future__ import annotations

import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

KeyId = uuid.UUID


# ==============================
# KeyId helpers
# ==============================
class KeyIdHelpers:
    """
    Utility helpers for working with cryptographic key identifiers.

    This class provides static helper methods for generating and
    serializing KeyId values.
    """

    @staticmethod
    def new_key_id() -> KeyId:
        """
        Generate a new unique identifier for a cryptographic key.

        :return: KeyId: A randomly generated UUID4 key identifier.
        """
        return uuid.uuid4()

    @staticmethod
    def key_id_to_bytes(key_id: KeyId) -> bytes:
        """
        Convert a KeyId to its binary representation.

        :param key_id: The key identifier.
        :return: bytes: 16-byte binary representation of the UUID.
        """
        return key_id.bytes

    @staticmethod
    def key_id_from_bytes(data: bytes) -> KeyId:
        """
        Restore a KeyId from its binary representation.

        :param data: 16-byte binary UUID representation.
        :return: KeyId: Parsed key identifier.
        """
        return uuid.UUID(bytes = data)


# ==============================
# Base class
# ==============================

@dataclass
class AsymmetricKeyPair:
    """
    Base container for asymmetric cryptographic key pairs.

    Attributes:
        sk: Private (secret) key.
        pk: Public key corresponding to the private key.
    """

    sk: object
    pk: object


# ==============================
# Signing keys (Ed25519)
# ==============================

@dataclass
class SigningKeyPair(AsymmetricKeyPair):
    """
    Ed25519 key pair used for digital signatures.

    Attributes:
        sk: Ed25519 private key used for signing.
        pk: Ed25519 public key used for signature verification.
    """

    sk: Ed25519PrivateKey
    pk: Ed25519PublicKey

    @staticmethod
    def generate() -> "SigningKeyPair":
        """Generate a new Ed25519 signing key pair."""
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return SigningKeyPair(sk = sk, pk = pk)

    def sign(self, data: bytes) -> bytes:
        """
        Sign arbitrary binary data.

        :param data: Message or binary payload to sign.
        :return: bytes: Cryptographic signature.
        """
        return self.sk.sign(data)

    @staticmethod
    def verify(pk: Ed25519PublicKey, signature: bytes, data: bytes) -> None:
        """
        Verify a signature created with Ed25519.

        :param pk: Public key used to verify the signature.
        :param signature: Signature bytes produced by the signer.
        :param data: Original message that was signed.
        """
        pk.verify(signature, data)


# ==============================
# Encryption keys (X25519)
# ==============================

@dataclass
class EncryptionKeyPair(AsymmetricKeyPair):
    """
    X25519 key pair used for Diffie–Hellman key exchange.

    Attributes:
        sk: X25519 private key used for key exchange.
        pk: X25519 public key shared with peers.
    """

    sk: X25519PrivateKey
    pk: X25519PublicKey

    @staticmethod
    def generate() -> "EncryptionKeyPair":
        """Generate a new X25519 key pair."""
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        return EncryptionKeyPair(sk = sk, pk = pk)

    def derive_shared_key(self, peer_pk: X25519PublicKey) -> bytes:
        """
        Derive a shared secret using Diffie–Hellman key exchange.

        :param peer_pk: Public key of the peer.
        :return: bytes: Raw shared secret.
        """
        return self.sk.exchange(peer_pk)

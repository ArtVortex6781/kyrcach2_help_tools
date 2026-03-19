from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..errors import InvalidKeyError
from .keys import EncryptionKeyPair, SigningKeyPair

__all__ = ["SigningKeySerializer", "EncryptionKeySerializer"]


class SigningKeySerializer:
    """
    Serialization helpers for Ed25519 signing keys.

    This class defines the single source of truth for converting Ed25519
    private/public keys and signing key pairs to and from raw byte form.
    """

    @staticmethod
    def serialize_private_key(key: Ed25519PrivateKey) -> bytes:
        """
        Serialize an Ed25519 private key into raw 32-byte form.

        :param key: Ed25519 private key object.
        :return: Raw private key bytes.
        :raises InvalidKeyError: If the key cannot be serialized.
        """
        try:
            return key.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
        except Exception as exc:
            raise InvalidKeyError("failed to serialize Ed25519 private key") from exc

    @staticmethod
    def serialize_public_key(key: Ed25519PublicKey) -> bytes:
        """
        Serialize an Ed25519 public key into raw 32-byte form.

        :param key: Ed25519 public key object.
        :return: Raw public key bytes.
        :raises InvalidKeyError: If the key cannot be serialized.
        """
        try:
            return key.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw,
            )
        except Exception as exc:
            raise InvalidKeyError("failed to serialize Ed25519 public key") from exc

    @staticmethod
    def deserialize_private_key(data: bytes) -> Ed25519PrivateKey:
        """
        Restore an Ed25519 private key from raw 32-byte form.

        :param data: Raw private key bytes.
        :return: Ed25519 private key object.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        try:
            return Ed25519PrivateKey.from_private_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid Ed25519 private key bytes") from exc

    @staticmethod
    def deserialize_public_key(data: bytes) -> Ed25519PublicKey:
        """
        Restore an Ed25519 public key from raw 32-byte form.

        :param data: Raw public key bytes.
        :return: Ed25519 public key object.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        try:
            return Ed25519PublicKey.from_public_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid Ed25519 public key bytes") from exc

    @staticmethod
    def serialize_pair_private_key(key_pair: SigningKeyPair) -> bytes:
        """
        Serialize the private key from a SigningKeyPair.

        :param key_pair: Signing key pair container.
        :return: Raw Ed25519 private key bytes.
        """
        return SigningKeySerializer.serialize_private_key(key_pair.sk)

    @staticmethod
    def serialize_pair_public_key(key_pair: SigningKeyPair) -> bytes:
        """
        Serialize the public key from a SigningKeyPair.

        :param key_pair: Signing key pair container.
        :return: Raw Ed25519 public key bytes.
        """
        return SigningKeySerializer.serialize_public_key(key_pair.pk)

    @staticmethod
    def restore_pair_from_private_bytes(data: bytes) -> SigningKeyPair:
        """
        Restore a SigningKeyPair from raw Ed25519 private key bytes.
        The public key is deterministically derived from the private key.

        :param data: Raw Ed25519 private key bytes.
        :return: Reconstructed signing key pair.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        sk = SigningKeySerializer.deserialize_private_key(data)
        pk = sk.public_key()
        return SigningKeyPair(sk = sk, pk = pk)


class EncryptionKeySerializer:
    """
    Serialization helpers for X25519 encryption keys.

    This class defines the single source of truth for converting X25519
    private/public keys and encryption key pairs to and from raw byte form.
    """

    @staticmethod
    def serialize_private_key(key: X25519PrivateKey) -> bytes:
        """
        Serialize an X25519 private key into raw 32-byte form.

        :param key: X25519 private key object.
        :return: Raw private key bytes.
        :raises InvalidKeyError: If the key cannot be serialized.
        """
        try:
            return key.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
        except Exception as exc:
            raise InvalidKeyError("failed to serialize X25519 private key") from exc

    @staticmethod
    def serialize_public_key(key: X25519PublicKey) -> bytes:
        """
        Serialize an X25519 public key into raw 32-byte form.

        :param key: X25519 public key object.
        :return: Raw public key bytes.
        :raises InvalidKeyError: If the key cannot be serialized.
        """
        try:
            return key.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw,
            )
        except Exception as exc:
            raise InvalidKeyError("failed to serialize X25519 public key") from exc

    @staticmethod
    def deserialize_private_key(data: bytes) -> X25519PrivateKey:
        """
        Restore an X25519 private key from raw 32-byte form.

        :param data: Raw private key bytes.
        :return: X25519 private key object.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        try:
            return X25519PrivateKey.from_private_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid X25519 private key bytes") from exc

    @staticmethod
    def deserialize_public_key(data: bytes) -> X25519PublicKey:
        """
        Restore an X25519 public key from raw 32-byte form.

        :param data: Raw public key bytes.
        :return: X25519 public key object.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        try:
            return X25519PublicKey.from_public_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid X25519 public key bytes") from exc

    @staticmethod
    def serialize_pair_private_key(key_pair: EncryptionKeyPair) -> bytes:
        """
        Serialize the private key from an EncryptionKeyPair.

        :param key_pair: Encryption key pair container.
        :return: Raw X25519 private key bytes.
        """
        return EncryptionKeySerializer.serialize_private_key(key_pair.sk)

    @staticmethod
    def serialize_pair_public_key(key_pair: EncryptionKeyPair) -> bytes:
        """
        Serialize the public key from an EncryptionKeyPair.

        :param key_pair: Encryption key pair container.
        :return: Raw X25519 public key bytes.
        """
        return EncryptionKeySerializer.serialize_public_key(key_pair.pk)

    @staticmethod
    def restore_pair_from_private_bytes(data: bytes) -> EncryptionKeyPair:
        """
        Restore an EncryptionKeyPair from raw X25519 private key bytes.
        The public key is deterministically derived from the private key.

        :param data: Raw X25519 private key bytes.
        :return: Reconstructed encryption key pair.
        :raises InvalidKeyError: If the input is malformed or invalid.
        """
        sk = EncryptionKeySerializer.deserialize_private_key(data)
        pk = sk.public_key()
        return EncryptionKeyPair(sk = sk, pk = pk)

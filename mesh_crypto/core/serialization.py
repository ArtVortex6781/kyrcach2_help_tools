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

from ..errors import InvalidKeyError, WrongKeyTypeError
from .keys import EncryptionKeyPair, SigningKeyPair
from .._internal import require_bytes, require_x25519_public_key, require_ed25519_public_key, \
    require_x25519_private_key, require_ed25519_private_key, require_instance

__all__ = ["SigningKeySerializer", "EncryptionKeySerializer"]


class SigningKeySerializer:
    """
    Raw import/export helpers for Ed25519 signing keys.

    This serializer operates on raw key material and makes that fact explicit
    in method names.
    """

    @staticmethod
    def export_private_key_raw(key: Ed25519PrivateKey) -> bytes:
        """
        Export an Ed25519 private key in raw 32-byte form.

        :param key: Ed25519 private key object.
        :return: Raw private key bytes.
        :raises WrongKeyTypeError: If the provided key object is not Ed25519PrivateKey.
        :raises InvalidKeyError: If export fails.
        """
        require_ed25519_private_key(key, field_name = "Ed25519PrivateKey")

        try:
            return key.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
        except Exception as exc:
            raise InvalidKeyError("failed to export Ed25519 private key in raw format") from exc

    @staticmethod
    def export_public_key_raw(key: Ed25519PublicKey) -> bytes:
        """
        Export an Ed25519 public key in raw 32-byte form.

        :param key: Ed25519 public key object.
        :return: Raw public key bytes.
        :raises WrongKeyTypeError: If the provided key object is not Ed25519PublicKey.
        :raises InvalidKeyError: If export fails.
        """
        require_ed25519_public_key(key, field_name = "Ed25519PublicKey")

        try:
            return key.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw,
            )
        except Exception as exc:
            raise InvalidKeyError("failed to export Ed25519 public key in raw format") from exc

    @staticmethod
    def import_private_key_raw(data: bytes) -> Ed25519PrivateKey:
        """
        Import an Ed25519 private key from raw 32-byte form.

        :param data: Raw private key bytes.
        :return: Ed25519 private key object.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as Ed25519 private key material.
        """
        require_bytes(data, field_name = "Ed25519_private_key_raw")

        try:
            return Ed25519PrivateKey.from_private_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid Ed25519 private key raw bytes") from exc

    @staticmethod
    def import_public_key_raw(data: bytes) -> Ed25519PublicKey:
        """
        Import an Ed25519 public key from raw 32-byte form.

        :param data: Raw public key bytes.
        :return: Ed25519 public key object.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as Ed25519 public key material.
        """
        require_bytes(data, field_name = "Ed25519_public_key_raw")

        try:
            return Ed25519PublicKey.from_public_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid Ed25519 public key raw bytes") from exc

    @staticmethod
    def export_pair_private_key_raw(key_pair: SigningKeyPair) -> bytes:
        """
        Export raw Ed25519 private key material from a SigningKeyPair.

        :param key_pair: Signing key pair container.
        :return: Raw private key bytes.
        :raises WrongKeyTypeError: If the provided object is not SigningKeyPair.
        :raises InvalidKeyError: If export fails.
        """
        require_instance(key_pair, SigningKeyPair, field_name = "SigningKeyPair",
                         error_cls = WrongKeyTypeError)

        return SigningKeySerializer.export_private_key_raw(key_pair.sk)

    @staticmethod
    def export_pair_public_key_raw(key_pair: SigningKeyPair) -> bytes:
        """
        Export raw Ed25519 public key material from a SigningKeyPair.

        :param key_pair: Signing key pair container.
        :return: Raw public key bytes.
        :raises WrongKeyTypeError: If the provided object is not SigningKeyPair.
        :raises InvalidKeyError: If export fails.
        """
        require_instance(key_pair, SigningKeyPair, field_name = "SigningKeyPair",
                         error_cls = WrongKeyTypeError)

        return SigningKeySerializer.export_public_key_raw(key_pair.pk)

    @staticmethod
    def restore_pair_from_private_bytes(data: bytes) -> SigningKeyPair:
        """
        Restore a SigningKeyPair from raw Ed25519 private key bytes.

        The public key is deterministically derived from the private key.

        :param data: Raw Ed25519 private key bytes.
        :return: Reconstructed signing key pair.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as Ed25519 private key material.
        """
        sk = SigningKeySerializer.import_private_key_raw(data)
        pk = sk.public_key()
        return SigningKeyPair(sk = sk, pk = pk)


class EncryptionKeySerializer:
    """
    Raw import/export helpers for X25519 encryption keys.

    This serializer operates on raw key material and makes that fact explicit
    in method names.
    """

    @staticmethod
    def export_private_key_raw(key: X25519PrivateKey) -> bytes:
        """
        Export an X25519 private key in raw 32-byte form.

        :param key: X25519 private key object.
        :return: Raw private key bytes.
        :raises WrongKeyTypeError: If the provided key object is not X25519PrivateKey.
        :raises InvalidKeyError: If export fails.
        """
        require_x25519_private_key(key, field_name = "X25519PrivateKey")

        try:
            return key.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
        except Exception as exc:
            raise InvalidKeyError("failed to export X25519 private key in raw format") from exc

    @staticmethod
    def export_public_key_raw(key: X25519PublicKey) -> bytes:
        """
        Export an X25519 public key in raw 32-byte form.

        :param key: X25519 public key object.
        :return: Raw public key bytes.
        :raises WrongKeyTypeError: If the provided key object is not X25519PublicKey.
        :raises InvalidKeyError: If export fails.
        """
        require_x25519_public_key(key, field_name = "X25519PublicKey")

        try:
            return key.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw,
            )
        except Exception as exc:
            raise InvalidKeyError("failed to export X25519 public key in raw format") from exc

    @staticmethod
    def import_private_key_raw(data: bytes) -> X25519PrivateKey:
        """
        Import an X25519 private key from raw 32-byte form.

        :param data: Raw private key bytes.
        :return: X25519 private key object.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as X25519 private key material.
        """
        require_bytes(data, field_name = "X25519_private_key_raw")

        try:
            return X25519PrivateKey.from_private_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid X25519 private key raw bytes") from exc

    @staticmethod
    def import_public_key_raw(data: bytes) -> X25519PublicKey:
        """
        Import an X25519 public key from raw 32-byte form.

        :param data: Raw public key bytes.
        :return: X25519 public key object.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as X25519 public key material.
        """
        require_bytes(data, field_name = "X25519_public_key_raw")

        try:
            return X25519PublicKey.from_public_bytes(data)
        except Exception as exc:
            raise InvalidKeyError("invalid X25519 public key raw bytes") from exc

    @staticmethod
    def export_pair_private_key_raw(key_pair: EncryptionKeyPair) -> bytes:
        """
        Export raw X25519 private key material from an EncryptionKeyPair.

        :param key_pair: Encryption key pair container.
        :return: Raw private key bytes.
        :raises WrongKeyTypeError: If the provided object is not EncryptionKeyPair.
        :raises InvalidKeyError: If export fails.
        """
        require_instance(key_pair, EncryptionKeyPair, field_name = "EncryptionKeyPair",
                         error_cls = WrongKeyTypeError)

        return EncryptionKeySerializer.export_private_key_raw(key_pair.sk)

    @staticmethod
    def export_pair_public_key_raw(key_pair: EncryptionKeyPair) -> bytes:
        """
        Export raw X25519 public key material from an EncryptionKeyPair.

        :param key_pair: Encryption key pair container.
        :return: Raw public key bytes.
        :raises WrongKeyTypeError: If the provided object is not EncryptionKeyPair.
        :raises InvalidKeyError: If export fails.
        """
        require_instance(key_pair, EncryptionKeyPair, field_name = "EncryptionKeyPair",
                         error_cls = WrongKeyTypeError)

        return EncryptionKeySerializer.export_public_key_raw(key_pair.pk)

    @staticmethod
    def restore_pair_from_private_bytes(data: bytes) -> EncryptionKeyPair:
        """
        Restore an EncryptionKeyPair from raw X25519 private key bytes.

        The public key is deterministically derived from the private key.

        :param data: Raw X25519 private key bytes.
        :return: Reconstructed encryption key pair.
        :raises InvalidInputError: If the input is not bytes.
        :raises InvalidKeyError: If raw bytes cannot be parsed as X25519 private key material.
        """
        sk = EncryptionKeySerializer.import_private_key_raw(data)
        pk = sk.public_key()
        return EncryptionKeyPair(sk = sk, pk = pk)

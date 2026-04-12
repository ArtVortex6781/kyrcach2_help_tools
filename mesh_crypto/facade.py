from __future__ import annotations

from pathlib import Path

from .core.keys import EncryptionKeyPair, SigningKeyPair
from .keystore.file_keystore import FileKeyStore
from .keystore.protectors import Protector
from .primitives.aead import decrypt, encrypt
from .primitives.dh import derive_session_key
from .primitives.signatures import sign, verify

__all__ = [
    "generate_signing_key_pair",
    "generate_encryption_key_pair",
    "create_file_keystore",
    "open_file_keystore",
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "derive_session_key",
]


def generate_signing_key_pair() -> SigningKeyPair:
    """
    Generate a new Ed25519 signing key pair.

    This is a curated convenience entrypoint over the core key model.

    :return: Fresh signing key pair.
    """
    return SigningKeyPair.generate()


def generate_encryption_key_pair() -> EncryptionKeyPair:
    """
    Generate a new X25519 encryption key pair.

    This is a curated convenience entrypoint over the core key model.

    :return: Fresh encryption key pair.
    """
    return EncryptionKeyPair.generate()


def create_file_keystore(path: str | Path, protector: Protector,
                         *, overwrite: bool = False) -> FileKeyStore:
    """
    Create a new file-based keystore and initialize it with a fresh master key.

    This is a convenience lifecycle helper over FileKeyStore.

    :param path: Keystore directory path.
    :param protector: Protector used to wrap the master key.
    :param overwrite: Whether to overwrite an existing keystore.
    :return: Initialized FileKeyStore instance.
    :raises FileExistsError: If the keystore already exists and overwrite is False.
    """
    keystore = FileKeyStore(path, protector)
    keystore.create_new(overwrite = overwrite)
    return keystore


def open_file_keystore(path: str | Path, protector: Protector) -> FileKeyStore:
    """
    Open an existing file-based keystore and load its master key.

    This is a convenience lifecycle helper over FileKeyStore.

    :param path: Keystore directory path.
    :param protector: Protector used to unwrap the master key.
    :return: Loaded FileKeyStore instance.
    :raises FileNotFoundError: If the keystore does not exist.
    """
    keystore = FileKeyStore(path, protector)
    keystore.load()
    return keystore

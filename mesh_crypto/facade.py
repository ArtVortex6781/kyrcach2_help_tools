from __future__ import annotations

from pathlib import Path

from .core.key_types import KeyKind
from .core.keys import EncryptionKeyPair, SigningKeyPair
from .core.types import KeyId
from .keystore.file_keystore import FileKeyStore
from .keystore.protectors import Protector

__all__ = [
    "generate_signing_key_pair",
    "generate_encryption_key_pair",
    "create_file_keystore",
    "open_file_keystore",
    "generate_keystore_key",
    "generate_identity_key",
    "generate_storage_key",
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


def generate_keystore_key(keystore: FileKeyStore,
                          kind: KeyKind | str = KeyKind.SYMMETRIC) -> KeyId:
    """
    Generate a key inside FileKeyStore.

    :param keystore: Loaded or newly created file keystore.
    :param kind: Key kind to generate.
    :return: Generated key identifier.
    """
    return keystore.generate_key(kind)


def generate_identity_key(keystore: FileKeyStore) -> KeyId:
    """
    Generate an Ed25519 identity signing key inside FileKeyStore.

    :param keystore: Loaded or newly created file keystore.
    :return: Generated identity key identifier.
    """
    return keystore.generate_key(KeyKind.ED25519)


def generate_storage_key(keystore: FileKeyStore) -> KeyId:
    """
    Generate a symmetric storage/data key inside FileKeyStore.

    :param keystore: Loaded or newly created file keystore.
    :return: Generated storage key identifier.
    """
    return keystore.generate_key(KeyKind.SYMMETRIC)

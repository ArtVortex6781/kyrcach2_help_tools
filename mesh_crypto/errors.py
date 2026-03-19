from __future__ import annotations

__all__ = [
    "MeshCryptoError",
    "InvalidKeyError",
    "UnsupportedFormatError",
    "IntegrityError",
    "KeyNotFoundError",
    "KeystoreNotLoadedError",
]


class MeshCryptoError(Exception):
    """
    Base exception for the mesh_crypto package.
    """


class InvalidKeyError(MeshCryptoError):
    """
    Raised when key material is malformed, invalid, or does not match
    the expected key type or format.
    """


class UnsupportedFormatError(MeshCryptoError):
    """
    Raised when serialized data uses an unknown, unsupported, or incompatible
    format/version.
    """


class IntegrityError(MeshCryptoError):
    """
    Raised when an integrity check fails, for example during authenticated
    decryption or signature-related validation paths.
    """


class KeyNotFoundError(MeshCryptoError):
    """
    Raised when a requested key cannot be found in the configured key store
    or key lookup context.
    """


class KeystoreNotLoadedError(MeshCryptoError):
    """
    Raised when a keystore operation requires loaded key material, but the
    keystore has not been initialized or opened yet.
    """

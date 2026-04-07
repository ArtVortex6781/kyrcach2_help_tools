from __future__ import annotations

__all__ = [
    "MeshCryptoError",
    "InvalidInputError",
    "InvalidKeyError",
    "WrongKeyTypeError",
    "KeyMismatchError",
    "UnsupportedFormatError",
    "MalformedDataError",
    "IntegrityError",
    "AuthenticationError",
    "SignatureVerificationError",
    "ReplayDetectedError",
    "RollbackDetectedError",
    "KeystoreError",
    "ProtectorError",
    "ProtectorBackendUnavailableError",
    "ProtectorOperationError",
    "KeyNotFoundError",
    "KeystoreNotLoadedError",
]


class MeshCryptoError(Exception):
    """
    Base exception for the mesh_crypto package.
    """


class InvalidInputError(MeshCryptoError):
    """
    Raised when a public API is called with invalid arguments.

    This includes programmer misuse such as wrong argument types, invalid
    lengths, missing required context values, or policy-level invalid input
    combinations.
    """


class InvalidKeyError(MeshCryptoError):
    """
    Raised when key material is malformed, invalid, or cannot be reconstructed
    into the expected cryptographic key object.
    """


class WrongKeyTypeError(InvalidKeyError):
    """
    Raised when a key of the wrong algorithm or usage type is provided for an
    operation.

    Example:
        passing an Ed25519 key where an X25519 key is required.
    """


class KeyMismatchError(InvalidKeyError):
    """
    Raised when multiple key objects are individually valid but do not belong
    together.

    Example:
        a private key and public key in the same key pair container do not
        match each other.
    """


class UnsupportedFormatError(MeshCryptoError):
    """
    Raised when serialized data uses an unknown, unsupported, or incompatible
    format.

    This includes unsupported versions, algorithm identifiers, provider names,
    or schema variants that are recognized structurally but not supported by
    the current implementation.
    """


class MalformedDataError(UnsupportedFormatError):
    """
    Raised when serialized or structured data is present but is internally
    malformed.

    This includes structurally broken envelopes, invalid field combinations,
    invalid nonce lengths, impossible blob layouts, or broken serialized
    objects that cannot be parsed safely.
    """


class IntegrityError(MeshCryptoError):
    """
    Raised when cryptographic integrity or authenticity verification fails.
    """


class AuthenticationError(IntegrityError):
    """
    Raised when authenticated decryption fails.

    This typically indicates tampering, wrong key usage, wrong AAD, or an
    invalid authentication tag.
    """


class SignatureVerificationError(IntegrityError):
    """
    Raised when a digital signature verification operation fails.
    """


class ReplayDetectedError(IntegrityError):
    """
    Raised when replayed data is detected.

    This error is defined as part of the public error model even if replay
    detection is introduced in a later layer.
    """


class RollbackDetectedError(IntegrityError):
    """
    Raised when rollback of protected state or metadata is detected.

    This error is defined as part of the public error model even if rollback
    detection is introduced in a later layer.
    """


class KeystoreError(MeshCryptoError):
    """
    Base exception for keystore-related failures.
    """


class ProtectorError(KeystoreError):
    """
    Base exception for protector-related failures.
    """


class ProtectorBackendUnavailableError(ProtectorError):
    """
    Raised when a required protector backend is not available.

    Example:
        OS keyring backend or python-keyring package is unavailable.
    """


class ProtectorOperationError(ProtectorError):
    """
    Raised when a protector backend fails during wrap/unwrap operations.
    """


class KeyNotFoundError(KeystoreError):
    """
    Raised when a requested key cannot be found in the current keystore
    context.
    """


class KeystoreNotLoadedError(KeystoreError):
    """
    Raised when a keystore operation requires loaded key material, but the
    keystore has not been initialized or opened yet.
    """

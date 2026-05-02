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
    "ProtectorSecretNotFoundError",
    "KeyNotFoundError",
    "KeystoreNotLoadedError",
    "StorageCryptoError",
    "SessionError",
    "HandshakeError",
    "InvalidSessionStateError",
    "SessionCounterError",
    "OutOfOrderMessageError",
    "SkippedKeyLimitError",
    "RatchetError",
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


class ProtectorSecretNotFoundError(ProtectorOperationError):
    """
    Raised when protector metadata is valid and the backend is reachable,
    but the referenced protected secret does not exist.
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


class StorageCryptoError(MeshCryptoError):
    """
    Base exception for storage field crypto failures.

    This is used for storage-layer misuse or policy failures.
    """


class SessionError(MeshCryptoError):
    """
    Base exception for authenticated direct session/message crypto failures.
    """


class HandshakeError(SessionError):
    """
    Raised when authenticated direct session establishment fails.

    This includes malformed handshake flow, unexpected peer identity,
    transcript mismatch, or invalid role/state combinations during handshake.
    """


class InvalidSessionStateError(SessionError):
    """
    Raised when a direct session state is malformed, inconsistent, or unusable.

    This includes invalid key lengths, invalid ratchet state, invalid role
    combinations, or state that cannot safely be used for message operations.
    """


class SessionCounterError(SessionError):
    """
    Raised when direct session counters are invalid or cannot be advanced safely.

    This includes invalid counter values, counter overflow, or impossible
    counter transitions.
    """


class OutOfOrderMessageError(SessionCounterError):
    """
    Raised when a direct message is too far ahead of the current receive state
    or cannot be handled by the supported out-of-order policy.
    """


class SkippedKeyLimitError(SessionCounterError):
    """
    Raised when deriving or storing skipped message keys would exceed the
    configured skipped-key limit.
    """


class RatchetError(SessionError):
    """
    Raised when DH ratchet state or ratchet transitions are invalid.

    This includes malformed ratchet public keys, inconsistent DH ratchet state,
    or failed root/chain refresh logic.
    """

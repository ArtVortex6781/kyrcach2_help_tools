from __future__ import annotations

from .._internal import (
    require_bytes,
    require_exact_length_bytes,
    require_instance,
    require_non_empty_bytes,
)
from ..core.domain_separation import AAD_PURPOSE_STORAGE_FIELD
from ..core.key_ids import KeyIdHelpers
from ..core.key_types import KeyKind
from ..core.types import KeyId
from ..errors import InvalidInputError, InvalidKeyError, KeyNotFoundError, WrongKeyTypeError
from ..keystore.file_keystore import FileKeyStore
from ..primitives.aead import decrypt, encrypt
from .envelopes import StorageFieldEnvelope

__all__ = [
    "encrypt_storage_field",
    "decrypt_storage_field",
    "encrypt_storage_field_raw",
    "decrypt_storage_field_raw",
]

_STORAGE_FIELD_VERSION = 1
_STORAGE_FIELD_TYPE = "storage_field"
_STORAGE_FIELD_ALGORITHM = "mesh-storage-v1"
_STORAGE_KEY_LENGTH = 32


# ==============================
# Framing / AAD helpers
# ==============================

def _frame_bytes(value: bytes) -> bytes:
    """
    Encode bytes as a length-prefixed frame.

    :param value: Bytes to frame.
    :return: 4-byte big-endian length followed by value.
    """
    return len(value).to_bytes(4, "big") + value


def _frame_str(value: str) -> bytes:
    """
    Encode string as a length-prefixed UTF-8 frame.

    :param value: String to frame.
    :return: Framed UTF-8 bytes.
    """
    return _frame_bytes(value.encode("utf-8"))


def _frame_uint32(value: int) -> bytes:
    """
    Encode an unsigned 32-bit integer as a framed big-endian value.

    :param value: Integer to frame.
    :return: Framed 4-byte big-endian representation.
    """
    return _frame_bytes(value.to_bytes(4, "big"))


def _build_storage_field_aad(*, key_id: KeyId, aad: bytes) -> bytes:
    """
    Build domain-separated AAD for storage field encryption.

    The caller-provided AAD must encode application-level context such as
    schema version, table name, field name, and record identifier.

    :param key_id: Storage key identifier stored in the envelope.
    :param aad: Non-empty caller-provided field AAD.
    :return: Final AEAD associated data.
    """
    return (
            AAD_PURPOSE_STORAGE_FIELD
            + _frame_uint32(_STORAGE_FIELD_VERSION)
            + _frame_str(_STORAGE_FIELD_TYPE)
            + _frame_str(_STORAGE_FIELD_ALGORITHM)
            + _frame_bytes(key_id.bytes)
            + _frame_bytes(aad)
    )


# ==============================
# Validation / keystore helpers
# ==============================

def _require_storage_aad(aad: bytes) -> None:
    """
    Validate storage field AAD.

    :param aad: Caller-provided field AAD.
    :raises InvalidInputError: If AAD is not non-empty bytes.
    """
    require_non_empty_bytes(aad, field_name = "aad")


def _validate_storage_key(key: bytes) -> None:
    """
    Validate raw storage encryption key bytes.

    Storage field encryption currently uses 32-byte AES-GCM keys.

    :param key: Raw storage key bytes.
    :raises InvalidInputError: If key is not bytes.
    :raises InvalidKeyError: If key length is invalid.
    """
    try:
        require_exact_length_bytes(
            key,
            field_name = "storage_key",
            length = _STORAGE_KEY_LENGTH,
        )
    except InvalidInputError as exc:
        raise InvalidKeyError("storage key must be exactly 32 bytes") from exc


def _load_storage_key_from_keystore(keystore: FileKeyStore, key_id: KeyId) -> bytes:
    """
    Load and validate a storage key from FileKeyStore.

    FileKeyStore is responsible for loading, decrypting, and validating the
    stored key record. This helper only enforces storage-crypto policy:
    the selected key must be symmetric and exactly 32 bytes.

    :param keystore: Loaded file keystore.
    :param key_id: Key identifier.
    :return: Raw 32-byte storage key bytes.
    :raises KeyNotFoundError: If key file is missing.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises WrongKeyTypeError: If the key is not symmetric.
    :raises InvalidKeyError: If key length is invalid.
    """
    require_instance(keystore, FileKeyStore, field_name = "keystore")

    key_bytes, meta = keystore.get_key(key_id)

    if meta.get("kind") != KeyKind.SYMMETRIC.value:
        raise WrongKeyTypeError("storage crypto requires a symmetric keystore key")

    _validate_storage_key(key_bytes)
    return key_bytes


# ==============================
# Low-level raw-key API
# ==============================

def encrypt_storage_field_raw(key: bytes, plaintext: bytes, *,
                              key_id: KeyId | str | bytes, aad: bytes) -> bytes:
    """
    Encrypt storage field bytes with a raw storage key.

    This is a low-level foundation API intended for tests and internal tooling.
    Recommended integration should use encrypt_storage_field(), which operates
    through FileKeyStore and does not require the caller to handle raw storage
    keys directly.

    :param key: Raw 32-byte storage key.
    :param plaintext: Plaintext field bytes.
    :param key_id: Identifier of the key used for encryption.
    :param aad: Non-empty caller-provided storage field AAD.
    :return: Serialized StorageFieldEnvelope bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises InvalidKeyError: If key material is invalid.
    :raises MalformedDataError: If envelope construction fails.
    :raises UnsupportedFormatError: If envelope constants are unsupported.
    """
    _validate_storage_key(key)
    require_bytes(plaintext, field_name = "plaintext")
    _require_storage_aad(aad)

    normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)
    final_aad = _build_storage_field_aad(
        key_id = normalized_key_id,
        aad = aad,
    )

    aead = encrypt(key, plaintext, final_aad)

    envelope = StorageFieldEnvelope(
        version = _STORAGE_FIELD_VERSION,
        type = _STORAGE_FIELD_TYPE,
        algorithm = _STORAGE_FIELD_ALGORITHM,
        key_id = normalized_key_id,
        aead = aead,
    )
    return envelope.to_bytes()


def decrypt_storage_field_raw(key: bytes, envelope: bytes,
                              *, aad: bytes) -> bytes:
    """
    Decrypt storage field bytes with a raw storage key.

    This is a low-level foundation API intended for tests and internal tooling.
    Recommended integration should use decrypt_storage_field(), which loads the
    required storage key through FileKeyStore using the key_id stored in the
    envelope.

    Wrong key, corrupted ciphertext, and AAD mismatch are reported by the
    underlying AEAD layer as AuthenticationError.

    :param key: Raw 32-byte storage key.
    :param envelope: Serialized StorageFieldEnvelope bytes.
    :param aad: Non-empty caller-provided storage field AAD.
    :return: Decrypted plaintext bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises InvalidKeyError: If key material is invalid.
    :raises MalformedDataError: If envelope is malformed.
    :raises UnsupportedFormatError: If envelope version/type/algorithm is unsupported.
    :raises AuthenticationError: If authenticated decryption fails.
    """
    _validate_storage_key(key)
    require_bytes(envelope, field_name = "envelope")
    _require_storage_aad(aad)

    parsed = StorageFieldEnvelope.from_bytes(envelope)
    final_aad = _build_storage_field_aad(
        key_id = parsed.key_id,
        aad = aad,
    )

    return decrypt(key, parsed.aead, final_aad)


# ==============================
# Recommended keystore-backed API
# ==============================

def encrypt_storage_field(keystore: FileKeyStore, plaintext: bytes, *,
                          aad: bytes, key_id: KeyId | str | bytes | None = None) -> bytes:
    """
    Encrypt storage field bytes using a symmetric key stored in FileKeyStore.

    This is the recommended storage crypto integration API. If key_id is not
    provided, the currently active keystore key is used. The selected key_id is
    always written into the storage envelope, so decryption remains stable after
    active-key rotation.

    :param keystore: Loaded file keystore.
    :param plaintext: Plaintext field bytes.
    :param aad: Non-empty caller-provided storage field AAD.
    :param key_id: Optional explicit storage key identifier.
    :return: Serialized StorageFieldEnvelope bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises KeyNotFoundError: If active or explicit key is missing.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises WrongKeyTypeError: If selected key is not symmetric.
    :raises InvalidKeyError: If selected key material is invalid.
    """
    require_instance(keystore, FileKeyStore, field_name = "keystore")
    require_bytes(plaintext, field_name = "plaintext")
    _require_storage_aad(aad)

    if key_id is None:
        normalized_key_id = keystore.get_active_key_id()
        if normalized_key_id is None:
            raise KeyNotFoundError("active storage key is not set")
    else:
        normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)

    key = _load_storage_key_from_keystore(keystore, normalized_key_id)

    return encrypt_storage_field_raw(
        key,
        plaintext,
        key_id = normalized_key_id,
        aad = aad,
    )


def decrypt_storage_field(keystore: FileKeyStore, envelope: bytes,
                          *, aad: bytes) -> bytes:
    """
    Decrypt storage field bytes using the key_id stored in the envelope.

    This is the recommended storage crypto integration API. Decryption does not
    fall back to the active keystore key. The key_id recorded in the envelope is
    used to load the exact key needed for decryption.

    :param keystore: Loaded file keystore.
    :param envelope: Serialized StorageFieldEnvelope bytes.
    :param aad: Non-empty caller-provided storage field AAD.
    :return: Decrypted plaintext bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises KeyNotFoundError: If the envelope key_id is not present in keystore.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises WrongKeyTypeError: If selected key is not symmetric.
    :raises InvalidKeyError: If selected key material is invalid.
    :raises MalformedDataError: If envelope is malformed.
    :raises UnsupportedFormatError: If envelope version/type/algorithm is unsupported.
    :raises AuthenticationError: If authenticated decryption fails.
    """
    require_instance(keystore, FileKeyStore, field_name = "keystore")
    require_bytes(envelope, field_name = "envelope")
    _require_storage_aad(aad)

    parsed = StorageFieldEnvelope.from_bytes(envelope)
    key = _load_storage_key_from_keystore(keystore, parsed.key_id)

    return decrypt_storage_field_raw(
        key,
        envelope,
        aad = aad,
    )

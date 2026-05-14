from __future__ import annotations

from .._internal import (
    frame_labeled_bytes,
    frame_str,
    frame_uint32,
    require_exact_length_bytes,
    require_instance,
    require_non_empty_bytes,
)
from ..core.key_ids import KeyIdHelpers
from ..core.key_types import KeyKind
from ..core.types import KeyId
from ..errors import (
    InvalidKeyError,
    KeyNotFoundError,
    KeystoreNotLoadedError,
    WrongKeyTypeError,
)
from ..keystore.file_keystore import FileKeyStore
from ..primitives.aead import decrypt, encrypt
from ._constants import (
    STORAGE_AAD_CONTEXT,
    STORAGE_FIELD_ALGORITHM,
    STORAGE_FIELD_TYPE,
    STORAGE_FIELD_VERSION,
    STORAGE_KEY_LENGTH,
)
from .envelopes import StorageFieldEnvelope

__all__ = [
    "encrypt_storage_field",
    "decrypt_storage_field",
    "encrypt_storage_field_with_raw_key",
    "decrypt_storage_field_with_raw_key",
]


def _require_loaded_keystore(keystore: FileKeyStore) -> None:
    """
    Validate that FileKeyStore is loaded for storage crypto operations.

    This helper does not call load() implicitly. Opening/loading the keystore
    remains the caller's responsibility.

    :param keystore: File keystore instance.
    :raises InvalidInputError: If keystore has the wrong type.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    """
    require_instance(keystore, FileKeyStore, field_name = "keystore")

    if not keystore.is_loaded():
        raise KeystoreNotLoadedError("keystore is not loaded")


def _build_storage_aad(*, key_id: KeyId,
                       aad: bytes) -> bytes:
    """
    Build protocol-level AAD for storage field encryption.

    User-supplied AAD is mandatory and is framed together with storage envelope
    metadata so ciphertext cannot be moved between keys or storage contexts.

    :param key_id: Storage key identifier embedded in the envelope.
    :param aad: Caller-provided storage context AAD.
    :return: Framed protocol AAD bytes.
    """
    return (
            frame_labeled_bytes(b"context", STORAGE_AAD_CONTEXT)
            + frame_labeled_bytes(b"algorithm", frame_str(STORAGE_FIELD_ALGORITHM))
            + frame_labeled_bytes(b"type", frame_str(STORAGE_FIELD_TYPE))
            + frame_labeled_bytes(b"version", frame_uint32(STORAGE_FIELD_VERSION))
            + frame_labeled_bytes(b"key_id", frame_str(str(key_id)))
            + frame_labeled_bytes(b"user_aad", aad)
    )


def _load_storage_key_from_keystore(keystore: FileKeyStore, key_id: KeyId) -> bytes:
    """
    Load a symmetric storage key from FileKeyStore.

    FileKeyStore remains responsible for key record loading/decryption. This
    helper only enforces the storage-crypto key kind and key length policy.

    :param keystore: Loaded file keystore.
    :param key_id: Storage key identifier.
    :return: Raw 32-byte symmetric storage key.
    :raises InvalidInputError: If keystore has the wrong type.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises KeyNotFoundError: If key_id does not exist.
    :raises WrongKeyTypeError: If key kind is not symmetric.
    :raises InvalidKeyError: If key material is not a 32-byte storage key.
    """
    _require_loaded_keystore(keystore)

    key_bytes, meta = keystore.get_key(key_id)

    if meta.get("kind") != KeyKind.SYMMETRIC.value:
        raise WrongKeyTypeError("storage crypto requires a symmetric keystore key")

    require_exact_length_bytes(
        key_bytes,
        field_name = "storage_key",
        length = STORAGE_KEY_LENGTH,
        error_cls = InvalidKeyError,
    )
    return key_bytes


def _resolve_storage_key_id(keystore: FileKeyStore,
                            key_id: KeyId | str | bytes | None) -> KeyId:
    """
    Resolve explicit storage key id or current active keystore key id.

    :param keystore: Loaded file keystore.
    :param key_id: Explicit storage key id or None.
    :return: Resolved storage key id.
    :raises InvalidInputError: If keystore or key_id is invalid.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises KeyNotFoundError: If key_id is omitted and no active key is set.
    """
    _require_loaded_keystore(keystore)

    if key_id is not None:
        return KeyIdHelpers.normalize_key_id(key_id)

    active_key_id = keystore.get_active_key_id()
    if active_key_id is None:
        raise KeyNotFoundError("active storage key is not set")

    return active_key_id


def encrypt_storage_field_with_raw_key(key: bytes, plaintext: bytes, *,
                                       aad: bytes, key_id: KeyId | str | bytes) -> bytes:
    """
    Encrypt storage field bytes using a raw storage key.

    This is a low-level foundation/test utility. Recommended integration should
    use encrypt_storage_field() with FileKeyStore and key_id.

    :param key: Raw 32-byte symmetric storage key.
    :param plaintext: Storage field plaintext bytes.
    :param aad: Mandatory caller-provided storage context AAD.
    :param key_id: Storage key identifier to embed in the envelope.
    :return: Serialized StorageFieldEnvelope bytes.
    :raises InvalidInputError: If plaintext or aad is invalid.
    :raises InvalidKeyError: If storage key is invalid.
    :raises MalformedDataError: If key_id is invalid for envelope construction.
    """
    require_exact_length_bytes(
        key,
        field_name = "storage_key",
        length = STORAGE_KEY_LENGTH,
        error_cls = InvalidKeyError,
    )
    require_instance(plaintext, bytes, field_name = "plaintext")
    require_non_empty_bytes(aad, field_name = "aad")

    normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)

    protocol_aad = _build_storage_aad(
        key_id = normalized_key_id,
        aad = aad,
    )
    aead = encrypt(key, plaintext, aad = protocol_aad)

    return StorageFieldEnvelope(
        version = STORAGE_FIELD_VERSION,
        type = STORAGE_FIELD_TYPE,
        algorithm = STORAGE_FIELD_ALGORITHM,
        key_id = normalized_key_id,
        aead = aead,
    ).to_bytes()


def decrypt_storage_field_with_raw_key(key: bytes, envelope: StorageFieldEnvelope,
                                       *, aad: bytes) -> bytes:
    """
    Decrypt a parsed storage field envelope using a raw storage key.

    This is a low-level foundation/test utility. Recommended integration should
    use decrypt_storage_field() with FileKeyStore and serialized envelope bytes.

    :param key: Raw 32-byte symmetric storage key.
    :param envelope: Parsed StorageFieldEnvelope.
    :param aad: Mandatory caller-provided storage context AAD.
    :return: Decrypted storage field plaintext bytes.
    :raises InvalidInputError: If envelope or aad is invalid.
    :raises InvalidKeyError: If storage key is invalid.
    :raises AuthenticationError: If AEAD authentication fails.
    """
    require_exact_length_bytes(
        key,
        field_name = "storage_key",
        length = STORAGE_KEY_LENGTH,
        error_cls = InvalidKeyError,
    )
    require_instance(
        envelope,
        StorageFieldEnvelope,
        field_name = "envelope",
    )
    require_non_empty_bytes(aad, field_name = "aad")

    protocol_aad = _build_storage_aad(
        key_id = envelope.key_id,
        aad = aad,
    )

    return decrypt(
        key,
        envelope.aead,
        aad = protocol_aad,
    )


def encrypt_storage_field(keystore: FileKeyStore, plaintext: bytes, *,
                          aad: bytes, key_id: KeyId | str | bytes | None = None) -> bytes:
    """
    Encrypt storage field bytes using a symmetric key from FileKeyStore.

    If key_id is omitted, the current active keystore key is used. The selected
    key_id is embedded into StorageFieldEnvelope, so future decrypt operations
    resolve the original key from the envelope instead of using the current
    active key.

    :param keystore: Loaded file keystore.
    :param plaintext: Storage field plaintext bytes.
    :param aad: Mandatory caller-provided storage context AAD.
    :param key_id: Optional explicit storage key id. If omitted, active key is used.
    :return: Serialized StorageFieldEnvelope bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises KeyNotFoundError: If explicit key does not exist or active key is not set.
    :raises WrongKeyTypeError: If resolved key is not symmetric.
    :raises InvalidKeyError: If resolved key material is invalid.
    """
    resolved_key_id = _resolve_storage_key_id(keystore, key_id)
    storage_key = _load_storage_key_from_keystore(keystore, resolved_key_id)

    return encrypt_storage_field_with_raw_key(
        storage_key,
        plaintext,
        aad = aad,
        key_id = resolved_key_id,
    )


def decrypt_storage_field(keystore: FileKeyStore, envelope: bytes, *,
                          aad: bytes) -> bytes:
    """
    Decrypt storage field bytes using the key_id embedded in StorageFieldEnvelope.

    The current active key is not used for decryption. This keeps old records
    decryptable after storage/data active key rotation.

    :param keystore: Loaded file keystore.
    :param envelope: Serialized StorageFieldEnvelope bytes.
    :param aad: Mandatory caller-provided storage context AAD.
    :return: Decrypted storage field plaintext bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises KeyNotFoundError: If envelope key_id does not exist.
    :raises WrongKeyTypeError: If envelope key_id does not reference a symmetric key.
    :raises InvalidKeyError: If storage key material is invalid.
    :raises MalformedDataError: If envelope is malformed.
    :raises UnsupportedFormatError: If envelope version/type/algorithm is unsupported.
    :raises AuthenticationError: If AEAD authentication fails.
    """
    _require_loaded_keystore(keystore)
    require_instance(envelope, bytes, field_name = "envelope")
    require_non_empty_bytes(aad, field_name = "aad")

    storage_envelope = StorageFieldEnvelope.from_bytes(envelope)
    storage_key = _load_storage_key_from_keystore(
        keystore,
        storage_envelope.key_id,
    )

    return decrypt_storage_field_with_raw_key(
        storage_key,
        storage_envelope,
        aad = aad,
    )

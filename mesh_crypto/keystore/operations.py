from __future__ import annotations

from .._internal import require_instance, b64_decode, require_exact_length_bytes
from ..core.key_ids import KeyIdHelpers
from ..core.key_types import KeyKind
from ..core.serialization import SigningKeySerializer
from ..core.types import KeyId
from ..errors import KeystoreNotLoadedError, InvalidKeyError, MalformedDataError, WrongKeyTypeError
from ..primitives.signatures import sign
from .file_keystore import FileKeyStore

__all__ = ["sign_with_key", "require_signing_key_matches_public_key"]


def _require_initialized_keystore(keystore: FileKeyStore) -> None:
    """
    Validate that FileKeyStore is initialized for operation-based key usage.

    This function does not call load() implicitly. Opening/loading the keystore
    remains the caller's responsibility.

    :param keystore: File keystore instance.
    :raises InvalidInputError: If keystore has the wrong type.
    :raises KeystoreNotLoadedError: If keystore master metadata does not exist.
    """
    require_instance(keystore, FileKeyStore, field_name = "keystore")

    if not keystore.exists():
        raise KeystoreNotLoadedError("keystore is not initialized or loaded")


def _require_ed25519_key_metadata(meta: dict[str, object]) -> None:
    """
    Validate that keystore metadata describes an Ed25519 private key record.

    FileKeyStore is responsible for record parsing, metadata validation, and
    decrypting the stored key blob. This helper only enforces the operation
    policy required for Ed25519 signing.

    :param meta: Keystore key metadata.
    :raises WrongKeyTypeError: If the key is not an Ed25519 key.
    """
    if meta.get("kind") != KeyKind.ED25519.value:
        raise WrongKeyTypeError("sign_with_key requires an Ed25519 keystore key")


def sign_with_key(keystore: FileKeyStore, key_id: KeyId | str | bytes, *,
                  context: bytes, data: bytes) -> bytes:
    """
    Sign context-bound data using an Ed25519 private key stored in FileKeyStore.

    The raw Ed25519 private key bytes are restored only inside this operation
    path and are not returned to the caller.

    :param keystore: Loaded file keystore.
    :param key_id: Identifier of the Ed25519 signing key.
    :param context: Non-empty signing context bytes.
    :param data: Data bytes to sign.
    :return: Ed25519 signature bytes.
    :raises InvalidInputError: If inputs are invalid.
    :raises KeystoreNotLoadedError: If keystore is not initialized or loaded.
    :raises KeyNotFoundError: If the key does not exist.
    :raises WrongKeyTypeError: If the key is not Ed25519.
    :raises InvalidKeyError: If stored key material is invalid or signing fails.
    """
    _require_initialized_keystore(keystore)

    normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)
    key_bytes, meta = keystore.get_key(normalized_key_id)

    _require_ed25519_key_metadata(meta)

    key_pair = SigningKeySerializer.restore_pair_from_private_bytes(key_bytes)
    return sign(context, data, key_pair.sk)


def require_signing_key_matches_public_key(keystore: FileKeyStore, key_id: KeyId | str | bytes,
                                           public_key: bytes) -> None:
    """
    Validate that a keystore Ed25519 signing key matches the provided public key.

    :param keystore: Loaded file keystore.
    :param key_id: Ed25519 signing key identifier.
    :param public_key: Expected raw Ed25519 public key bytes.
    :raises KeystoreNotLoadedError: If keystore is not loaded.
    :raises KeyNotFoundError: If key_id does not exist.
    :raises WrongKeyTypeError: If key_id does not reference an Ed25519 key.
    :raises MalformedDataError: If key metadata is malformed.
    :raises InvalidKeyError: If public_key does not match keystore metadata.
    """
    require_exact_length_bytes(
        public_key,
        field_name = "public_key",
        length = 32,
        error_cls = InvalidKeyError,
    )

    _require_initialized_keystore(keystore)

    _, meta = keystore.get_key(key_id)

    if meta.get("kind") != KeyKind.ED25519.value:
        raise WrongKeyTypeError("signing operation requires an Ed25519 key")

    public_key_b64 = meta.get("public_key")
    if not isinstance(public_key_b64, str):
        raise MalformedDataError("signing key metadata missing public_key")

    stored_public_key = b64_decode(
        public_key_b64,
        field_name = "public_key",
    )

    if stored_public_key != public_key:
        raise InvalidKeyError("identity public key does not match keystore signing key")

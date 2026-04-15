from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable

from .._internal import require_instance, require_non_empty_bytes, require_exact_length_bytes, \
    require_optional_instance, b64_encode, require_dict_field, require_int_field, require_str_field
from ..core.key_ids import KeyIdHelpers
from ..core.key_types import KeyKind
from ..core.serialization import EncryptionKeySerializer, SigningKeySerializer
from ..core.types import KeyId
from ..core.domain_separation import AAD_PURPOSE_KEY_BLOB
from ..errors import (
    InvalidInputError,
    InvalidKeyError,
    KeyNotFoundError,
    KeystoreNotLoadedError,
    MalformedDataError, UnsupportedFormatError,
)
from ..primitives.aead import decrypt, encrypt
from ..primitives.envelopes import AeadEnvelope
from .protectors import Protector

__all__ = ["FileKeyStore"]

_KEY_FILE_VERSION = 1
_METADATA_VERSION = 1
_MASTER_KEY_LENGTH = 32
_KEYS_DIRNAME = "keys"
_MASTER_FILENAME = "master.key"
_METADATA_FILENAME = "keystore.json"


def _ensure_mode_600(path: Path) -> None:
    """
    Best-effort attempt to restrict file permissions to owner read/write only.

    :param path: File path whose permissions should be restricted.
    """
    try:
        path.chmod(0o600)
    except Exception:
        pass


def _atomic_write_text(path: Path, text: str) -> None:
    """
    Atomically write text to a file.

    :param path: Target file path.
    :param text: UTF-8 text to write.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding = "utf-8")
    _ensure_mode_600(tmp)
    os.replace(tmp, path)


class FileKeyStore:
    """
    File-based keystore for encrypted key blobs.

    Directory layout under the configured keystore path:

      master.key           # provider metadata used to restore the master key
      keys/
        <uuid>.key         # versioned encrypted key records
      keystore.json        # keystore metadata (version, created_at, active_key)

    Responsibilities:
    - manage filesystem layout and keystore metadata
    - load/store wrapped master key metadata through a Protector
    - encrypt/decrypt per-key blobs using the loaded master key
    - track active key selection
    """

    def __init__(self, path: str | Path, protector: Protector):
        """
        Initialize the file keystore.

        :param path: Keystore directory path.
        :param protector: Protector used to wrap and unwrap the master key.
        """
        self.path = Path(path).expanduser()
        self._protector = protector

        self.path.mkdir(parents = True, exist_ok = True)
        self._keys_dir = self.path / _KEYS_DIRNAME
        self._keys_dir.mkdir(parents = True, exist_ok = True)

        self._master_meta_path = self.path / _MASTER_FILENAME
        self._meta_path = self.path / _METADATA_FILENAME

        self._master_key: bytes | None = None
        self._meta: dict[str, Any] = {}

    # ==============================
    # Lifecycle and master key state
    # ==============================

    def exists(self) -> bool:
        """
        Check whether keystore master metadata exists.

        :return: True if wrapped master metadata exists.
        """
        return self._master_meta_path.exists()

    def create_new(self, overwrite: bool = False) -> None:
        """
        Create a new keystore with a fresh master key.

        :param overwrite: Whether to overwrite existing master metadata.
        :raises FileExistsError: If keystore already exists and overwrite is False.
        """
        if self.exists() and not overwrite:
            raise FileExistsError("master.key already exists")

        master_key = os.urandom(_MASTER_KEY_LENGTH)
        wrapped_meta = self._protector.wrap(master_key)

        _atomic_write_text(
            self._master_meta_path,
            json.dumps(wrapped_meta, separators = (",", ":")),
        )

        self._master_key = master_key
        self._meta = {
            "version": _METADATA_VERSION,
            "created_at": int(time.time()),
            "active_key": None,
        }
        self._write_meta()

    def load(self) -> None:
        """
        Load wrapped master key metadata and restore the plaintext master key.

        The load operation is fail-closed:
        - in-memory state is updated only after all required metadata has been
          successfully parsed and validated;
        - if loading fails at any stage, the keystore remains unloaded.

        :raises FileNotFoundError: If master metadata file is missing.
        :raises MalformedDataError: If metadata files are malformed or not valid JSON objects.
        :raises InvalidKeyError: If the restored master key is invalid.
        """
        if not self.exists():
            raise FileNotFoundError("master.key not found")

        try:
            raw = json.loads(self._master_meta_path.read_text(encoding = "utf-8"))
        except json.JSONDecodeError as exc:
            raise MalformedDataError("master.key contains invalid JSON") from exc
        require_instance(raw, dict, field_name = "master_metadata", error_cls = MalformedDataError)

        master_key = self._protector.unwrap(raw)
        try:
            require_exact_length_bytes(master_key, field_name = "master_key", length = _MASTER_KEY_LENGTH)
        except InvalidInputError as exc:
            raise InvalidKeyError("restored master key is invalid") from exc

        if self._meta_path.exists():
            try:
                raw_meta = json.loads(self._meta_path.read_text(encoding = "utf-8"))
            except json.JSONDecodeError as exc:
                raise MalformedDataError("keystore.json contains invalid JSON") from exc
            require_instance(raw_meta, dict, field_name = "keystore_metadata", error_cls = MalformedDataError)
            self._validate_metadata(raw_meta)
            validated_meta = raw_meta
        else:
            validated_meta = {
                "version": _METADATA_VERSION,
                "created_at": int(time.time()),
                "active_key": None,
            }

        self._master_key = master_key
        self._meta = validated_meta

    def close(self) -> None:
        """
        Close the keystore and best-effort clear the in-memory master key.
        """
        self.wipe_master()

    def wipe_master(self) -> None:
        """
        Best-effort cleanup of the in-memory master key reference.

        This is not a strong secure-memory wiping guarantee.
        """
        if self._master_key is None:
            return

        try:
            buf = bytearray(self._master_key)
            for i in range(len(buf)):
                buf[i] = 0
        finally:
            self._master_key = None

    def _require_loaded(self) -> bytes:
        """
        Return the loaded master key or raise if keystore is not loaded.

        :return: Loaded master key bytes.
        :raises KeystoreNotLoadedError: If master key is not loaded.
        """
        if self._master_key is None:
            raise KeystoreNotLoadedError("master key not loaded; call load() or create_new() first")
        return self._master_key

    # ==============================
    # Metadata handling
    # ==============================

    def _validate_metadata(self, meta: dict[str, Any]) -> None:
        """
        Validate keystore metadata structure.

        :param meta: Metadata dictionary.
        :raises MalformedDataError: If metadata structure is invalid.
        """
        version = require_int_field(meta, "version")
        if version != _METADATA_VERSION:
            raise MalformedDataError(f"unsupported keystore metadata version: {version}")

        require_int_field(meta, "created_at")

        active_key = meta.get("active_key")
        require_optional_instance(active_key, str, field_name = "active_key", error_cls = MalformedDataError)

    def _write_meta(self) -> None:
        """
        Persist in-memory keystore metadata to disk.
        """
        self._validate_metadata(self._meta)
        _atomic_write_text(
            self._meta_path,
            json.dumps(self._meta, separators = (",", ":")),
        )

    # ==============================
    # Path helpers
    # ==============================

    def _key_file_path(self, key_id: KeyId) -> Path:
        """
        Compute per-key file path.

        :param key_id: Key identifier.
        :return: Path to the key file.
        """
        return self._keys_dir / f"{key_id.hex}.key"

    # ==============================
    # Blob encryption helpers
    # ==============================

    @staticmethod
    def _build_key_blob_aad(*, key_id: KeyId, kind: KeyKind) -> bytes:
        """
        Build canonical AAD for encrypted key blobs.

        :param key_id: Key identifier.
        :param kind: Key kind.
        :return: Canonical AAD bytes.
        """
        kind_value = kind.value if hasattr(kind, "value") else str(kind)
        return (
                AAD_PURPOSE_KEY_BLOB
                + len(kind_value.encode("utf-8")).to_bytes(4, "big")
                + kind_value.encode("utf-8")
                + key_id.bytes
        )

    def _encrypt_key_bytes(self, *, key_id: KeyId, kind: KeyKind, plaintext: bytes) -> AeadEnvelope:
        """
        Encrypt raw key bytes under the loaded master key.

        :param key_id: Key identifier.
        :param kind: Key kind.
        :param plaintext: Raw key bytes.
        :return: AEAD envelope.
        """
        master_key = self._require_loaded()
        aad = self._build_key_blob_aad(key_id = key_id, kind = kind)
        return encrypt(master_key, plaintext, aad)

    def _decrypt_key_bytes(self, *, key_id: KeyId, kind: KeyKind, envelope: AeadEnvelope) -> bytes:
        """
        Decrypt raw key bytes under the loaded master key.

        :param key_id: Key identifier.
        :param kind: Key kind.
        :param envelope: AEAD envelope.
        :return: Decrypted raw key bytes.
        """
        master_key = self._require_loaded()
        aad = self._build_key_blob_aad(key_id = key_id, kind = kind)
        return decrypt(master_key, envelope, aad)

    # ==============================
    # Key serialization helpers
    # ==============================

    @staticmethod
    def _normalize_kind(kind: KeyKind | str) -> KeyKind:
        """
        Normalize key kind into KeyKind.

        :param kind: Key kind enum or supported string value.
        :return: Normalized KeyKind.
        :raises InvalidInputError: If key kind is invalid.
        """
        if isinstance(kind, KeyKind):
            return kind

        if isinstance(kind, str):
            try:
                return KeyKind(kind)
            except Exception as exc:
                raise InvalidInputError(f"unsupported key kind: {kind}") from exc

        raise InvalidInputError("kind must be KeyKind or string")

    @staticmethod
    def _validate_imported_key_bytes(kind: KeyKind, key_bytes: bytes) -> dict[str, Any]:
        """
        Validate imported raw key bytes for the given key kind and build metadata.

        :param kind: Key kind.
        :param key_bytes: Raw key bytes.
        :return: Metadata dictionary.
        :raises InvalidInputError: If inputs are invalid.
        :raises InvalidKeyError: If key bytes do not match the declared kind.
        """
        require_non_empty_bytes(key_bytes, field_name = "key_bytes")
        created_at = int(time.time())

        if kind == KeyKind.SYMMETRIC:
            if len(key_bytes) != 32:
                raise InvalidKeyError("symmetric key must be 32 bytes")
            return {
                "kind": kind.value,
                "created_at": created_at,
            }

        if kind == KeyKind.ED25519:
            pair = SigningKeySerializer.restore_pair_from_private_bytes(key_bytes)
            public_key = SigningKeySerializer.export_pair_public_key_raw(pair)
            return {
                "kind": kind.value,
                "created_at": created_at,
                "public_key": b64_encode(public_key),
            }

        if kind == KeyKind.X25519:
            pair = EncryptionKeySerializer.restore_pair_from_private_bytes(key_bytes)
            public_key = EncryptionKeySerializer.export_pair_public_key_raw(pair)
            return {
                "kind": kind.value,
                "created_at": created_at,
                "public_key": b64_encode(public_key),
            }

        raise InvalidInputError(f"unsupported key kind: {kind}")

    @staticmethod
    def _validate_key_record(record: dict[str, Any]) -> None:
        """
        Validate on-disk key record structure.

        :param record: Key record dictionary.
        :raises MalformedDataError: If record is malformed.
        """
        version = require_int_field(record, "version")
        if version != _KEY_FILE_VERSION:
            raise MalformedDataError(f"unsupported key record version: {version}")

        envelope_raw = require_dict_field(record, "envelope")
        AeadEnvelope.from_dict(envelope_raw)

        meta = require_dict_field(record, "meta")
        kind = require_str_field(meta, "kind")
        require_int_field(meta, "created_at")

        try:
            KeyKind(kind)
        except Exception as exc:
            raise MalformedDataError(f"unsupported key kind in metadata: {kind}") from exc

        public_key = meta.get("public_key")
        require_optional_instance(public_key, str, field_name = "public_key", error_cls = MalformedDataError)

    # ==============================
    # Public key management API
    # ==============================

    def generate_key(self, kind: KeyKind | str = KeyKind.SYMMETRIC) -> KeyId:
        """
        Generate a fresh key, encrypt it under the master key, and store it.

        :param kind: Key kind.
        :return: New key identifier.
        """
        normalized_kind = self._normalize_kind(kind)
        key_id = KeyIdHelpers.new_key_id()

        if normalized_kind == KeyKind.SYMMETRIC:
            key_bytes = os.urandom(32)
            meta = {
                "kind": normalized_kind.value,
                "created_at": int(time.time()),
            }
        elif normalized_kind == KeyKind.ED25519:
            from ..core.keys import SigningKeyPair

            pair = SigningKeyPair.generate()
            key_bytes = SigningKeySerializer.export_pair_private_key_raw(pair)
            meta = {
                "kind": normalized_kind.value,
                "created_at": int(time.time()),
                "public_key": b64_encode(SigningKeySerializer.export_pair_public_key_raw(pair)),
            }
        elif normalized_kind == KeyKind.X25519:
            from ..core.keys import EncryptionKeyPair

            pair = EncryptionKeyPair.generate()
            key_bytes = EncryptionKeySerializer.export_pair_private_key_raw(pair)
            meta = {
                "kind": normalized_kind.value,
                "created_at": int(time.time()),
                "public_key": b64_encode(EncryptionKeySerializer.export_pair_public_key_raw(pair)),
            }
        else:
            raise InvalidInputError(f"unsupported key kind: {kind}")

        self._store_key_record(key_id = key_id, kind = normalized_kind, key_bytes = key_bytes, meta = meta)

        if self._meta.get("active_key") is None:
            self._meta["active_key"] = str(key_id)
            self._write_meta()

        return key_id

    def import_key(self, key_id: KeyId | str | bytes, key_bytes: bytes, kind: KeyKind | str) -> None:
        """
        Import externally provided raw key bytes into the keystore.

        :param key_id: Key identifier.
        :param key_bytes: Raw key bytes.
        :param kind: Declared key kind.
        """
        normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)
        normalized_kind = self._normalize_kind(kind)
        meta = self._validate_imported_key_bytes(normalized_kind, key_bytes)

        self._store_key_record(
            key_id = normalized_key_id,
            kind = normalized_kind,
            key_bytes = key_bytes,
            meta = meta,
        )

    def _store_key_record(self, *, key_id: KeyId, kind: KeyKind,
                          key_bytes: bytes, meta: dict[str, Any]) -> None:
        """
        Encrypt and persist a key record.

        :param key_id: Key identifier.
        :param kind: Key kind.
        :param key_bytes: Raw key bytes.
        :param meta: Per-key metadata.
        """
        envelope = self._encrypt_key_bytes(
            key_id = key_id,
            kind = kind,
            plaintext = key_bytes,
        )

        record = {
            "version": _KEY_FILE_VERSION,
            "envelope": envelope.to_dict(),
            "meta": meta,
        }
        self._validate_key_record(record)

        _atomic_write_text(
            self._key_file_path(key_id),
            json.dumps(record, separators = (",", ":")),
        )

    def get_key(self, key_id: KeyId | str | bytes) -> tuple[bytes, dict[str, Any]]:
        """
        Low-level retrieval of raw key bytes and metadata.

        This method intentionally returns raw decrypted key bytes and should be
        treated as a low-level API.

        :param key_id: Key identifier.
        :return: Tuple of raw key bytes and metadata.
        :raises KeyNotFoundError: If key file is missing.
        """
        normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)
        path = self._key_file_path(normalized_key_id)

        if not path.exists():
            raise KeyNotFoundError(str(normalized_key_id))

        raw = json.loads(path.read_text(encoding = "utf-8"))
        require_instance(raw, dict, field_name = "key_record", error_cls = MalformedDataError)
        self._validate_key_record(raw)

        meta = require_dict_field(raw, "meta")
        kind = self._normalize_kind(require_str_field(meta, "kind"))

        envelope = AeadEnvelope.from_dict(require_dict_field(raw, "envelope"))
        key_bytes = self._decrypt_key_bytes(
            key_id = normalized_key_id,
            kind = kind,
            envelope = envelope,
        )
        return key_bytes, meta

    def list_keys(self, *, strict: bool = True) -> list[dict[str, Any]] | tuple[
        list[dict[str, Any]], list[dict[str, Any]]]:
        """
        List stored keys without decrypting raw key material.

        In strict mode, malformed key records fail closed and abort the operation.
        In non-strict mode, malformed records are collected and returned separately.

        :param strict: Whether to fail on the first malformed key record.
        :return:
            - if strict=True: list of dictionaries with `key_id` and `meta`
            - if strict=False: tuple of (`valid_records`, `errors`)
        :raises MalformedDataError: If a key record is malformed in strict mode.
        """
        out: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []

        handled_error_types = (
            json.JSONDecodeError,
            MalformedDataError,
            InvalidInputError,
            InvalidKeyError,
            UnsupportedFormatError,
        )

        for path in sorted(self._keys_dir.glob("*.key")):
            try:
                raw = json.loads(path.read_text(encoding = "utf-8"))
                require_instance(raw, dict, field_name = "key_record", error_cls = MalformedDataError)
                self._validate_key_record(raw)
                meta = require_dict_field(raw, "meta")
                key_id = KeyIdHelpers.normalize_key_id(path.stem)
                out.append({"key_id": key_id, "meta": meta})
            except handled_error_types as exc:
                if strict:
                    if isinstance(exc, json.JSONDecodeError):
                        raise MalformedDataError(f"key record '{path.name}' contains invalid JSON") from exc
                    raise
                errors.append(
                    {
                        "key_id": path.stem,
                        "path": str(path),
                        "error": exc,
                    }
                )

        if strict:
            return out
        return out, errors

    # ==============================
    # Active key handling
    # ==============================

    def set_active_key(self, key_id: KeyId | str | bytes) -> None:
        """
        Set the active key identifier.

        :param key_id: Key identifier.
        :raises KeyNotFoundError: If the key does not exist.
        :raises MalformedDataError: If the key record is malformed.
        :raises InvalidKeyError: If the key record cannot be decrypted or restored safely.
        """
        normalized_key_id = KeyIdHelpers.normalize_key_id(key_id)

        self.get_key(normalized_key_id)

        self._meta["active_key"] = str(normalized_key_id)
        self._write_meta()

    def get_active_key_id(self) -> KeyId | None:
        """
        Return currently active key identifier.

        :return: Active key identifier or None.
        """
        value = self._meta.get("active_key")
        if value is None:
            return None
        return KeyIdHelpers.normalize_key_id(value)

    def get_active_key(self) -> tuple[bytes, dict[str, Any]] | None:
        """
        Return the active key record using the low-level retrieval API.

        :return: Tuple of raw key bytes and metadata, or None.
        """
        active_key_id = self.get_active_key_id()
        if active_key_id is None:
            return None
        return self.get_key(active_key_id)

    def rotate_key(self, old_key_id: KeyId | str | bytes, new_key_id: KeyId | str | bytes,
                   migrator: Callable[[KeyId, KeyId], None] | None = None) -> None:
        """
        Baseline active-key switch helper with best-effort rollback on migration failure.

        :param old_key_id: Previous key identifier.
        :param new_key_id: New active key identifier.
        :param migrator: Optional migration hook.
        """
        normalized_old = KeyIdHelpers.normalize_key_id(old_key_id)
        normalized_new = KeyIdHelpers.normalize_key_id(new_key_id)

        self.set_active_key(normalized_new)

        if migrator is None:
            return
        try:
            migrator(normalized_old, normalized_new)
        except Exception:
            self.set_active_key(normalized_old)
            raise

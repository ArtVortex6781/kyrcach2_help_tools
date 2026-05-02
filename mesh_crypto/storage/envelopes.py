from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .._internal import (
    require_bytes,
    require_dict_field,
    require_instance,
    require_int_field,
    require_str_field,
    require_exact_keys
)
from ..core.key_ids import KeyIdHelpers
from ..core.types import KeyId
from ..errors import InvalidInputError, MalformedDataError, UnsupportedFormatError
from ..primitives.envelopes import AeadEnvelope

__all__ = ["StorageFieldEnvelope"]

_STORAGE_FIELD_VERSION = 1
_STORAGE_FIELD_TYPE = "storage_field"
_STORAGE_FIELD_ALGORITHM = "mesh-storage-v1"

_STORAGE_FIELD_KEYS = {
    "version",
    "type",
    "algorithm",
    "key_id",
    "aead",
}


def _validate_version(version: int) -> None:
    """
    Validate storage field envelope version.

    :param version: Envelope version.
    :raises UnsupportedFormatError: If the version is unsupported.
    """
    if version != _STORAGE_FIELD_VERSION:
        raise UnsupportedFormatError(f"unsupported storage field envelope version: {version}")


def _validate_type(value: str) -> None:
    """
    Validate storage field envelope type.

    :param value: Envelope type.
    :raises UnsupportedFormatError: If the type is unsupported.
    """
    if value != _STORAGE_FIELD_TYPE:
        raise UnsupportedFormatError(f"unsupported storage field envelope type: {value}")


def _validate_algorithm(algorithm: str) -> None:
    """
    Validate storage field envelope algorithm.

    :param algorithm: Envelope algorithm.
    :raises UnsupportedFormatError: If the algorithm is unsupported.
    """
    if algorithm != _STORAGE_FIELD_ALGORITHM:
        raise UnsupportedFormatError(f"unsupported storage field algorithm: {algorithm}")


def _normalize_envelope_key_id(value: KeyId | str | bytes) -> KeyId:
    """
    Normalize a storage envelope key identifier.

    :param value: Key identifier value.
    :return: Normalized KeyId.
    :raises MalformedDataError: If the key identifier is malformed.
    """
    try:
        return KeyIdHelpers.normalize_key_id(value)
    except InvalidInputError as exc:
        raise MalformedDataError("invalid storage field key_id") from exc


@dataclass(frozen = True)
class StorageFieldEnvelope:
    """
    Versioned envelope for encrypted storage fields.

    This envelope is a storage-layer wrapper around the primitive AEAD envelope.
    It binds encrypted field blobs to a storage-specific format and records the
    key identifier required for keystore-backed decryption.
    """

    version: int
    type: str
    algorithm: str
    key_id: KeyId
    aead: AeadEnvelope

    def __post_init__(self) -> None:
        """
        Validate storage field envelope invariants.

        :raises MalformedDataError: If field types are invalid.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(self.version, int, field_name = "version", error_cls = MalformedDataError)
        require_instance(self.type, str, field_name = "type", error_cls = MalformedDataError)
        require_instance(self.algorithm, str, field_name = "algorithm", error_cls = MalformedDataError)
        require_instance(self.aead, AeadEnvelope, field_name = "aead", error_cls = MalformedDataError)

        _validate_version(self.version)
        _validate_type(self.type)
        _validate_algorithm(self.algorithm)

        normalized_key_id = _normalize_envelope_key_id(self.key_id)
        object.__setattr__(self, "key_id", normalized_key_id)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the storage field envelope to a JSON-serializable dictionary.

        :return: Dictionary representation.
        """
        return {
            "version": self.version,
            "type": self.type,
            "algorithm": self.algorithm,
            "key_id": str(self.key_id),
            "aead": self.aead.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "StorageFieldEnvelope":
        """
        Parse a storage field envelope from a dictionary.

        The parser is fail-closed:
        - input must be a dict
        - keys must match exactly
        - version/type/algorithm must be supported
        - key_id must be a valid key identifier
        - nested AEAD envelope must be valid

        :param data: Dictionary representation.
        :return: Parsed StorageFieldEnvelope.
        :raises MalformedDataError: If structure or fields are malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        require_exact_keys(data, _STORAGE_FIELD_KEYS, schema_name = "storage field envelope")

        version = require_int_field(data, "version")
        envelope_type = require_str_field(data, "type")
        algorithm = require_str_field(data, "algorithm")
        key_id_raw = require_str_field(data, "key_id")
        aead_raw = require_dict_field(data, "aead")

        return StorageFieldEnvelope(
            version = version,
            type = envelope_type,
            algorithm = algorithm,
            key_id = _normalize_envelope_key_id(key_id_raw),
            aead = AeadEnvelope.from_dict(aead_raw),
        )

    def to_bytes(self) -> bytes:
        """
        Serialize the storage field envelope to canonical UTF-8 JSON bytes.

        :return: Serialized envelope bytes.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys = True,
            separators = (",", ":"),
        ).encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "StorageFieldEnvelope":
        """
        Parse a storage field envelope from serialized UTF-8 JSON bytes.

        :param data: Serialized envelope bytes.
        :return: Parsed StorageFieldEnvelope.
        :raises InvalidInputError: If data is not bytes.
        :raises MalformedDataError: If bytes are not valid envelope JSON.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_bytes(data, field_name = "data")

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("storage field envelope is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("storage field envelope contains invalid JSON") from exc

        require_instance(raw, dict, field_name = "storage_field_envelope", error_cls = MalformedDataError)

        return StorageFieldEnvelope.from_dict(raw)

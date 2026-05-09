from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .._internal import (
    remap_crypto_error,
    require_dict_field,
    require_exact_keys,
    require_instance,
    require_int,
    require_int_field,
    require_str,
    require_str_field,
    require_supported_algorithm,
    require_supported_type,
    require_supported_version,
)
from ..core.key_ids import KeyIdHelpers
from ..core.types import KeyId
from ..errors import InvalidInputError, MalformedDataError
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


@dataclass(frozen = True)
class StorageFieldEnvelope:
    """
    Versioned envelope for encrypted-at-rest storage fields.

    The envelope binds a storage ciphertext to the key identifier used for
    encryption and wraps the primitive AEAD envelope containing nonce and
    ciphertext bytes.
    """

    version: int
    type: str
    algorithm: str
    key_id: KeyId
    aead: AeadEnvelope

    def __post_init__(self) -> None:
        """
        Validate storage field envelope invariants.

        :raises MalformedDataError: If field types or shapes are invalid.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_int(self.version, field_name = "version", error_cls = MalformedDataError)
        require_str(self.type, field_name = "type", error_cls = MalformedDataError)
        require_str(self.algorithm, field_name = "algorithm", error_cls = MalformedDataError)
        require_instance(self.aead, AeadEnvelope, field_name = "aead", error_cls = MalformedDataError)

        require_supported_version(self.version, _STORAGE_FIELD_VERSION)
        require_supported_type(self.type, _STORAGE_FIELD_TYPE)
        require_supported_algorithm(self.algorithm, _STORAGE_FIELD_ALGORITHM)

        object.__setattr__(
            self,
            "key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.key_id),
                error_cls = MalformedDataError,
                message = "invalid storage field key_id",
            ),
        )

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
        - input must be a dict;
        - keys must match exactly;
        - version/type/algorithm must be supported;
        - key_id must be a valid UUID;
        - nested AEAD envelope must be valid.

        :param data: Dictionary representation.
        :return: Parsed StorageFieldEnvelope.
        :raises MalformedDataError: If structure or fields are malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        require_exact_keys(
            data,
            _STORAGE_FIELD_KEYS,
            schema_name = "storage field envelope",
        )

        version = require_int_field(data, "version")
        envelope_type = require_str_field(data, "type")
        algorithm = require_str_field(data, "algorithm")
        key_id_raw = require_str_field(data, "key_id")
        aead_raw = require_dict_field(data, "aead")

        return StorageFieldEnvelope(
            version = version,
            type = envelope_type,
            algorithm = algorithm,
            key_id = remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(key_id_raw),
                error_cls = MalformedDataError,
                message = "invalid storage field key_id",
            ),
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
        require_instance(data, bytes, field_name = "data", error_cls = InvalidInputError)

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("storage field envelope is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("storage field envelope contains invalid JSON") from exc

        require_instance(
            raw,
            dict,
            field_name = "storage_field_envelope",
            error_cls = MalformedDataError,
        )

        return StorageFieldEnvelope.from_dict(raw)

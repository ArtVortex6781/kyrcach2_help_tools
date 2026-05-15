from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .._internal import (
    b64_decode,
    b64_encode,
    remap_crypto_error,
    require_dict_field,
    require_exact_keys,
    require_exact_length_bytes,
    require_instance,
    require_int,
    require_int_field,
    require_str,
    require_str_field,
    require_supported_algorithm,
    require_supported_type,
    require_supported_version,
    require_uint64,
)
from ..core.key_ids import KeyIdHelpers
from ..core.types import KeyId
from ..errors import InvalidInputError, MalformedDataError
from ..primitives.envelopes import AeadEnvelope
from ._constants import (
    DIRECT_MESSAGE_ALGORITHM,
    DIRECT_MESSAGE_TYPE,
    DIRECT_MESSAGE_VERSION,
)

__all__ = ["DirectMessageEnvelope"]

_RATCHET_PUBLIC_KEY_LENGTH = 32

_DIRECT_MESSAGE_KEYS = {
    "version",
    "type",
    "session_id",
    "counter",
    "previous_chain_length",
    "algorithm",
    "ratchet_pub",
    "aead",
}


@dataclass(frozen = True)
class DirectMessageEnvelope:
    """
    Versioned envelope for encrypted direct one-to-one messages.

    This envelope stores direct-message protocol metadata and wraps the
    primitive AEAD envelope containing nonce and ciphertext. The metadata is
    later bound into AEAD AAD by message encryption/decryption logic.
    """

    version: int
    type: str
    session_id: KeyId
    counter: int
    previous_chain_length: int
    algorithm: str
    ratchet_pub: bytes
    aead: AeadEnvelope

    def __post_init__(self) -> None:
        """
        Validate direct message envelope invariants.

        :raises MalformedDataError: If field types or shapes are invalid.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_int(self.version, field_name = "version", error_cls = MalformedDataError)
        require_str(self.type, field_name = "type", error_cls = MalformedDataError)
        require_str(self.algorithm, field_name = "algorithm", error_cls = MalformedDataError)
        require_uint64(self.counter, field_name = "counter", error_cls = MalformedDataError)
        require_uint64(
            self.previous_chain_length,
            field_name = "previous_chain_length",
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.ratchet_pub,
            field_name = "ratchet_pub",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_instance(
            self.aead,
            AeadEnvelope,
            field_name = "aead",
            error_cls = MalformedDataError,
        )

        require_supported_version(self.version, DIRECT_MESSAGE_VERSION)
        require_supported_type(self.type, DIRECT_MESSAGE_TYPE)
        require_supported_algorithm(self.algorithm, DIRECT_MESSAGE_ALGORITHM)

        object.__setattr__(
            self,
            "session_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.session_id),
                error_cls = MalformedDataError,
                message = "invalid direct message session_id",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the direct message envelope to a JSON-serializable dictionary.

        :return: Dictionary representation with base64-encoded binary fields.
        """
        return {
            "version": self.version,
            "type": self.type,
            "session_id": str(self.session_id),
            "counter": self.counter,
            "previous_chain_length": self.previous_chain_length,
            "algorithm": self.algorithm,
            "ratchet_pub": b64_encode(self.ratchet_pub),
            "aead": self.aead.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DirectMessageEnvelope":
        """
        Parse a direct message envelope from a dictionary.

        The parser is fail-closed:
        - input must be a dict;
        - keys must match exactly;
        - version/type/algorithm must be supported;
        - session_id must be a valid UUID;
        - counters must be uint64;
        - ratchet_pub must be valid base64 and decode to 32 bytes;
        - nested AEAD envelope must be valid.

        :param data: Dictionary representation.
        :return: Parsed DirectMessageEnvelope.
        :raises MalformedDataError: If structure or fields are malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        require_exact_keys(
            data,
            _DIRECT_MESSAGE_KEYS,
            schema_name = "direct message envelope",
        )

        version = require_int_field(data, "version")
        envelope_type = require_str_field(data, "type")
        session_id_raw = require_str_field(data, "session_id")
        counter = require_int_field(data, "counter")
        previous_chain_length = require_int_field(data, "previous_chain_length")
        algorithm = require_str_field(data, "algorithm")
        ratchet_pub_b64 = require_str_field(data, "ratchet_pub")
        aead_raw = require_dict_field(data, "aead")

        return DirectMessageEnvelope(
            version = version,
            type = envelope_type,
            session_id = remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(session_id_raw),
                error_cls = MalformedDataError,
                message = "invalid direct message session_id",
            ),
            counter = counter,
            previous_chain_length = previous_chain_length,
            algorithm = algorithm,
            ratchet_pub = b64_decode(ratchet_pub_b64, field_name = "ratchet_pub"),
            aead = AeadEnvelope.from_dict(aead_raw),
        )

    def to_bytes(self) -> bytes:
        """
        Serialize the direct message envelope to canonical UTF-8 JSON bytes.

        :return: Serialized envelope bytes.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys = True,
            separators = (",", ":"),
        ).encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "DirectMessageEnvelope":
        """
        Parse a direct message envelope from serialized UTF-8 JSON bytes.

        :param data: Serialized envelope bytes.
        :return: Parsed DirectMessageEnvelope.
        :raises InvalidInputError: If data is not bytes.
        :raises MalformedDataError: If bytes are not valid envelope JSON.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, bytes, field_name = "data", error_cls = InvalidInputError)

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("direct message envelope is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("direct message envelope contains invalid JSON") from exc

        require_instance(
            raw,
            dict,
            field_name = "direct_message_envelope",
            error_cls = MalformedDataError,
        )

        return DirectMessageEnvelope.from_dict(raw)

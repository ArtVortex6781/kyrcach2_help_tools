from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .._internal import (
    b64_decode,
    b64_encode,
    require_bytes,
    require_int,
    require_dict_field,
    require_exact_keys,
    require_exact_length_bytes,
    require_instance,
    require_int_field,
    require_str_field,
    require_uint64,
)
from ..core.key_ids import KeyIdHelpers
from ..core.types import KeyId
from ..errors import InvalidInputError, MalformedDataError, UnsupportedFormatError
from ..primitives.envelopes import AeadEnvelope

__all__ = ["DirectMessageEnvelope"]

_DIRECT_MESSAGE_VERSION = 1
_DIRECT_MESSAGE_TYPE = "direct_message"
_DIRECT_MESSAGE_ALGORITHM = "mesh-direct-v1"
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


def _validate_version(version: int) -> None:
    """
    Validate direct message envelope version.

    :param version: Envelope version.
    :raises UnsupportedFormatError: If the version is unsupported.
    """
    if version != _DIRECT_MESSAGE_VERSION:
        raise UnsupportedFormatError(f"unsupported direct message envelope version: {version}")


def _validate_type(value: str) -> None:
    """
    Validate direct message envelope type.

    :param value: Envelope type.
    :raises UnsupportedFormatError: If the type is unsupported.
    """
    if value != _DIRECT_MESSAGE_TYPE:
        raise UnsupportedFormatError(f"unsupported direct message envelope type: {value}")


def _validate_algorithm(algorithm: str) -> None:
    """
    Validate direct message envelope algorithm.

    :param algorithm: Envelope algorithm.
    :raises UnsupportedFormatError: If the algorithm is unsupported.
    """
    if algorithm != _DIRECT_MESSAGE_ALGORITHM:
        raise UnsupportedFormatError(f"unsupported direct message algorithm: {algorithm}")


def _normalize_session_id(value: KeyId | str | bytes) -> KeyId:
    """
    Normalize direct session identifier.

    :param value: Session identifier.
    :return: Normalized UUID session identifier.
    :raises MalformedDataError: If the session identifier is malformed.
    """
    try:
        return KeyIdHelpers.normalize_key_id(value)
    except InvalidInputError as exc:
        raise MalformedDataError("invalid direct message session_id") from exc


def _validate_ratchet_public_key(value: object) -> None:
    """
    Validate raw X25519 ratchet public key bytes.

    :param value: Ratchet public key bytes.
    :raises MalformedDataError: If the value is not a 32-byte public key blob.
    """
    try:
        require_exact_length_bytes(
            value,
            field_name = "ratchet_pub",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
        )
    except InvalidInputError as exc:
        raise MalformedDataError(
            f"ratchet_pub must be exactly {_RATCHET_PUBLIC_KEY_LENGTH} bytes"
        ) from exc


@dataclass(frozen = True)
class DirectMessageEnvelope:
    """
    Versioned envelope for encrypted direct one-to-one messages.

    This envelope stores direct-message protocol metadata and wraps the
    primitive AEAD envelope containing nonce and ciphertext. The metadata is
    validated here and must later be bound into AEAD AAD by message encryption
    and decryption logic.
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
        try:
            require_int(self.version, field_name = "version")
        except InvalidInputError as exc:
            raise MalformedDataError(str(exc)) from exc
        require_instance(self.type, str, field_name = "type", error_cls = MalformedDataError)
        require_instance(self.algorithm, str, field_name = "algorithm", error_cls = MalformedDataError)
        require_instance(self.aead, AeadEnvelope, field_name = "aead", error_cls = MalformedDataError)

        _validate_version(self.version)
        _validate_type(self.type)
        _validate_algorithm(self.algorithm)

        normalized_session_id = _normalize_session_id(self.session_id)
        object.__setattr__(self, "session_id", normalized_session_id)

        try:
            require_uint64(self.counter, field_name = "counter")
            require_uint64(self.previous_chain_length, field_name = "previous_chain_length")
        except InvalidInputError as exc:
            raise MalformedDataError(str(exc)) from exc

        _validate_ratchet_public_key(self.ratchet_pub)

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
        - input must be a dict
        - keys must match exactly
        - version/type/algorithm must be supported
        - session_id must be a valid UUID
        - counters must be uint64
        - ratchet_pub must be valid base64 and decode to 32 bytes
        - nested AEAD envelope must be valid

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
            session_id = _normalize_session_id(session_id_raw),
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
        require_bytes(data, field_name = "data")

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("direct message envelope is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("direct message envelope contains invalid JSON") from exc

        require_instance(raw, dict, field_name = "direct_message_envelope", error_cls = MalformedDataError)

        return DirectMessageEnvelope.from_dict(raw)

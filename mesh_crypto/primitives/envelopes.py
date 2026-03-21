from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from ..errors import InvalidKeyError, UnsupportedFormatError

__all__ = ["AeadEnvelope", "WrappedKeyEnvelope"]


def _b64_encode(data: bytes) -> str:
    """
    Encode raw bytes as base64 ASCII string.

    :param data: Raw bytes.
    :return: Base64-encoded ASCII string.
    """
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str, *, field_name: str) -> bytes:
    """
    Decode base64 ASCII string into raw bytes.

    :param data: Base64-encoded ASCII string.
    :param field_name: Field name used for error reporting.
    :return: Decoded raw bytes.
    :raises InvalidKeyError: If the value is not valid base64 text.
    """
    try:
        return base64.b64decode(data.encode("ascii"), validate = True)
    except Exception as exc:
        raise InvalidKeyError(f"invalid base64 value for '{field_name}'") from exc


def _require_int(data: dict[str, Any], field_name: str) -> int:
    """
    Extract and validate an integer field from a mapping.

    :param data: Source mapping.
    :param field_name: Required field name.
    :return: Integer field value.
    :raises UnsupportedFormatError: If the field is missing or not an integer.
    """
    value = data.get(field_name)
    if not isinstance(value, int):
        raise UnsupportedFormatError(f"missing or invalid integer field '{field_name}'")
    return value


def _require_str(data: dict[str, Any], field_name: str) -> str:
    """
    Extract and validate a string field from a mapping.

    :param data: Source mapping.
    :param field_name: Required field name.
    :return: String field value.
    :raises UnsupportedFormatError: If the field is missing or not a string.
    """
    value = data.get(field_name)
    if not isinstance(value, str):
        raise UnsupportedFormatError(f"missing or invalid string field '{field_name}'")
    return value


def _validate_version(version: int) -> None:
    """
    Validate envelope version.

    :param version: Envelope version.
    :raises UnsupportedFormatError: If the version is unsupported.
    """
    if version != 1:
        raise UnsupportedFormatError(f"unsupported envelope version: {version}")


def _validate_common_envelope_fields(*, version: int, algorithm: str, expected_algorithm: str,
                                     nonce: bytes, ciphertext: bytes) -> None:
    """
    Validate common fields shared by envelope structures.

    :param version: Envelope version.
    :param algorithm: Algorithm identifier provided in the envelope.
    :param expected_algorithm: Expected algorithm identifier for this envelope type.
    :param nonce: Nonce bytes.
    :param ciphertext: Ciphertext bytes.
    :raises UnsupportedFormatError: If version is unsupported, algorithm does not match,
        or required fields have invalid types.
    """
    _validate_version(version)
    if algorithm != expected_algorithm:
        raise UnsupportedFormatError(
            f"unsupported envelope algorithm: {algorithm}"
        )
    if not isinstance(nonce, bytes):
        raise UnsupportedFormatError("field 'nonce' must be bytes")
    if not isinstance(ciphertext, bytes):
        raise UnsupportedFormatError("field 'ciphertext' must be bytes")


@dataclass(frozen = True)
class AeadEnvelope:
    """
    Versioned envelope for AEAD ciphertext blobs.

    Runtime representation stores raw bytes. JSON/dict export is handled via
    to_dict()/from_dict() and uses base64 for binary fields.
    """

    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        _validate_common_envelope_fields(version = self.version, algorithm = self.algorithm,
                                         expected_algorithm = "aesgcm", nonce = self.nonce,
                                         ciphertext = self.ciphertext)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert envelope to JSON-serializable dictionary representation.

        :return: Dictionary with base64-encoded binary fields.
        """
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "nonce": _b64_encode(self.nonce),
            "ciphertext": _b64_encode(self.ciphertext),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AeadEnvelope":
        """
        Parse AEAD envelope from dictionary representation.

        :param data: Dictionary representation of the envelope.
        :return: Parsed AeadEnvelope instance.
        :raises UnsupportedFormatError: If required fields or structure are invalid.
        :raises InvalidKeyError: If binary fields cannot be decoded.
        """
        if not isinstance(data, dict):
            raise UnsupportedFormatError("AEAD envelope must be a dictionary")

        version = _require_int(data, "version")
        algorithm = _require_str(data, "algorithm")
        nonce_b64 = _require_str(data, "nonce")
        ciphertext_b64 = _require_str(data, "ciphertext")

        return AeadEnvelope(
            version = version,
            algorithm = algorithm,
            nonce = _b64_decode(nonce_b64, field_name = "nonce"),
            ciphertext = _b64_decode(ciphertext_b64, field_name = "ciphertext"),
        )


@dataclass(frozen = True)
class WrappedKeyEnvelope:
    """
    Versioned envelope for wrapped key material.

    This format is intended for later keystore integration. It keeps wrapped
    ciphertext fields separate from KDF metadata while remaining storage-agnostic.
    """

    version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes
    kdf: str | None = None
    kdf_salt: bytes | None = None
    kdf_params: dict[str, int] | None = None

    def __post_init__(self) -> None:
        _validate_common_envelope_fields(version = self.version, algorithm = self.algorithm,
                                         expected_algorithm = "aesgcm", nonce = self.nonce,
                                         ciphertext = self.ciphertext)

        if self.kdf is not None and not isinstance(self.kdf, str):
            raise UnsupportedFormatError("field 'kdf' must be string or None")
        if self.kdf_salt is not None and not isinstance(self.kdf_salt, bytes):
            raise UnsupportedFormatError("field 'kdf_salt' must be bytes or None")
        if self.kdf_params is not None:
            if not isinstance(self.kdf_params, dict):
                raise UnsupportedFormatError("field 'kdf_params' must be dict or None")
            for key, value in self.kdf_params.items():
                if not isinstance(key, str) or not isinstance(value, int):
                    raise UnsupportedFormatError(
                        "field 'kdf_params' must be dict[str, int]"
                    )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert wrapped key envelope to JSON-serializable dictionary representation.

        :return: Dictionary with base64-encoded binary fields where applicable.
        """
        out: dict[str, Any] = {
            "version": self.version,
            "algorithm": self.algorithm,
            "nonce": _b64_encode(self.nonce),
            "ciphertext": _b64_encode(self.ciphertext),
        }

        if self.kdf is not None:
            out["kdf"] = self.kdf
        if self.kdf_salt is not None:
            out["kdf_salt"] = _b64_encode(self.kdf_salt)
        if self.kdf_params is not None:
            out["kdf_params"] = dict(self.kdf_params)

        return out

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "WrappedKeyEnvelope":
        """
        Parse wrapped key envelope from dictionary representation.

        :param data: Dictionary representation of the envelope.
        :return: Parsed WrappedKeyEnvelope instance.
        :raises UnsupportedFormatError: If required fields or structure are invalid.
        :raises InvalidKeyError: If binary fields cannot be decoded.
        """
        if not isinstance(data, dict):
            raise UnsupportedFormatError("wrapped key envelope must be a dictionary")

        version = _require_int(data, "version")
        algorithm = _require_str(data, "algorithm")
        nonce_b64 = _require_str(data, "nonce")
        ciphertext_b64 = _require_str(data, "ciphertext")

        kdf = data.get("kdf")
        if kdf is not None and not isinstance(kdf, str):
            raise UnsupportedFormatError("field 'kdf' must be string or None")

        kdf_salt_raw = data.get("kdf_salt")
        if kdf_salt_raw is not None and not isinstance(kdf_salt_raw, str):
            raise UnsupportedFormatError("field 'kdf_salt' must be string or None")

        kdf_params_raw = data.get("kdf_params")
        normalized_kdf_params: dict[str, int] | None
        if kdf_params_raw is not None:
            if not isinstance(kdf_params_raw, dict):
                raise UnsupportedFormatError("field 'kdf_params' must be dict or None")
            normalized_kdf_params = {}
            for key, value in kdf_params_raw.items():
                if not isinstance(key, str) or not isinstance(value, int):
                    raise UnsupportedFormatError("field 'kdf_params' must be dict[str, int]")
                normalized_kdf_params[key] = value
        else:
            normalized_kdf_params = None

        return WrappedKeyEnvelope(
            version = version,
            algorithm = algorithm,
            nonce = _b64_decode(nonce_b64, field_name = "nonce"),
            ciphertext = _b64_decode(ciphertext_b64, field_name = "ciphertext"),
            kdf = kdf,
            kdf_salt = (
                _b64_decode(kdf_salt_raw, field_name = "kdf_salt")
                if kdf_salt_raw is not None
                else None
            ),
            kdf_params = normalized_kdf_params,
        )

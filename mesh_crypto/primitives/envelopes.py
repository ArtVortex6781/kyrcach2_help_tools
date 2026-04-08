from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..errors import MalformedDataError, UnsupportedFormatError
from .._internal import require_instance, require_optional_instance, SCRYPT_MIN_SALT_LEN, b64_encode, b64_decode, \
    require_int_field, require_str_field

__all__ = ["AeadEnvelope", "WrappedKeyEnvelope"]

_AEAD_ALGORITHMS = {"aesgcm"}
_WRAPPED_KEY_ALGORITHMS = {"aesgcm"}
_KDF_IDS = {"scrypt"}
_WRAPPED_KEY_PURPOSES = {"private_key", "seed", "session_key"}

_AEAD_KEYS = {"version", "algorithm", "nonce", "ciphertext"}
_WRAPPED_KEY_KEYS = {
    "version",
    "algorithm",
    "nonce",
    "ciphertext",
    "kdf",
    "kdf_salt",
    "kdf_params",
    "purpose",
}
_WRAPPED_BASE_KEY_KEYS = {"version", "algorithm", "nonce", "ciphertext", "purpose"}

_AESGCM_NONCE_LEN = 12
_AESGCM_TAG_LEN = 16
_SCRYPT_REQUIRED_PARAMS = {"n", "r", "p"}


def _require_required_keys(data: dict[str, Any], required_keys: set[str], *, schema_name: str) -> None:
    """
    Validate that a mapping contains all required keys.

    :param data: Source mapping.
    :param required_keys: Required key set.
    :param schema_name: Human-readable schema name used in error messages.
    :raises MalformedDataError: If required keys are missing.
    """
    actual_keys = set(data.keys())
    missing = required_keys - actual_keys

    if missing:
        raise MalformedDataError(
            f"{schema_name} missing keys: {sorted(missing)}"
        )


def _require_allowed_keys(data: dict[str, Any], allowed_keys: set[str], *, schema_name: str) -> None:
    """
    Validate that a mapping does not contain unexpected keys.

    :param data: Source mapping.
    :param allowed_keys: Allowed key set.
    :param schema_name: Human-readable schema name used in error messages.
    :raises MalformedDataError: If unexpected keys are present.
    """
    actual_keys = set(data.keys())
    extra = actual_keys - allowed_keys
    if extra:
        raise MalformedDataError(f"{schema_name} contains unexpected keys: {sorted(extra)}")


def _require_exact_keys(data: dict[str, Any], expected_keys: set[str], *, schema_name: str) -> None:
    """
    Validate that a mapping contains exactly the expected keys.

    :param data: Source mapping.
    :param expected_keys: Allowed and required key set.
    :param schema_name: Human-readable schema name used in error messages.
    :raises MalformedDataError: If keys are missing or unexpected.
    """
    _require_allowed_keys(data, expected_keys, schema_name = schema_name)
    _require_required_keys(data, expected_keys, schema_name = schema_name)


def _validate_version(version: int) -> None:
    """
    Validate envelope version.

    :param version: Envelope version.
    :raises UnsupportedFormatError: If the version is unsupported.
    """
    if version != 1:
        raise UnsupportedFormatError(f"unsupported envelope version: {version}")


def _validate_algorithm(*, algorithm: str, allowed_algorithms: set[str], field_name: str = "algorithm") -> None:
    """
    Validate that an algorithm identifier is supported.

    :param algorithm: Algorithm identifier.
    :param allowed_algorithms: Allowed algorithm identifiers.
    :param field_name: Field name used in error messages.
    :raises UnsupportedFormatError: If the algorithm is unsupported.
    """
    if algorithm not in allowed_algorithms:
        raise UnsupportedFormatError(f"unsupported {field_name}: {algorithm}")


def _validate_common_envelope_fields(*, version: int, algorithm: str,
                                     allowed_algorithms: set[str], nonce: bytes, ciphertext: bytes) -> None:
    """
    Validate fields common to encrypted envelope structures.

    This helper centralizes validation shared across multiple envelope types:
    version, algorithm, nonce type, and ciphertext type.

    :param version: Envelope version.
    :param algorithm: Algorithm identifier stored in the envelope.
    :param allowed_algorithms: Allowed algorithm identifiers for this envelope type.
    :param nonce: Nonce bytes.
    :param ciphertext: Ciphertext bytes.
    :raises UnsupportedFormatError: If version or algorithm is unsupported.
    :raises InvalidInputError: If runtime envelope construction uses invalid argument types.
    """
    _validate_version(version)
    _validate_algorithm(algorithm = algorithm, allowed_algorithms = allowed_algorithms)
    require_instance(nonce, bytes, field_name = "nonce", error_cls = MalformedDataError)
    require_instance(ciphertext, bytes, field_name = "ciphertext", error_cls = MalformedDataError)


def _validate_aesgcm_shape(*, nonce: bytes, ciphertext: bytes) -> None:
    """
    Validate AES-GCM-specific structural invariants.

    :param nonce: Nonce bytes.
    :param ciphertext: Ciphertext bytes.
    :raises MalformedDataError: If nonce or ciphertext shape is invalid.
    """
    if len(nonce) != _AESGCM_NONCE_LEN:
        raise MalformedDataError(
            f"AES-GCM nonce must be {_AESGCM_NONCE_LEN} bytes, got {len(nonce)}"
        )

    if len(ciphertext) < _AESGCM_TAG_LEN:
        raise MalformedDataError(
            f"AES-GCM ciphertext must be at least {_AESGCM_TAG_LEN} bytes"
        )


def _validate_encrypted_blob_shape(*, algorithm: str, nonce: bytes, ciphertext: bytes) -> None:
    """
    Validate algorithm-specific structural invariants for encrypted blob envelopes.

    :param algorithm: Algorithm identifier.
    :param nonce: Nonce bytes.
    :param ciphertext: Ciphertext bytes.
    :raises UnsupportedFormatError: If algorithm is unsupported.
    :raises MalformedDataError: If structure does not satisfy algorithm-specific constraints.
    """
    if algorithm == "aesgcm":
        _validate_aesgcm_shape(nonce = nonce, ciphertext = ciphertext)
        return

    raise UnsupportedFormatError(f"unsupported algorithm shape validation: {algorithm}")


def _validate_scrypt_params(kdf_params: dict[str, int]) -> None:
    """
    Validate scrypt parameter mapping.

    Required keys:
    - n
    - r
    - p

    Each value must be a strict positive integer.

    :param kdf_params: KDF parameter mapping.
    :raises MalformedDataError: If parameters are missing or invalid.
    """
    require_instance(kdf_params, dict, field_name = "kdf_params", error_cls = MalformedDataError)

    actual_keys = set(kdf_params.keys())
    if actual_keys != _SCRYPT_REQUIRED_PARAMS:
        missing = _SCRYPT_REQUIRED_PARAMS - actual_keys
        extra = actual_keys - _SCRYPT_REQUIRED_PARAMS

        parts: list[str] = []
        if missing:
            parts.append(f"missing keys: {sorted(missing)}")
        if extra:
            parts.append(f"unexpected keys: {sorted(extra)}")

        raise MalformedDataError(
            f"invalid scrypt parameter set ({'; '.join(parts)})"
        )

    for key, value in kdf_params.items():
        require_instance(key, str, field_name = "key", error_cls = MalformedDataError)
        if type(value) is not int:
            raise MalformedDataError(f"scrypt parameter '{key}' must be a strict int")
        if value <= 0:
            raise MalformedDataError(f"scrypt parameter '{key}' must be positive")


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
        _validate_common_envelope_fields(
            version = self.version,
            algorithm = self.algorithm,
            allowed_algorithms = _AEAD_ALGORITHMS,
            nonce = self.nonce,
            ciphertext = self.ciphertext,
        )

        _validate_encrypted_blob_shape(
            algorithm = self.algorithm,
            nonce = self.nonce,
            ciphertext = self.ciphertext,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the envelope to a JSON-serializable dictionary.

        :return: Dictionary with base64-encoded binary fields.
        """
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "nonce": b64_encode(self.nonce),
            "ciphertext": b64_encode(self.ciphertext),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AeadEnvelope":
        """
        Parse an AEAD envelope from a dictionary representation.

        The parser is fail-closed:
        - input must be a dict
        - keys must match exactly
        - binary fields must be valid base64
        - semantic invariants are validated after decoding

        :param data: Dictionary representation of the envelope.
        :return: Parsed AeadEnvelope instance.
        :raises MalformedDataError: If structure or field contents are malformed.
        :raises UnsupportedFormatError: If version or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        _require_exact_keys(data, _AEAD_KEYS, schema_name = "AEAD envelope")

        version = require_int_field(data, "version")
        algorithm = require_str_field(data, "algorithm")
        nonce_b64 = require_str_field(data, "nonce")
        ciphertext_b64 = require_str_field(data, "ciphertext")

        return AeadEnvelope(
            version = version,
            algorithm = algorithm,
            nonce = b64_decode(nonce_b64, field_name = "nonce"),
            ciphertext = b64_decode(ciphertext_b64, field_name = "ciphertext"),
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
    purpose: str
    kdf: str | None = None
    kdf_salt: bytes | None = None
    kdf_params: dict[str, int] | None = None

    def __post_init__(self) -> None:
        _validate_common_envelope_fields(
            version = self.version,
            algorithm = self.algorithm,
            allowed_algorithms = _WRAPPED_KEY_ALGORITHMS,
            nonce = self.nonce,
            ciphertext = self.ciphertext,
        )

        _validate_encrypted_blob_shape(
            algorithm = self.algorithm,
            nonce = self.nonce,
            ciphertext = self.ciphertext,
        )

        require_instance(self.purpose, str, field_name = "purpose", error_cls = MalformedDataError)
        if self.purpose not in _WRAPPED_KEY_PURPOSES:
            raise UnsupportedFormatError(f"unsupported wrapped key purpose: {self.purpose}")

        require_optional_instance(self.kdf, str, field_name = "kdf", error_cls = MalformedDataError)
        require_optional_instance(self.kdf_salt, bytes, field_name = "kdf_salt", error_cls = MalformedDataError)
        require_optional_instance(self.kdf_params, dict, field_name = "kdf_params", error_cls = MalformedDataError)

        has_any_kdf_fields = any(
            value is not None for value in (self.kdf, self.kdf_salt, self.kdf_params)
        )
        has_all_kdf_fields = all(
            value is not None for value in (self.kdf, self.kdf_salt, self.kdf_params)
        )

        if has_any_kdf_fields and not has_all_kdf_fields:
            raise MalformedDataError(
                "kdf, kdf_salt, and kdf_params must be all present or all absent"
            )

        if not has_any_kdf_fields:
            return

        _validate_algorithm(
            algorithm = self.kdf,
            allowed_algorithms = _KDF_IDS,
            field_name = "kdf",
        )

        if self.kdf == "scrypt":
            if len(self.kdf_salt) < SCRYPT_MIN_SALT_LEN:
                raise MalformedDataError(
                    f"scrypt salt must be at least {SCRYPT_MIN_SALT_LEN} bytes"
                )
            _validate_scrypt_params(self.kdf_params)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the wrapped key envelope to a JSON-serializable dictionary.

        :return: Dictionary with base64-encoded binary fields where applicable.
        """
        out: dict[str, Any] = {
            "version": self.version,
            "algorithm": self.algorithm,
            "nonce": b64_encode(self.nonce),
            "ciphertext": b64_encode(self.ciphertext),
            "purpose": self.purpose,
        }

        if self.kdf is not None:
            out["kdf"] = self.kdf
        if self.kdf_salt is not None:
            out["kdf_salt"] = b64_encode(self.kdf_salt)
        if self.kdf_params is not None:
            out["kdf_params"] = dict(self.kdf_params)

        return out

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "WrappedKeyEnvelope":
        """
        Parse a wrapped key envelope from a dictionary representation.

        The parser is fail-closed:
        - input must be a dict
        - unknown fields are rejected
        - required base fields must be present
        - optional KDF fields must obey strict invariants
        - semantic validation is delegated to the dataclass constructor

        :param data: Dictionary representation of the envelope.
        :return: Parsed WrappedKeyEnvelope instance.
        :raises MalformedDataError: If structure or field contents are malformed.
        :raises UnsupportedFormatError: If version, algorithm, purpose, or KDF id is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)

        schema_name = "wrapped key envelope"
        _require_allowed_keys(data, _WRAPPED_KEY_KEYS, schema_name = schema_name)
        _require_required_keys(
            data,
            _WRAPPED_BASE_KEY_KEYS,
            schema_name = schema_name,
        )

        version = require_int_field(data, "version")
        algorithm = require_str_field(data, "algorithm")
        nonce_b64 = require_str_field(data, "nonce")
        ciphertext_b64 = require_str_field(data, "ciphertext")
        purpose = require_str_field(data, "purpose")

        kdf = data.get("kdf")

        kdf_salt_raw = data.get("kdf_salt")
        require_optional_instance(kdf_salt_raw, str, field_name = "kdf_salt_raw", error_cls = MalformedDataError)

        kdf_params_raw = data.get("kdf_params")
        require_optional_instance(kdf_params_raw, dict, field_name = "kdf_params_raw", error_cls = MalformedDataError)

        return WrappedKeyEnvelope(
            version = version,
            algorithm = algorithm,
            nonce = b64_decode(nonce_b64, field_name = "nonce"),
            ciphertext = b64_decode(ciphertext_b64, field_name = "ciphertext"),
            purpose = purpose,
            kdf = kdf,
            kdf_salt = (
                b64_decode(kdf_salt_raw, field_name = "kdf_salt")
                if kdf_salt_raw is not None
                else None
            ),
            kdf_params = kdf_params_raw,
        )

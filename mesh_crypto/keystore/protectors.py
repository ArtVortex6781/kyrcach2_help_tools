from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Protocol

from .._validation import require_non_empty_bytes, require_non_empty_str, require_instance, \
    require_positive_int
from ..errors import (
    InvalidInputError,
    MalformedDataError,
    UnsupportedFormatError,
    ProtectorBackendUnavailableError,
    ProtectorOperationError
)

from ..core.domain_separation import AAD_PURPOSE_WRAPPED_KEY
from ..primitives.aead import decrypt, encrypt
from ..primitives.envelopes import AeadEnvelope, WrappedKeyEnvelope
from ..primitives.kdf import derive_key_scrypt

__all__ = [
    "Protector",
    "PasswordProtector",
    "KeyringProtector",
]

try:
    import keyring
except Exception:
    keyring = None

_PASSWORD_PROVIDER = "password"
_KEYRING_PROVIDER = "keyring"
_PROVIDER_METADATA_VERSION = 1
_MASTER_KEY_PURPOSE = "seed"


def _b64_encode(data: bytes) -> str:
    """
    Encode raw bytes as a base64 ASCII string.

    :param data: Raw bytes to encode.
    :return: Base64-encoded ASCII string.
    """
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data: str, *, field_name: str) -> bytes:
    """
    Decode a base64 ASCII string into raw bytes.

    :param data: Base64-encoded ASCII string.
    :param field_name: Field name used in error messages.
    :return: Decoded raw bytes.
    :raises MalformedDataError: If the value is not valid base64 text.
    """
    try:
        return base64.b64decode(data.encode("ascii"), validate = True)
    except Exception as exc:
        raise MalformedDataError(f"invalid base64 value for '{field_name}'") from exc


def _require_dict_field(data: dict[str, Any], field_name: str) -> dict[str, Any]:
    """
    Extract and validate a required dictionary field.

    :param data: Source metadata dictionary.
    :param field_name: Required field name.
    :return: Dictionary field value.
    :raises MalformedDataError: If the field is missing or invalid.
    """
    value = data.get(field_name)
    require_instance(value, dict, field_name = field_name, error_cls = MalformedDataError)
    return value


def _require_str_field(data: dict[str, Any], field_name: str) -> str:
    """
    Extract and validate a required string field.

    :param data: Source metadata dictionary.
    :param field_name: Required field name.
    :return: String field value.
    :raises MalformedDataError: If the field is missing or invalid.
    """
    value = data.get(field_name)
    require_instance(value, str, field_name = field_name, error_cls = MalformedDataError)
    return value


def _require_int_field(data: dict[str, Any], field_name: str) -> int:
    """
    Extract and validate a required strict integer field.

    :param data: Source metadata dictionary.
    :param field_name: Required field name.
    :return: Integer field value.
    :raises MalformedDataError: If the field is missing or invalid.
    """
    value = data.get(field_name)
    if type(value) is not int:
        raise MalformedDataError(f"missing or invalid integer field '{field_name}'")
    return value


def _validate_provider_metadata_common(meta: dict[str, Any], *, expected_provider: str) -> None:
    """
    Validate common provider metadata fields.

    :param meta: Provider metadata dictionary.
    :param expected_provider: Expected provider identifier.
    :raises MalformedDataError: If metadata structure is invalid.
    :raises UnsupportedFormatError: If version or provider is unsupported.
    """
    version = _require_int_field(meta, "version")
    provider = _require_str_field(meta, "provider")

    if version != _PROVIDER_METADATA_VERSION:
        raise UnsupportedFormatError(f"unsupported protector metadata version: {version}")
    if provider != expected_provider:
        raise UnsupportedFormatError(f"unsupported protector provider: {provider}")


class Protector(Protocol):
    """
    Abstraction for protecting and restoring keystore master keys.
    """

    def wrap(self, master_key: bytes) -> dict[str, Any]:
        """
        Protect plaintext master key bytes and return provider metadata.

        :param master_key: Plaintext master key bytes.
        :return: Provider metadata dictionary.
        """
        ...

    def unwrap(self, meta: dict[str, Any]) -> bytes:
        """
        Restore plaintext master key bytes from provider metadata.

        :param meta: Provider metadata dictionary.
        :return: Plaintext master key bytes.
        """
        ...


@dataclass(frozen = True)
class PasswordProtector:
    """
    Protect master key bytes with a password-derived wrapping key.

    The wrapping key is derived with scrypt and the master key is encrypted
    with AES-GCM through the primitives layer.
    """

    password: str
    scrypt_n: int = 2 ** 16
    scrypt_r: int = 8
    scrypt_p: int = 1
    salt_len: int = 16
    derived_key_length: int = 32

    def __post_init__(self) -> None:
        """
        Validate password protector configuration.

        :raises InvalidInputError: If password or configuration is invalid.
        """
        require_non_empty_str(self.password, field_name = "password")
        require_positive_int(self.scrypt_n, field_name = "scrypt_n")
        require_positive_int(self.scrypt_r, field_name = "scrypt_r")
        require_positive_int(self.scrypt_p, field_name = "scrypt_p")
        if type(self.salt_len) is not int or self.salt_len < 16:
            raise InvalidInputError("salt_len must be an integer >= 16")
        require_positive_int(self.derived_key_length, field_name = "derived_key_length")

    def wrap(self, master_key: bytes) -> dict[str, Any]:
        """
        Protect plaintext master key bytes with password-based wrapping.

        :param master_key: Plaintext master key bytes.
        :return: Provider metadata dictionary.
        :raises InvalidInputError: If inputs are invalid.
        :raises InvalidKeyError: If wrapping fails.
        """
        require_non_empty_bytes(master_key, field_name = "master_key")
        salt = __import__("os").urandom(self.salt_len)

        wrapping_key = derive_key_scrypt(
            self.password.encode("utf-8"),
            salt,
            length = self.derived_key_length,
            n = self.scrypt_n,
            r = self.scrypt_r,
            p = self.scrypt_p,
        )

        encrypted = encrypt(
            wrapping_key,
            master_key,
            AAD_PURPOSE_WRAPPED_KEY,
        )

        wrapped = WrappedKeyEnvelope(
            version = encrypted.version,
            algorithm = encrypted.algorithm,
            nonce = encrypted.nonce,
            ciphertext = encrypted.ciphertext,
            purpose = _MASTER_KEY_PURPOSE,
            kdf = "scrypt",
            kdf_salt = salt,
            kdf_params = {
                "n": self.scrypt_n,
                "r": self.scrypt_r,
                "p": self.scrypt_p,
            },
        )

        return {
            "version": _PROVIDER_METADATA_VERSION,
            "provider": _PASSWORD_PROVIDER,
            "wrapped": wrapped.to_dict(),
        }

    def unwrap(self, meta: dict[str, Any]) -> bytes:
        """
        Restore plaintext master key bytes from password-based metadata.

        :param meta: Provider metadata dictionary.
        :return: Plaintext master key bytes.
        :raises MalformedDataError: If metadata shape is invalid.
        :raises UnsupportedFormatError: If provider metadata version/provider is unsupported.
        :raises InvalidKeyError: If unwrap/decryption fails.
        """
        require_instance(meta, dict, field_name = "meta", error_cls = MalformedDataError)

        _validate_provider_metadata_common(meta, expected_provider = _PASSWORD_PROVIDER)
        wrapped_raw = _require_dict_field(meta, "wrapped")
        wrapped = WrappedKeyEnvelope.from_dict(wrapped_raw)

        if wrapped.kdf != "scrypt" or wrapped.kdf_salt is None or wrapped.kdf_params is None:
            raise MalformedDataError("wrapped metadata must contain complete scrypt parameters")

        wrapping_key = derive_key_scrypt(
            self.password.encode("utf-8"),
            wrapped.kdf_salt,
            length = self.derived_key_length,
            n = wrapped.kdf_params["n"],
            r = wrapped.kdf_params["r"],
            p = wrapped.kdf_params["p"],
        )

        envelope = AeadEnvelope(
            version = wrapped.version,
            algorithm = wrapped.algorithm,
            nonce = wrapped.nonce,
            ciphertext = wrapped.ciphertext,
        )
        return decrypt(wrapping_key, envelope, AAD_PURPOSE_WRAPPED_KEY)


@dataclass(frozen = True)
class KeyringProtector:
    """
    Protect master key bytes by storing them in the OS keyring.

    The provider metadata stores only a locator to the keyring entry.
    """

    service_name: str = "mesh_keystore"
    entry_name: str | None = None

    def __post_init__(self) -> None:
        """
        Validate keyring protector configuration.

        :raises InvalidInputError: If configuration is invalid.
        :raises ProtectorBackendUnavailableError: If the keyring backend is not available.
        """
        if keyring is None:
            raise ProtectorBackendUnavailableError("keyring backend is not available")
        require_non_empty_str(self.service_name, field_name = "service_name")
        if self.entry_name is not None:
            require_non_empty_str(self.entry_name, field_name = "entry_name")

    def wrap(self, master_key: bytes) -> dict[str, Any]:
        """
        Store plaintext master key bytes in the OS keyring.

        :param master_key: Plaintext master key bytes.
        :return: Provider metadata dictionary containing the keyring locator.
        :raises InvalidInputError: If input is invalid.
        :raises ProtectorOperationError: If storing the master key in the keyring fails.
        """
        require_non_empty_bytes(master_key, field_name = "master_key")

        try:
            from uuid import uuid4

            name = self.entry_name or f"mesh-master-{uuid4().hex}"
            keyring.set_password(self.service_name, name, _b64_encode(master_key))
        except Exception as exc:
            raise ProtectorOperationError("failed to store master key in keyring") from exc

        return {
            "version": _PROVIDER_METADATA_VERSION,
            "provider": _KEYRING_PROVIDER,
            "service": self.service_name,
            "name": name,
        }

    def unwrap(self, meta: dict[str, Any]) -> bytes:
        """
        Restore plaintext master key bytes from OS keyring metadata.

        :param meta: Provider metadata dictionary.
        :return: Plaintext master key bytes.
        :raises MalformedDataError: If metadata shape is invalid.
        :raises UnsupportedFormatError: If provider metadata version/provider is unsupported.
        :raises ProtectorOperationError: If keyring lookup fails or the referenced secret is missing.
        """
        require_instance(meta, dict, field_name = "meta", error_cls = MalformedDataError)
        _validate_provider_metadata_common(meta, expected_provider = _KEYRING_PROVIDER)

        service = _require_str_field(meta, "service")
        name = _require_str_field(meta, "name")

        try:
            value = keyring.get_password(service, name)
        except Exception as exc:
            raise ProtectorOperationError("failed to load master key from keyring") from exc

        if value is None:
            raise ProtectorOperationError("no keyring secret found for provided metadata")

        return _b64_decode(value, field_name = "keyring_secret")

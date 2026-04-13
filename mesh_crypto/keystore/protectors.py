from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .._internal import require_non_empty_bytes, require_non_empty_str, require_instance, \
    require_positive_int, b64_decode, b64_encode, require_int_field, require_str_field, require_dict_field
from ..errors import (
    InvalidInputError,
    MalformedDataError,
    UnsupportedFormatError,
    ProtectorBackendUnavailableError,
    ProtectorOperationError, ProtectorSecretNotFoundError
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


def _validate_provider_metadata_common(meta: dict[str, Any], *, expected_provider: str) -> None:
    """
    Validate common provider metadata fields.

    :param meta: Provider metadata dictionary.
    :param expected_provider: Expected provider identifier.
    :raises MalformedDataError: If metadata structure is invalid.
    :raises UnsupportedFormatError: If version or provider is unsupported.
    """
    version = require_int_field(meta, "version")
    provider = require_str_field(meta, "provider")

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

    Compatibility model:
    - unwrap requires the same password that was used for wrap;
    - wrapped metadata carries the scrypt parameters and salt used for derivation;
    - local protector configuration acts as a minimum accepted unwrap policy for
      scrypt parameters;
    - derived_key_length is local protector configuration and must remain
      compatible across wrap/unwrap usage.

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

    def _validate_unwrap_scrypt_policy(self, kdf_params: dict[str, int]) -> None:
        """
        Validate password-based unwrap policy for scrypt parameters loaded from metadata.

        This validator is intentionally policy-level, not structural:
        structural correctness of `kdf_params` must already be guaranteed by
        WrappedKeyEnvelope validation.

        :param kdf_params: Parsed scrypt parameter mapping from wrapped metadata.
        :raises MalformedDataError: If metadata-supplied scrypt parameters violate
            local unwrap policy.
        """
        if kdf_params["n"] < self.scrypt_n:
            raise MalformedDataError(
                f"scrypt parameter 'n' below local minimum policy: "
                f"{kdf_params['n']} < {self.scrypt_n}"
            )

        if kdf_params["r"] < self.scrypt_r:
            raise MalformedDataError(
                f"scrypt parameter 'r' below local minimum policy: "
                f"{kdf_params['r']} < {self.scrypt_r}"
            )

        if kdf_params["p"] < self.scrypt_p:
            raise MalformedDataError(
                f"scrypt parameter 'p' below local minimum policy: "
                f"{kdf_params['p']} < {self.scrypt_p}"
            )

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

        Unwrap compatibility notes:
        - password must match the original wrap password;
        - wrapped metadata must satisfy the local scrypt minimum policy;
        - authentication failure does not uniquely mean wrong password:
          it may also indicate tampering or corrupted metadata.

        :param meta: Provider metadata dictionary.
        :return: Plaintext master key bytes.
        :raises MalformedDataError: If metadata shape is invalid.
        :raises UnsupportedFormatError: If provider metadata version/provider is unsupported.
        :raises InvalidKeyError: If unwrap/decryption fails.
        """
        require_instance(meta, dict, field_name = "meta", error_cls = MalformedDataError)

        _validate_provider_metadata_common(meta, expected_provider = _PASSWORD_PROVIDER)
        wrapped_raw = require_dict_field(meta, "wrapped")
        wrapped = WrappedKeyEnvelope.from_dict(wrapped_raw)

        if wrapped.purpose != _MASTER_KEY_PURPOSE:
            raise MalformedDataError("wrapped metadata has unexpected purpose")
        if wrapped.kdf != "scrypt" or wrapped.kdf_salt is None or wrapped.kdf_params is None:
            raise MalformedDataError("wrapped metadata must contain complete scrypt parameters")
        self._validate_unwrap_scrypt_policy(wrapped.kdf_params)

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
            keyring.set_password(self.service_name, name, b64_encode(master_key))
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
        :raises ProtectorOperationError: If keyring lookup fails.
        :raises ProtectorSecretNotFoundError: If the referenced secret is missing.
        """
        require_instance(meta, dict, field_name = "meta", error_cls = MalformedDataError)
        _validate_provider_metadata_common(meta, expected_provider = _KEYRING_PROVIDER)

        service = require_str_field(meta, "service")
        name = require_str_field(meta, "name")

        try:
            value = keyring.get_password(service, name)
        except Exception as exc:
            raise ProtectorOperationError("failed to load master key from keyring") from exc

        if value is None:
            raise ProtectorSecretNotFoundError(
                "no keyring secret found for provided metadata"
            )

        return b64_decode(value, field_name = "keyring_secret")

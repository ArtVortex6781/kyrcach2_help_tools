from __future__ import annotations

"""
Internal helper namespace for mesh_crypto.

This subpackage contains low-level support modules used across core,
primitives, and keystore layers:

- validation: shared input/type/value validators
- encoding: shared base64 helpers
- parsing: shared mapping field parsers

These modules are internal implementation details and are not part of the
stable public mesh_crypto API.
"""

from .encoding import b64_decode, b64_encode
from .parsing import (
    require_dict_field,
    require_field_instance,
    require_int_field,
    require_str_field,
    require_required_keys,
    require_allowed_keys,
    require_exact_keys
)
from .validation import (
    SCRYPT_MIN_SALT_LEN,
    VALID_AES_KEY_LENGTHS,
    UINT64_MAX,
    require_aesgcm_key_length,
    require_bytes,
    require_ed25519_private_key,
    require_ed25519_public_key,
    require_exact_length_bytes,
    require_instance,
    require_int,
    require_min_length_bytes,
    require_non_empty_bytes,
    require_non_empty_str,
    require_nonce_length,
    require_optional_instance,
    require_positive_int,
    require_non_negative_int,
    require_uint64,
    require_str,
    require_symmetric_key_bytes,
    require_x25519_private_key,
    require_x25519_public_key,
)

__all__ = [
    "b64_encode",
    "b64_decode",
    "require_field_instance",
    "require_str_field",
    "require_int_field",
    "require_dict_field",
    "require_exact_keys",
    "require_allowed_keys",
    "require_required_keys",
    "require_instance",
    "require_optional_instance",
    "require_bytes",
    "require_non_empty_bytes",
    "require_str",
    "require_non_empty_str",
    "require_int",
    "require_positive_int",
    "require_non_negative_int",
    "require_uint64",
    "require_exact_length_bytes",
    "require_min_length_bytes",
    "require_ed25519_private_key",
    "require_ed25519_public_key",
    "require_x25519_private_key",
    "require_x25519_public_key",
    "require_symmetric_key_bytes",
    "require_nonce_length",
    "require_aesgcm_key_length",
    "VALID_AES_KEY_LENGTHS",
    "SCRYPT_MIN_SALT_LEN",
    "UINT64_MAX"
]

__version__ = "0.36.0"

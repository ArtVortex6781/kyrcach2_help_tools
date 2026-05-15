from __future__ import annotations

from .file_keystore import FileKeyStore
from .protectors import KeyringProtector, PasswordProtector, Protector
from .operations import sign_with_key, require_signing_key_matches_public_key

__all__ = [
    "Protector",
    "PasswordProtector",
    "KeyringProtector",
    "FileKeyStore",
    "sign_with_key",
    "require_signing_key_matches_public_key"
]

__version__ = "0.37.0"

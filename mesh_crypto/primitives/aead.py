from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import AuthenticationError, InvalidKeyError
from .envelopes import AeadEnvelope
from .._internal import require_bytes, require_aesgcm_key_length, require_instance

__all__ = ["encrypt", "decrypt"]

_AEAD_VERSION = 1
_AEAD_ALGORITHM = "aesgcm"
_NONCE_LEN = 12


def _validate_encrypt_inputs(key: bytes, plaintext: bytes, aad: bytes) -> None:
    """
    Validate public API inputs for AEAD encryption.

    :param key: Symmetric AES key bytes.
    :param plaintext: Plaintext bytes to encrypt.
    :param aad: Additional authenticated data bytes.
    :raises InvalidInputError: If argument types are invalid.
    :raises InvalidKeyError: If key length is invalid for AES-GCM.
    """
    require_bytes(plaintext, field_name = "plaintext")
    require_bytes(aad, field_name = "aad")
    require_aesgcm_key_length(key)


def _validate_decrypt_inputs(key: bytes, envelope: AeadEnvelope, aad: bytes) -> None:
    """
    Validate public API inputs for AEAD decryption.

    :param key: Symmetric AES key bytes.
    :param envelope: Parsed AEAD envelope.
    :param aad: Additional authenticated data bytes.
    :raises InvalidInputError: If argument types are invalid.
    :raises InvalidKeyError: If key length is invalid for AES-GCM.
    """
    require_aesgcm_key_length(key)
    require_bytes(aad, field_name = "aad")
    require_instance(envelope, AeadEnvelope, field_name = "envelope")


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> AeadEnvelope:
    """
    Encrypt binary data using AES-GCM and return a versioned AEAD envelope.

    :param key: Symmetric AES key bytes.
    :param plaintext: Plaintext bytes to encrypt.
    :param aad: Additional authenticated data bytes.
    :return: AEAD envelope containing version, algorithm, nonce, and ciphertext.
    :raises InvalidInputError: If argument types are invalid.
    :raises InvalidKeyError: If key length/material is invalid or encryption fails.
    """
    _validate_encrypt_inputs(key, plaintext, aad)

    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    except Exception as exc:
        raise InvalidKeyError("failed to encrypt data with AES-GCM") from exc

    return AeadEnvelope(
        version = _AEAD_VERSION,
        algorithm = _AEAD_ALGORITHM,
        nonce = nonce,
        ciphertext = ciphertext,
    )


def decrypt(key: bytes, envelope: AeadEnvelope, aad: bytes) -> bytes:
    """
    Decrypt binary data from an AEAD envelope using AES-GCM.

    :param key: Symmetric AES key bytes.
    :param envelope: Parsed AEAD envelope.
    :param aad: Additional authenticated data bytes.
    :return: Decrypted plaintext bytes.
    :raises InvalidInputError: If argument types are invalid.
    :raises InvalidKeyError: If key length/material is invalid.
    :raises AuthenticationError: If authenticated decryption fails.
    """
    _validate_decrypt_inputs(key, envelope, aad)

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(envelope.nonce, envelope.ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("AES-GCM authentication failed") from exc
    except Exception as exc:
        raise InvalidKeyError("failed to decrypt data with AES-GCM") from exc

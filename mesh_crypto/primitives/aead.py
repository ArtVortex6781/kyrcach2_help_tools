from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import AuthenticationError, InvalidInputError, InvalidKeyError
from .envelopes import AeadEnvelope

__all__ = ["encrypt", "decrypt"]

_AEAD_VERSION = 1
_AEAD_ALGORITHM = "aesgcm"
_VALID_AES_KEY_LENGTHS = {16, 24, 32}
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
    if not isinstance(key, bytes):
        raise InvalidInputError("key must be bytes")
    if not isinstance(plaintext, bytes):
        raise InvalidInputError("plaintext must be bytes")
    if not isinstance(aad, bytes):
        raise InvalidInputError("aad must be bytes")

    if len(key) not in _VALID_AES_KEY_LENGTHS:
        raise InvalidKeyError("AES-GCM key must be 16, 24, or 32 bytes")


def _validate_decrypt_inputs(key: bytes, envelope: AeadEnvelope, aad: bytes) -> None:
    """
    Validate public API inputs for AEAD decryption.

    :param key: Symmetric AES key bytes.
    :param envelope: Parsed AEAD envelope.
    :param aad: Additional authenticated data bytes.
    :raises InvalidInputError: If argument types are invalid.
    :raises InvalidKeyError: If key length is invalid for AES-GCM.
    """
    if not isinstance(key, bytes):
        raise InvalidInputError("key must be bytes")
    if not isinstance(envelope, AeadEnvelope):
        raise InvalidInputError("envelope must be an AeadEnvelope instance")
    if not isinstance(aad, bytes):
        raise InvalidInputError("aad must be bytes")

    if len(key) not in _VALID_AES_KEY_LENGTHS:
        raise InvalidKeyError("AES-GCM key must be 16, 24, or 32 bytes")


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

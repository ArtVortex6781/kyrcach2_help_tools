from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import IntegrityError, InvalidKeyError
from .envelopes import AeadEnvelope

__all__ = ["encrypt", "decrypt"]

_AEAD_VERSION = 1
_AEAD_ALGORITHM = "aesgcm"
_NONCE_LEN = 12


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> AeadEnvelope:
    """
    Encrypt binary data using AES-GCM and return a versioned AEAD envelope.

    :param key: Symmetric AES key bytes.
    :param plaintext: Plaintext bytes to encrypt.
    :param aad: Optional additional authenticated data.
    :return: AEAD envelope containing version, algorithm, nonce, and ciphertext.
    :raises InvalidKeyError: If the key is invalid or encryption fails.
    """
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


def decrypt(key: bytes, envelope: AeadEnvelope, aad: bytes | None = None) -> bytes:
    """
    Decrypt binary data from an AEAD envelope using AES-GCM.

    :param key: Symmetric AES key bytes.
    :param envelope: AEAD envelope containing nonce and ciphertext.
    :param aad: Optional additional authenticated data.
    :return: Decrypted plaintext bytes.
    :raises IntegrityError: If envelope authentication fails.
    :raises InvalidKeyError: If the key is invalid or decryption cannot be performed.
    """
    if not isinstance(envelope, AeadEnvelope):
        raise InvalidKeyError("envelope must be an AeadEnvelope instance")

    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(envelope.nonce, envelope.ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityError("AES-GCM integrity check failed") from exc
    except Exception as exc:
        raise InvalidKeyError("failed to decrypt data with AES-GCM") from exc

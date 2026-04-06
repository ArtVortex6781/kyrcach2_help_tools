from __future__ import annotations

import pytest

from mesh_crypto.core import AAD_PURPOSE_STORAGE
from mesh_crypto.errors import AuthenticationError, InvalidInputError, InvalidKeyError
from mesh_crypto.primitives import AeadEnvelope, decrypt, encrypt


class TestAead:
    def test_encrypt_returns_aead_envelope(self) -> None:
        key = b"\x01" * 32
        plaintext = b"hello mesh"
        aad = AAD_PURPOSE_STORAGE

        envelope = encrypt(key, plaintext, aad)

        assert isinstance(envelope, AeadEnvelope)
        assert envelope.version == 1
        assert envelope.algorithm == "aesgcm"
        assert isinstance(envelope.nonce, bytes)
        assert isinstance(envelope.ciphertext, bytes)
        assert len(envelope.nonce) == 12
        assert envelope.ciphertext != plaintext

    def test_decrypt_returns_original_plaintext(self) -> None:
        key = b"\x02" * 32
        plaintext = b"hello mesh"
        aad = AAD_PURPOSE_STORAGE

        envelope = encrypt(key, plaintext, aad)
        decrypted = decrypt(key, envelope, aad)

        assert decrypted == plaintext

    def test_aad_is_required_and_bytes(self) -> None:
        key = b"\x03" * 32
        plaintext = b"hello mesh"

        with pytest.raises(InvalidInputError):
            encrypt(key, plaintext, None)

    def test_same_plaintext_with_different_nonces_produces_different_envelopes(self) -> None:
        key = b"\x04" * 32
        plaintext = b"hello mesh"
        aad = AAD_PURPOSE_STORAGE

        first = encrypt(key, plaintext, aad)
        second = encrypt(key, plaintext, aad)

        assert first != second
        assert first.nonce != second.nonce or first.ciphertext != second.ciphertext

    @pytest.mark.parametrize(
        "bad_key",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_encrypt_rejects_non_bytes_key(self, bad_key) -> None:
        with pytest.raises(InvalidInputError):
            encrypt(bad_key, b"hello", AAD_PURPOSE_STORAGE)

    @pytest.mark.parametrize(
        "bad_plaintext",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_encrypt_rejects_non_bytes_plaintext(self, bad_plaintext) -> None:
        key = b"\x05" * 32

        with pytest.raises(InvalidInputError):
            encrypt(key, bad_plaintext, AAD_PURPOSE_STORAGE)

    @pytest.mark.parametrize(
        "bad_aad",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_encrypt_rejects_non_bytes_aad(self, bad_aad) -> None:
        key = b"\x06" * 32

        with pytest.raises(InvalidInputError):
            encrypt(key, b"hello", bad_aad)

    @pytest.mark.parametrize(
        "bad_key",
        [
            b"",
            b"short",
            b"x" * 15,
            b"x" * 17,
            b"x" * 31,
            b"x" * 33,
        ],
    )
    def test_encrypt_rejects_invalid_aes_key_length(self, bad_key: bytes) -> None:
        with pytest.raises(InvalidKeyError):
            encrypt(bad_key, b"hello", AAD_PURPOSE_STORAGE)

    def test_wrong_key_raises_authentication_error(self) -> None:
        key = b"\x07" * 32
        wrong_key = b"\x08" * 32
        plaintext = b"secret payload"
        aad = AAD_PURPOSE_STORAGE

        envelope = encrypt(key, plaintext, aad)

        with pytest.raises(AuthenticationError):
            decrypt(wrong_key, envelope, aad)

    def test_wrong_aad_raises_authentication_error(self) -> None:
        key = b"\x09" * 32
        plaintext = b"secret payload"
        aad = AAD_PURPOSE_STORAGE
        wrong_aad = b"mesh_crypto:aad:other:v1"

        envelope = encrypt(key, plaintext, aad)

        with pytest.raises(AuthenticationError):
            decrypt(key, envelope, wrong_aad)

    def test_tampered_ciphertext_raises_authentication_error(self) -> None:
        key = b"\x0A" * 32
        plaintext = b"secret payload"
        aad = AAD_PURPOSE_STORAGE

        envelope = encrypt(key, plaintext, aad)
        tampered = AeadEnvelope(
            version = envelope.version,
            algorithm = envelope.algorithm,
            nonce = envelope.nonce,
            ciphertext = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 0x01]),
        )

        with pytest.raises(AuthenticationError):
            decrypt(key, tampered, aad)

    def test_tampered_nonce_raises_authentication_error(self) -> None:
        key = b"\x0B" * 32
        plaintext = b"secret payload"
        aad = AAD_PURPOSE_STORAGE

        envelope = encrypt(key, plaintext, aad)
        tampered = AeadEnvelope(
            version = envelope.version,
            algorithm = envelope.algorithm,
            nonce = envelope.nonce[:-1] + bytes([envelope.nonce[-1] ^ 0x01]),
            ciphertext = envelope.ciphertext,
        )

        with pytest.raises(AuthenticationError):
            decrypt(key, tampered, aad)

    def test_decrypt_rejects_non_envelope_argument(self) -> None:
        key = b"\x0C" * 32

        with pytest.raises(InvalidInputError):
            decrypt(key, object(), AAD_PURPOSE_STORAGE)

    @pytest.mark.parametrize(
        "bad_key",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_decrypt_rejects_non_bytes_key(self, bad_key) -> None:
        key = b"\x0D" * 32
        envelope = encrypt(key, b"hello", AAD_PURPOSE_STORAGE)

        with pytest.raises(InvalidInputError):
            decrypt(bad_key, envelope, AAD_PURPOSE_STORAGE)

    @pytest.mark.parametrize(
        "bad_key",
        [
            b"",
            b"short",
            b"x" * 15,
            b"x" * 17,
            b"x" * 31,
            b"x" * 33,
        ],
    )
    def test_decrypt_rejects_invalid_aes_key_length(self, bad_key: bytes) -> None:
        key = b"\x0E" * 32
        envelope = encrypt(key, b"hello", AAD_PURPOSE_STORAGE)

        with pytest.raises(InvalidKeyError):
            decrypt(bad_key, envelope, AAD_PURPOSE_STORAGE)

    @pytest.mark.parametrize(
        "bad_aad",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_decrypt_rejects_non_bytes_aad(self, bad_aad) -> None:
        key = b"\x0F" * 32
        envelope = encrypt(key, b"hello", AAD_PURPOSE_STORAGE)

        with pytest.raises(InvalidInputError):
            decrypt(key, envelope, bad_aad)

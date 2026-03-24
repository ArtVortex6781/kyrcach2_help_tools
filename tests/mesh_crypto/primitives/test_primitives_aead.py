from __future__ import annotations

import pytest

from mesh_crypto.errors import IntegrityError, InvalidKeyError
from mesh_crypto.primitives.aead import decrypt, encrypt
from mesh_crypto.primitives.envelopes import AeadEnvelope


class TestAead:
    def test_encrypt_returns_aead_envelope(self) -> None:
        key = b"\x01" * 32
        plaintext = b"hello mesh"

        envelope = encrypt(key, plaintext)

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

        envelope = encrypt(key, plaintext)
        decrypted = decrypt(key, envelope)

        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad_none_works(self) -> None:
        key = b"\x03" * 32
        plaintext = b"payload without aad"

        envelope = encrypt(key, plaintext, aad = None)
        decrypted = decrypt(key, envelope, aad = None)

        assert decrypted == plaintext

    def test_encrypt_decrypt_with_aad_bytes_works(self) -> None:
        key = b"\x04" * 32
        plaintext = b"payload with aad"
        aad = b"context-data"

        envelope = encrypt(key, plaintext, aad = aad)
        decrypted = decrypt(key, envelope, aad = aad)

        assert decrypted == plaintext

    def test_wrong_key_raises_integrity_error(self) -> None:
        key = b"\x05" * 32
        wrong_key = b"\x06" * 32
        plaintext = b"secret payload"

        envelope = encrypt(key, plaintext)

        with pytest.raises(IntegrityError):
            decrypt(wrong_key, envelope)

    def test_tampered_ciphertext_raises_integrity_error(self) -> None:
        key = b"\x07" * 32
        plaintext = b"secret payload"

        envelope = encrypt(key, plaintext)
        tampered_envelope = AeadEnvelope(
            version = envelope.version,
            algorithm = envelope.algorithm,
            nonce = envelope.nonce,
            ciphertext = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 0x01]),
        )

        with pytest.raises(IntegrityError):
            decrypt(key, tampered_envelope)

    def test_tampered_nonce_raises_integrity_error(self) -> None:
        key = b"\x08" * 32
        plaintext = b"secret payload"

        envelope = encrypt(key, plaintext)
        tampered_envelope = AeadEnvelope(
            version = envelope.version,
            algorithm = envelope.algorithm,
            nonce = envelope.nonce[:-1] + bytes([envelope.nonce[-1] ^ 0x01]),
            ciphertext = envelope.ciphertext,
        )

        with pytest.raises(IntegrityError):
            decrypt(key, tampered_envelope)

    def test_wrong_aad_raises_integrity_error(self) -> None:
        key = b"\x09" * 32
        plaintext = b"secret payload"
        aad = b"aad-1"
        wrong_aad = b"aad-2"

        envelope = encrypt(key, plaintext, aad = aad)

        with pytest.raises(IntegrityError):
            decrypt(key, envelope, aad = wrong_aad)

    def test_decrypt_rejects_non_envelope_argument(self) -> None:
        key = b"\x0A" * 32

        with pytest.raises(InvalidKeyError):
            decrypt(key, object())

    @pytest.mark.parametrize(
        "bad_key",
        [
            b"",
            b"short",
            b"x" * 15,
            b"x" * 17,
            b"x" * 31,
            None,
            "not-bytes",
            object(),
        ],
    )
    def test_encrypt_rejects_invalid_key(self, bad_key) -> None:
        with pytest.raises(InvalidKeyError):
            encrypt(bad_key, b"hello")

    @pytest.mark.parametrize(
        "bad_key",
        [
            b"",
            b"short",
            b"x" * 15,
            b"x" * 17,
            b"x" * 31,
            None,
            "not-bytes",
            object(),
        ],
    )
    def test_decrypt_rejects_invalid_key(self, bad_key) -> None:
        valid_key = b"\x0B" * 32
        envelope = encrypt(valid_key, b"hello")

        with pytest.raises(InvalidKeyError):
            decrypt(bad_key, envelope)

    @pytest.mark.parametrize(
        "bad_plaintext",
        [
            None,
            "not-bytes",
            object(),
            123,
        ],
    )
    def test_encrypt_rejects_invalid_plaintext(self, bad_plaintext) -> None:
        key = b"\x0C" * 32

        with pytest.raises(InvalidKeyError):
            encrypt(key, bad_plaintext)

    @pytest.mark.parametrize(
        "bad_aad",
        [
            "not-bytes",
            object(),
            123,
        ],
    )
    def test_encrypt_rejects_invalid_aad(self, bad_aad) -> None:
        key = b"\x0D" * 32

        with pytest.raises(InvalidKeyError):
            encrypt(key, b"hello", aad = bad_aad)

    @pytest.mark.parametrize(
        "bad_aad",
        [
            "not-bytes",
            object(),
            123,
        ],
    )
    def test_decrypt_rejects_invalid_aad(self, bad_aad) -> None:
        key = b"\x0E" * 32
        envelope = encrypt(key, b"hello", aad = b"context")

        with pytest.raises(InvalidKeyError):
            decrypt(key, envelope, aad = bad_aad)

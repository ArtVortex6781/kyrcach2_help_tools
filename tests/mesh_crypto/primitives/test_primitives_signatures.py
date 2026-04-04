from __future__ import annotations

import pytest

from mesh_crypto.core import (
    SIGNING_CONTEXT_HANDSHAKE,
    SIGNING_CONTEXT_IDENTITY,
    SigningKeyPair,
)
from mesh_crypto.errors import (
    InvalidInputError,
    SignatureVerificationError,
    WrongKeyTypeError,
)
from mesh_crypto.primitives import sign, verify
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class TestSignatures:
    def test_sign_returns_bytes(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(SIGNING_CONTEXT_IDENTITY, data, pair.sk)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_verify_succeeds_for_valid_signature(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(SIGNING_CONTEXT_IDENTITY, data, pair.sk)

        verify(SIGNING_CONTEXT_IDENTITY, data, signature, pair.pk)

    def test_same_data_but_different_context_fails_verification(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(SIGNING_CONTEXT_IDENTITY, data, pair.sk)

        with pytest.raises(SignatureVerificationError):
            verify(SIGNING_CONTEXT_HANDSHAKE, data, signature, pair.pk)

    def test_same_context_but_modified_data_fails_verification(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"
        tampered_data = b"hello mesh!"

        signature = sign(SIGNING_CONTEXT_IDENTITY, data, pair.sk)

        with pytest.raises(SignatureVerificationError):
            verify(SIGNING_CONTEXT_IDENTITY, tampered_data, signature, pair.pk)

    def test_other_public_key_fails_verification(self) -> None:
        alice = SigningKeyPair.generate()
        bob = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(SIGNING_CONTEXT_IDENTITY, data, alice.sk)

        with pytest.raises(SignatureVerificationError):
            verify(SIGNING_CONTEXT_IDENTITY, data, signature, bob.pk)

    def test_invalid_signature_raises_signature_verification_error(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"
        signature = sign(SIGNING_CONTEXT_IDENTITY, data, pair.sk)
        bad_signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

        with pytest.raises(SignatureVerificationError):
            verify(SIGNING_CONTEXT_IDENTITY, data, bad_signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_context",
        [
            None,
            "",
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_sign_rejects_non_bytes_context(self, bad_context) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidInputError):
            sign(bad_context, b"hello mesh", pair.sk)

    def test_sign_rejects_empty_context(self) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidInputError):
            sign(b"", b"hello mesh", pair.sk)

    @pytest.mark.parametrize(
        "bad_context",
        [
            None,
            "",
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_verify_rejects_non_bytes_context(self, bad_context) -> None:
        pair = SigningKeyPair.generate()
        signature = sign(SIGNING_CONTEXT_IDENTITY, b"hello mesh", pair.sk)

        with pytest.raises(InvalidInputError):
            verify(bad_context, b"hello mesh", signature, pair.pk)

    def test_verify_rejects_empty_context(self) -> None:
        pair = SigningKeyPair.generate()
        signature = sign(SIGNING_CONTEXT_IDENTITY, b"hello mesh", pair.sk)

        with pytest.raises(InvalidInputError):
            verify(b"", b"hello mesh", signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_sign_rejects_non_bytes_data(self, bad_data) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidInputError):
            sign(SIGNING_CONTEXT_IDENTITY, bad_data, pair.sk)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_verify_rejects_non_bytes_data(self, bad_data) -> None:
        pair = SigningKeyPair.generate()
        signature = sign(SIGNING_CONTEXT_IDENTITY, b"hello mesh", pair.sk)

        with pytest.raises(InvalidInputError):
            verify(SIGNING_CONTEXT_IDENTITY, bad_data, signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_signature",
        [
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_verify_rejects_non_bytes_signature(self, bad_signature) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidInputError):
            verify(SIGNING_CONTEXT_IDENTITY, b"hello mesh", bad_signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_sk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            X25519PrivateKey.generate(),
            X25519PrivateKey.generate().public_key(),
            SigningKeyPair.generate().pk,
        ],
    )
    def test_sign_rejects_wrong_private_key_type(self, bad_sk) -> None:
        with pytest.raises(WrongKeyTypeError):
            sign(SIGNING_CONTEXT_IDENTITY, b"hello mesh", bad_sk)

    @pytest.mark.parametrize(
        "bad_pk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            X25519PrivateKey.generate(),
            X25519PrivateKey.generate().public_key(),
            SigningKeyPair.generate().sk,
        ],
    )
    def test_verify_rejects_wrong_public_key_type(self, bad_pk) -> None:
        pair = SigningKeyPair.generate()
        signature = sign(SIGNING_CONTEXT_IDENTITY, b"hello mesh", pair.sk)

        with pytest.raises(WrongKeyTypeError):
            verify(SIGNING_CONTEXT_IDENTITY, b"hello mesh", signature, bad_pk)

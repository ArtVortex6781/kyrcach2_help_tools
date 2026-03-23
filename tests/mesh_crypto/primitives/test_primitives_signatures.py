from __future__ import annotations

import pytest

from mesh_crypto.core import SigningKeyPair
from mesh_crypto.errors import IntegrityError, InvalidKeyError
from mesh_crypto.primitives.signatures import sign, verify


class TestSignatures:
    def test_sign_returns_bytes(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(data, pair.sk)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_verify_succeeds_for_valid_signature(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(data, pair.sk)

        verify(data, signature, pair.pk)

    def test_verify_fails_when_data_is_modified(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"
        tampered_data = b"hello mesh!"

        signature = sign(data, pair.sk)

        with pytest.raises(IntegrityError):
            verify(tampered_data, signature, pair.pk)

    def test_verify_fails_with_other_public_key(self) -> None:
        alice = SigningKeyPair.generate()
        bob = SigningKeyPair.generate()
        data = b"hello mesh"

        signature = sign(data, alice.sk)

        with pytest.raises(IntegrityError):
            verify(data, signature, bob.pk)

    def test_verify_fails_for_invalid_signature_bytes(self) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"
        signature = sign(data, pair.sk)

        bad_signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

        with pytest.raises(IntegrityError):
            verify(data, bad_signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_private_key",
        [
            None,
            object(),
            b"not-a-private-key",
            "not-a-private-key",
            123,
        ],
    )
    def test_sign_rejects_invalid_private_key(self, bad_private_key) -> None:
        with pytest.raises(InvalidKeyError):
            sign(b"hello mesh", bad_private_key)

    @pytest.mark.parametrize(
        "bad_public_key",
        [
            None,
            object(),
            b"not-a-public-key",
            "not-a-public-key",
            123,
        ],
    )
    def test_verify_rejects_invalid_public_key(self, bad_public_key) -> None:
        pair = SigningKeyPair.generate()
        data = b"hello mesh"
        signature = sign(data, pair.sk)

        with pytest.raises(InvalidKeyError):
            verify(data, signature, bad_public_key)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
        ],
    )
    def test_sign_rejects_invalid_data_argument(self, bad_data) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidKeyError):
            sign(bad_data, pair.sk)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
        ],
    )
    def test_verify_rejects_invalid_data_argument(self, bad_data) -> None:
        pair = SigningKeyPair.generate()
        signature = sign(b"hello mesh", pair.sk)

        with pytest.raises(InvalidKeyError):
            verify(bad_data, signature, pair.pk)

    @pytest.mark.parametrize(
        "bad_signature",
        [
            None,
            object(),
            "not-bytes",
            123,
        ],
    )
    def test_verify_rejects_invalid_signature_argument(self, bad_signature) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(InvalidKeyError):
            verify(b"hello mesh", bad_signature, pair.pk)

    def test_verify_empty_signature_raises_integrity_error(self) -> None:
        pair = SigningKeyPair.generate()

        with pytest.raises(IntegrityError):
            verify(b"hello mesh", b"", pair.pk)

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from mesh_crypto.core.keys import EncryptionKeyPair, SigningKeyPair
from mesh_crypto.errors import KeyMismatchError, WrongKeyTypeError


class TestSigningKeyPair:
    def test_generate_creates_valid_ed25519_pair(self) -> None:
        pair = SigningKeyPair.generate()

        assert isinstance(pair.sk, Ed25519PrivateKey)
        assert isinstance(pair.pk, Ed25519PublicKey)
        assert isinstance(pair, SigningKeyPair)

    def test_generate_public_key_matches_private_key(self) -> None:
        pair = SigningKeyPair.generate()

        expected_pk = pair.sk.public_key()

        assert pair.pk.public_bytes_raw() == expected_pk.public_bytes_raw()

    def test_manual_construction_with_matching_pair_succeeds(self) -> None:
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()

        pair = SigningKeyPair(sk = sk, pk = pk)

        assert isinstance(pair, SigningKeyPair)
        assert pair.sk is sk
        assert pair.pk is pk

    def test_manual_construction_with_mismatched_public_key_raises_key_mismatch_error(self) -> None:
        left = Ed25519PrivateKey.generate()
        right = Ed25519PrivateKey.generate()

        with pytest.raises(KeyMismatchError):
            SigningKeyPair(sk = left, pk = right.public_key())

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
            Ed25519PrivateKey.generate().public_key(),
        ],
    )
    def test_wrong_sk_type_raises_wrong_key_type_error(self, bad_sk) -> None:
        pk = Ed25519PrivateKey.generate().public_key()

        with pytest.raises(WrongKeyTypeError):
            SigningKeyPair(sk = bad_sk, pk = pk)

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
            Ed25519PrivateKey.generate(),
        ],
    )
    def test_wrong_pk_type_raises_wrong_key_type_error(self, bad_pk) -> None:
        sk = Ed25519PrivateKey.generate()

        with pytest.raises(WrongKeyTypeError):
            SigningKeyPair(sk = sk, pk = bad_pk)


class TestEncryptionKeyPair:
    def test_generate_creates_valid_x25519_pair(self) -> None:
        pair = EncryptionKeyPair.generate()

        assert isinstance(pair.sk, X25519PrivateKey)
        assert isinstance(pair.pk, X25519PublicKey)
        assert isinstance(pair, EncryptionKeyPair)

    def test_generate_public_key_matches_private_key(self) -> None:
        pair = EncryptionKeyPair.generate()

        expected_pk = pair.sk.public_key()

        assert pair.pk.public_bytes_raw() == expected_pk.public_bytes_raw()

    def test_manual_construction_with_matching_pair_succeeds(self) -> None:
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()

        pair = EncryptionKeyPair(sk = sk, pk = pk)

        assert isinstance(pair, EncryptionKeyPair)
        assert pair.sk is sk
        assert pair.pk is pk

    def test_manual_construction_with_mismatched_public_key_raises_key_mismatch_error(self) -> None:
        left = X25519PrivateKey.generate()
        right = X25519PrivateKey.generate()

        with pytest.raises(KeyMismatchError):
            EncryptionKeyPair(sk = left, pk = right.public_key())

    @pytest.mark.parametrize(
        "bad_sk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            X25519PrivateKey.generate().public_key(),
        ],
    )
    def test_wrong_sk_type_raises_wrong_key_type_error(self, bad_sk) -> None:
        pk = X25519PrivateKey.generate().public_key()

        with pytest.raises(WrongKeyTypeError):
            EncryptionKeyPair(sk = bad_sk, pk = pk)

    @pytest.mark.parametrize(
        "bad_pk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            X25519PrivateKey.generate(),
        ],
    )
    def test_wrong_pk_type_raises_wrong_key_type_error(self, bad_pk) -> None:
        sk = X25519PrivateKey.generate()

        with pytest.raises(WrongKeyTypeError):
            EncryptionKeyPair(sk = sk, pk = bad_pk)

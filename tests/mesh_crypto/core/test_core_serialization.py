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

from mesh_crypto.core import (
    EncryptionKeyPair,
    EncryptionKeySerializer,
    SigningKeyPair,
    SigningKeySerializer,
)
from mesh_crypto.errors import InvalidKeyError


class TestSigningKeySerializer:
    def test_serialize_private_deserialize_roundtrip(self) -> None:
        pair = SigningKeyPair.generate()

        private_bytes = SigningKeySerializer.serialize_private_key(pair.sk)
        restored = SigningKeySerializer.deserialize_private_key(private_bytes)

        assert isinstance(restored, Ed25519PrivateKey)
        assert SigningKeySerializer.serialize_private_key(restored) == private_bytes

    def test_serialize_public_deserialize_roundtrip(self) -> None:
        pair = SigningKeyPair.generate()

        public_bytes = SigningKeySerializer.serialize_public_key(pair.pk)
        restored = SigningKeySerializer.deserialize_public_key(public_bytes)

        assert isinstance(restored, Ed25519PublicKey)
        assert SigningKeySerializer.serialize_public_key(restored) == public_bytes

    def test_restore_pair_from_private_bytes_restores_matching_public_key(self) -> None:
        pair = SigningKeyPair.generate()

        private_bytes = SigningKeySerializer.serialize_private_key(pair.sk)
        restored = SigningKeySerializer.restore_pair_from_private_bytes(private_bytes)

        assert isinstance(restored, SigningKeyPair)
        assert SigningKeySerializer.serialize_private_key(restored.sk) == private_bytes
        assert SigningKeySerializer.serialize_public_key(restored.pk) == (
            SigningKeySerializer.serialize_public_key(pair.pk)
        )

    def test_serialize_pair_private_key_matches_private_key_serialization(self) -> None:
        pair = SigningKeyPair.generate()

        assert SigningKeySerializer.serialize_pair_private_key(pair) == (
            SigningKeySerializer.serialize_private_key(pair.sk)
        )

    def test_serialize_pair_public_key_matches_public_key_serialization(self) -> None:
        pair = SigningKeyPair.generate()

        assert SigningKeySerializer.serialize_pair_public_key(pair) == (
            SigningKeySerializer.serialize_public_key(pair.pk)
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_deserialize_private_key_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            SigningKeySerializer.deserialize_private_key(data)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_deserialize_public_key_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            SigningKeySerializer.deserialize_public_key(data)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_restore_pair_from_private_bytes_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            SigningKeySerializer.restore_pair_from_private_bytes(data)


class TestEncryptionKeySerializer:
    def test_serialize_private_deserialize_roundtrip(self) -> None:
        pair = EncryptionKeyPair.generate()

        private_bytes = EncryptionKeySerializer.serialize_private_key(pair.sk)
        restored = EncryptionKeySerializer.deserialize_private_key(private_bytes)

        assert isinstance(restored, X25519PrivateKey)
        assert EncryptionKeySerializer.serialize_private_key(restored) == private_bytes

    def test_serialize_public_deserialize_roundtrip(self) -> None:
        pair = EncryptionKeyPair.generate()

        public_bytes = EncryptionKeySerializer.serialize_public_key(pair.pk)
        restored = EncryptionKeySerializer.deserialize_public_key(public_bytes)

        assert isinstance(restored, X25519PublicKey)
        assert EncryptionKeySerializer.serialize_public_key(restored) == public_bytes

    def test_restore_pair_from_private_bytes_restores_matching_public_key(self) -> None:
        pair = EncryptionKeyPair.generate()

        private_bytes = EncryptionKeySerializer.serialize_private_key(pair.sk)
        restored = EncryptionKeySerializer.restore_pair_from_private_bytes(private_bytes)

        assert isinstance(restored, EncryptionKeyPair)
        assert EncryptionKeySerializer.serialize_private_key(restored.sk) == private_bytes
        assert EncryptionKeySerializer.serialize_public_key(restored.pk) == (
            EncryptionKeySerializer.serialize_public_key(pair.pk)
        )

    def test_serialize_pair_private_key_matches_private_key_serialization(self) -> None:
        pair = EncryptionKeyPair.generate()

        assert EncryptionKeySerializer.serialize_pair_private_key(pair) == (
            EncryptionKeySerializer.serialize_private_key(pair.sk)
        )

    def test_serialize_pair_public_key_matches_public_key_serialization(self) -> None:
        pair = EncryptionKeyPair.generate()

        assert EncryptionKeySerializer.serialize_pair_public_key(pair) == (
            EncryptionKeySerializer.serialize_public_key(pair.pk)
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_deserialize_private_key_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            EncryptionKeySerializer.deserialize_private_key(data)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_deserialize_public_key_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            EncryptionKeySerializer.deserialize_public_key(data)

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
            "not-bytes",
            None,
            object(),
        ],
    )
    def test_restore_pair_from_private_bytes_rejects_invalid_data(self, data) -> None:
        with pytest.raises(InvalidKeyError):
            EncryptionKeySerializer.restore_pair_from_private_bytes(data)

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
from mesh_crypto.errors import InvalidInputError, InvalidKeyError, WrongKeyTypeError


class TestSigningKeySerializer:
    def test_export_private_key_raw_returns_32_bytes(self) -> None:
        pair = SigningKeyPair.generate()

        raw = SigningKeySerializer.export_private_key_raw(pair.sk)

        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_export_public_key_raw_returns_32_bytes(self) -> None:
        pair = SigningKeyPair.generate()

        raw = SigningKeySerializer.export_public_key_raw(pair.pk)

        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_import_private_key_raw_restores_private_key(self) -> None:
        pair = SigningKeyPair.generate()
        raw = SigningKeySerializer.export_private_key_raw(pair.sk)

        restored = SigningKeySerializer.import_private_key_raw(raw)

        assert isinstance(restored, Ed25519PrivateKey)
        assert SigningKeySerializer.export_private_key_raw(restored) == raw

    def test_import_public_key_raw_restores_public_key(self) -> None:
        pair = SigningKeyPair.generate()
        raw = SigningKeySerializer.export_public_key_raw(pair.pk)

        restored = SigningKeySerializer.import_public_key_raw(raw)

        assert isinstance(restored, Ed25519PublicKey)
        assert SigningKeySerializer.export_public_key_raw(restored) == raw

    def test_private_export_import_roundtrip_preserves_derived_public_key(self) -> None:
        pair = SigningKeyPair.generate()

        private_raw = SigningKeySerializer.export_private_key_raw(pair.sk)
        restored_sk = SigningKeySerializer.import_private_key_raw(private_raw)
        restored_pk = restored_sk.public_key()

        assert SigningKeySerializer.export_public_key_raw(restored_pk) == (
            SigningKeySerializer.export_public_key_raw(pair.pk)
        )

    def test_export_pair_private_key_raw_works(self) -> None:
        pair = SigningKeyPair.generate()

        raw = SigningKeySerializer.export_pair_private_key_raw(pair)

        assert raw == SigningKeySerializer.export_private_key_raw(pair.sk)
        assert len(raw) == 32

    def test_export_pair_public_key_raw_works(self) -> None:
        pair = SigningKeyPair.generate()

        raw = SigningKeySerializer.export_pair_public_key_raw(pair)

        assert raw == SigningKeySerializer.export_public_key_raw(pair.pk)
        assert len(raw) == 32

    def test_restore_pair_from_private_bytes_restores_signing_key_pair(self) -> None:
        pair = SigningKeyPair.generate()
        private_raw = SigningKeySerializer.export_private_key_raw(pair.sk)

        restored = SigningKeySerializer.restore_pair_from_private_bytes(private_raw)

        assert isinstance(restored, SigningKeyPair)
        assert SigningKeySerializer.export_private_key_raw(restored.sk) == private_raw
        assert SigningKeySerializer.export_public_key_raw(restored.pk) == (
            SigningKeySerializer.export_public_key_raw(pair.pk)
        )

    @pytest.mark.parametrize(
        "bad_key",
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
    def test_export_private_key_raw_rejects_wrong_object_type(self, bad_key) -> None:
        with pytest.raises(WrongKeyTypeError):
            SigningKeySerializer.export_private_key_raw(bad_key)

    @pytest.mark.parametrize(
        "bad_key",
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
    def test_export_public_key_raw_rejects_wrong_object_type(self, bad_key) -> None:
        with pytest.raises(WrongKeyTypeError):
            SigningKeySerializer.export_public_key_raw(bad_key)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
            bytearray(b"x" * 32),
        ],
    )
    def test_import_private_key_raw_rejects_non_bytes_input(self, bad_data) -> None:
        with pytest.raises(InvalidInputError):
            SigningKeySerializer.import_private_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
            bytearray(b"x" * 32),
        ],
    )
    def test_import_public_key_raw_rejects_non_bytes_input(self, bad_data) -> None:
        with pytest.raises(InvalidInputError):
            SigningKeySerializer.import_public_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
        ],
    )
    def test_import_private_key_raw_rejects_malformed_bytes(self, bad_data: bytes) -> None:
        with pytest.raises(InvalidKeyError):
            SigningKeySerializer.import_private_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
        ],
    )
    def test_import_public_key_raw_rejects_malformed_bytes(self, bad_data: bytes) -> None:
        with pytest.raises(InvalidKeyError):
            SigningKeySerializer.import_public_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_pair",
        [
            None,
            object(),
            "not-a-pair",
            b"not-a-pair",
            123,
            EncryptionKeyPair.generate(),
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
        ],
    )
    def test_export_pair_private_key_raw_rejects_wrong_object_type(self, bad_pair) -> None:
        with pytest.raises(WrongKeyTypeError):
            SigningKeySerializer.export_pair_private_key_raw(bad_pair)

    @pytest.mark.parametrize(
        "bad_pair",
        [
            None,
            object(),
            "not-a-pair",
            b"not-a-pair",
            123,
            EncryptionKeyPair.generate(),
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
        ],
    )
    def test_export_pair_public_key_raw_rejects_wrong_object_type(self, bad_pair) -> None:
        with pytest.raises(WrongKeyTypeError):
            SigningKeySerializer.export_pair_public_key_raw(bad_pair)


class TestEncryptionKeySerializer:
    def test_export_private_key_raw_returns_32_bytes(self) -> None:
        pair = EncryptionKeyPair.generate()

        raw = EncryptionKeySerializer.export_private_key_raw(pair.sk)

        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_export_public_key_raw_returns_32_bytes(self) -> None:
        pair = EncryptionKeyPair.generate()

        raw = EncryptionKeySerializer.export_public_key_raw(pair.pk)

        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_import_private_key_raw_restores_private_key(self) -> None:
        pair = EncryptionKeyPair.generate()
        raw = EncryptionKeySerializer.export_private_key_raw(pair.sk)

        restored = EncryptionKeySerializer.import_private_key_raw(raw)

        assert isinstance(restored, X25519PrivateKey)
        assert EncryptionKeySerializer.export_private_key_raw(restored) == raw

    def test_import_public_key_raw_restores_public_key(self) -> None:
        pair = EncryptionKeyPair.generate()
        raw = EncryptionKeySerializer.export_public_key_raw(pair.pk)

        restored = EncryptionKeySerializer.import_public_key_raw(raw)

        assert isinstance(restored, X25519PublicKey)
        assert EncryptionKeySerializer.export_public_key_raw(restored) == raw

    def test_private_export_import_roundtrip_preserves_derived_public_key(self) -> None:
        pair = EncryptionKeyPair.generate()

        private_raw = EncryptionKeySerializer.export_private_key_raw(pair.sk)
        restored_sk = EncryptionKeySerializer.import_private_key_raw(private_raw)
        restored_pk = restored_sk.public_key()

        assert EncryptionKeySerializer.export_public_key_raw(restored_pk) == (
            EncryptionKeySerializer.export_public_key_raw(pair.pk)
        )

    def test_export_pair_private_key_raw_works(self) -> None:
        pair = EncryptionKeyPair.generate()

        raw = EncryptionKeySerializer.export_pair_private_key_raw(pair)

        assert raw == EncryptionKeySerializer.export_private_key_raw(pair.sk)
        assert len(raw) == 32

    def test_export_pair_public_key_raw_works(self) -> None:
        pair = EncryptionKeyPair.generate()

        raw = EncryptionKeySerializer.export_pair_public_key_raw(pair)

        assert raw == EncryptionKeySerializer.export_public_key_raw(pair.pk)
        assert len(raw) == 32

    def test_restore_pair_from_private_bytes_restores_encryption_key_pair(self) -> None:
        pair = EncryptionKeyPair.generate()
        private_raw = EncryptionKeySerializer.export_private_key_raw(pair.sk)

        restored = EncryptionKeySerializer.restore_pair_from_private_bytes(private_raw)

        assert isinstance(restored, EncryptionKeyPair)
        assert EncryptionKeySerializer.export_private_key_raw(restored.sk) == private_raw
        assert EncryptionKeySerializer.export_public_key_raw(restored.pk) == (
            EncryptionKeySerializer.export_public_key_raw(pair.pk)
        )

    @pytest.mark.parametrize(
        "bad_key",
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
    def test_export_private_key_raw_rejects_wrong_object_type(self, bad_key) -> None:
        with pytest.raises(WrongKeyTypeError):
            EncryptionKeySerializer.export_private_key_raw(bad_key)

    @pytest.mark.parametrize(
        "bad_key",
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
    def test_export_public_key_raw_rejects_wrong_object_type(self, bad_key) -> None:
        with pytest.raises(WrongKeyTypeError):
            EncryptionKeySerializer.export_public_key_raw(bad_key)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
            bytearray(b"x" * 32),
        ],
    )
    def test_import_private_key_raw_rejects_non_bytes_input(self, bad_data) -> None:
        with pytest.raises(InvalidInputError):
            EncryptionKeySerializer.import_private_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            object(),
            "not-bytes",
            123,
            bytearray(b"x" * 32),
        ],
    )
    def test_import_public_key_raw_rejects_non_bytes_input(self, bad_data) -> None:
        with pytest.raises(InvalidInputError):
            EncryptionKeySerializer.import_public_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
        ],
    )
    def test_import_private_key_raw_rejects_malformed_bytes(self, bad_data: bytes) -> None:
        with pytest.raises(InvalidKeyError):
            EncryptionKeySerializer.import_private_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            b"",
            b"short",
            b"x" * 31,
            b"x" * 33,
            b"x" * 64,
        ],
    )
    def test_import_public_key_raw_rejects_malformed_bytes(self, bad_data: bytes) -> None:
        with pytest.raises(InvalidKeyError):
            EncryptionKeySerializer.import_public_key_raw(bad_data)

    @pytest.mark.parametrize(
        "bad_pair",
        [
            None,
            object(),
            "not-a-pair",
            b"not-a-pair",
            123,
            SigningKeyPair.generate(),
            X25519PrivateKey.generate(),
            X25519PrivateKey.generate().public_key(),
        ],
    )
    def test_export_pair_private_key_raw_rejects_wrong_object_type(self, bad_pair) -> None:
        with pytest.raises(WrongKeyTypeError):
            EncryptionKeySerializer.export_pair_private_key_raw(bad_pair)

    @pytest.mark.parametrize(
        "bad_pair",
        [
            None,
            object(),
            "not-a-pair",
            b"not-a-pair",
            123,
            SigningKeyPair.generate(),
            X25519PrivateKey.generate(),
            X25519PrivateKey.generate().public_key(),
        ],
    )
    def test_export_pair_public_key_raw_rejects_wrong_object_type(self, bad_pair) -> None:
        with pytest.raises(WrongKeyTypeError):
            EncryptionKeySerializer.export_pair_public_key_raw(bad_pair)

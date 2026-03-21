from __future__ import annotations

import pytest

from mesh_crypto.core import KeyIdHelpers
from mesh_crypto.errors import InvalidKeyError
from mesh_crypto.core import KeyId


class TestNewKeyId:
    def test_new_key_id_returns_uuid_instance(self) -> None:
        key_id = KeyIdHelpers.new_key_id()

        assert isinstance(key_id, KeyId)
        assert key_id.version == 4

    def test_new_key_id_returns_unique_values(self) -> None:
        first = KeyIdHelpers.new_key_id()
        second = KeyIdHelpers.new_key_id()

        assert first != second


class TestKeyIdBytes:
    def test_key_id_to_bytes_returns_16_bytes(self) -> None:
        key_id = KeyIdHelpers.new_key_id()

        raw = KeyIdHelpers.key_id_to_bytes(key_id)

        assert isinstance(raw, bytes)
        assert len(raw) == 16

    def test_key_id_bytes_roundtrip(self) -> None:
        original = KeyIdHelpers.new_key_id()

        raw = KeyIdHelpers.key_id_to_bytes(original)
        restored = KeyIdHelpers.key_id_from_bytes(raw)

        assert restored == original
        assert KeyIdHelpers.key_id_to_bytes(restored) == raw


class TestNormalizeKeyId:
    def test_normalize_key_id_accepts_uuid(self) -> None:
        original = KeyIdHelpers.new_key_id()

        normalized = KeyIdHelpers.normalize_key_id(original)

        assert normalized == original

    def test_normalize_key_id_accepts_uuid_string(self) -> None:
        original = KeyIdHelpers.new_key_id()

        normalized = KeyIdHelpers.normalize_key_id(str(original))

        assert normalized == original

    def test_normalize_key_id_accepts_uuid_bytes(self) -> None:
        original = KeyIdHelpers.new_key_id()

        normalized = KeyIdHelpers.normalize_key_id(original.bytes)

        assert normalized == original

    def test_normalize_key_id_accepts_bytearray(self) -> None:
        original = KeyIdHelpers.new_key_id()

        normalized = KeyIdHelpers.normalize_key_id(bytearray(original.bytes))

        assert normalized == original


@pytest.mark.parametrize(
    "value",
    [
        "not-a-uuid",
        b"",
        b"short",
        b"x" * 15,
        b"x" * 17,
        123,
        12.5,
        object(),
        None,
    ],
)
def test_normalize_key_id_rejects_invalid_values(value) -> None:
    with pytest.raises(InvalidKeyError):
        KeyIdHelpers.normalize_key_id(value)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"short",
        b"x" * 15,
        b"x" * 17,
        "not-bytes",
        None,
        object(),
    ],
)
def test_key_id_from_bytes_rejects_invalid_values(value) -> None:
    with pytest.raises(InvalidKeyError):
        KeyIdHelpers.key_id_from_bytes(value)

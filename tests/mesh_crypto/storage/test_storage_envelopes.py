from __future__ import annotations

import json

import pytest

from mesh_crypto.core import KeyId, KeyIdHelpers
from mesh_crypto.errors import (
    InvalidInputError,
    MalformedDataError,
    UnsupportedFormatError,
)
from mesh_crypto.primitives import AeadEnvelope
from mesh_crypto.storage import StorageFieldEnvelope


def make_aead_envelope() -> AeadEnvelope:
    return AeadEnvelope(
        version = 1,
        algorithm = "aesgcm",
        nonce = b"0123456789ab",
        ciphertext = b"ciphertext-with-authentication-tag",
    )


def make_aead_dict() -> dict[str, object]:
    return make_aead_envelope().to_dict()


def make_storage_dict(
        *,
        key_id: str | None = None,
        aead: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "version": 1,
        "type": "storage_field",
        "algorithm": "mesh-storage-v1",
        "key_id": key_id if key_id is not None else str(KeyIdHelpers.new_key_id()),
        "aead": aead if aead is not None else make_aead_dict(),
    }


class TestStorageFieldEnvelopeHappyPath:
    def test_create_valid_envelope_from_dict(self) -> None:
        data = make_storage_dict()

        envelope = StorageFieldEnvelope.from_dict(data)

        assert envelope.version == 1
        assert envelope.type == "storage_field"
        assert envelope.algorithm == "mesh-storage-v1"
        assert str(envelope.key_id) == data["key_id"]
        assert isinstance(envelope.aead, AeadEnvelope)
        assert envelope.aead.to_dict() == data["aead"]

    def test_direct_constructor_accepts_key_id_object(self) -> None:
        key_id = KeyIdHelpers.new_key_id()
        aead = make_aead_envelope()

        envelope = StorageFieldEnvelope(
            version = 1,
            type = "storage_field",
            algorithm = "mesh-storage-v1",
            key_id = key_id,
            aead = aead,
        )

        assert envelope.key_id == key_id
        assert envelope.aead == aead

    def test_direct_constructor_normalizes_key_id_from_string(self) -> None:
        key_id = KeyIdHelpers.new_key_id()
        aead = make_aead_envelope()

        envelope = StorageFieldEnvelope(
            version = 1,
            type = "storage_field",
            algorithm = "mesh-storage-v1",
            key_id = str(key_id),
            aead = aead,
        )

        assert envelope.key_id == key_id

    def test_direct_constructor_normalizes_key_id_from_bytes(self) -> None:
        key_id = KeyIdHelpers.new_key_id()
        aead = make_aead_envelope()

        envelope = StorageFieldEnvelope(
            version = 1,
            type = "storage_field",
            algorithm = "mesh-storage-v1",
            key_id = KeyIdHelpers.key_id_to_bytes(key_id),
            aead = aead,
        )

        assert envelope.key_id == key_id

    def test_to_dict_from_dict_roundtrip_preserves_fields(self) -> None:
        original = StorageFieldEnvelope.from_dict(make_storage_dict())

        restored = StorageFieldEnvelope.from_dict(original.to_dict())

        assert restored == original
        assert restored.to_dict() == original.to_dict()
        assert restored.aead.to_dict() == original.aead.to_dict()

    def test_to_bytes_from_bytes_roundtrip_preserves_fields(self) -> None:
        original = StorageFieldEnvelope.from_dict(make_storage_dict())

        serialized = original.to_bytes()
        restored = StorageFieldEnvelope.from_bytes(serialized)

        assert isinstance(serialized, bytes)
        assert restored == original
        assert restored.to_dict() == original.to_dict()
        assert restored.aead.to_dict() == original.aead.to_dict()

    def test_to_bytes_returns_json_object_bytes(self) -> None:
        envelope = StorageFieldEnvelope.from_dict(make_storage_dict())

        serialized = envelope.to_bytes()
        decoded = json.loads(serialized.decode("utf-8"))

        assert isinstance(serialized, bytes)
        assert decoded == envelope.to_dict()


class TestStorageFieldEnvelopeRequiredFields:
    @pytest.mark.parametrize(
        "missing_field",
        ["version", "type", "algorithm", "key_id", "aead"],
    )
    def test_from_dict_missing_required_field_raises_malformed_data_error(
            self,
            missing_field: str,
    ) -> None:
        data = make_storage_dict()
        del data[missing_field]

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)

    def test_from_dict_extra_field_raises_malformed_data_error(self) -> None:
        data = make_storage_dict()
        data["extra"] = "not-allowed"

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)


class TestStorageFieldEnvelopeUnsupportedValues:
    @pytest.mark.parametrize("version", [0, 2, 999])
    def test_unsupported_version_raises_unsupported_format_error(self, version: int) -> None:
        data = make_storage_dict()
        data["version"] = version

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_dict(data)

    @pytest.mark.parametrize(
        "envelope_type",
        ["", "field", "storage", "storage-field", "storage_field_v2"],
    )
    def test_unsupported_type_raises_unsupported_format_error(self, envelope_type: str) -> None:
        data = make_storage_dict()
        data["type"] = envelope_type

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_dict(data)

    @pytest.mark.parametrize(
        "algorithm",
        ["", "aesgcm", "mesh-storage-v2", "mesh-storage", "unknown"],
    )
    def test_unsupported_algorithm_raises_unsupported_format_error(self, algorithm: str) -> None:
        data = make_storage_dict()
        data["algorithm"] = algorithm

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_dict(data)


class TestStorageFieldEnvelopeInvalidFieldTypes:
    @pytest.mark.parametrize(
        ("field_name", "bad_value"),
        [
            ("version", "1"),
            ("version", None),
            ("type", 123),
            ("type", None),
            ("algorithm", 123),
            ("algorithm", None),
            ("key_id", 123),
            ("key_id", None),
            ("aead", "not-dict"),
            ("aead", None),
        ],
    )
    def test_invalid_field_types_raise_malformed_data_error(
            self,
            field_name: str,
            bad_value: object,
    ) -> None:
        data = make_storage_dict()
        data[field_name] = bad_value

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)

    @pytest.mark.parametrize(
        "bad_key_id",
        [
            "",
            "not-a-uuid",
            "00000000-0000-0000-0000",
            "z" * 36,
        ],
    )
    def test_invalid_key_id_raises_malformed_data_error(self, bad_key_id: str) -> None:
        data = make_storage_dict(key_id = bad_key_id)

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)

    @pytest.mark.parametrize(
        "bad_key_id",
        [
            b"",
            b"short",
            b"x" * 15,
            b"x" * 17,
        ],
    )
    def test_direct_constructor_invalid_key_id_bytes_raise_malformed_data_error(
            self,
            bad_key_id: bytes,
    ) -> None:
        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope(
                version = 1,
                type = "storage_field",
                algorithm = "mesh-storage-v1",
                key_id = bad_key_id,
                aead = make_aead_envelope(),
            )

    def test_direct_constructor_invalid_aead_type_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope(
                version = 1,
                type = "storage_field",
                algorithm = "mesh-storage-v1",
                key_id = KeyIdHelpers.new_key_id(),
                aead = object(),
            )


class TestStorageFieldEnvelopeNestedAeadValidation:
    @pytest.mark.parametrize(
        "aead",
        [
            {},
            {"version": 1, "algorithm": "aesgcm"},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi"},
        ],
    )
    def test_malformed_nested_aead_envelope_raises_malformed_data_error(
            self,
            aead: dict[str, object],
    ) -> None:
        data = make_storage_dict(aead = aead)

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)

    def test_nested_aead_invalid_base64_raises_malformed_data_error(self) -> None:
        aead = make_aead_dict()
        aead["nonce"] = "not-valid-base64!!!"
        data = make_storage_dict(aead = aead)

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_dict(data)

    def test_nested_aead_unsupported_version_raises_unsupported_format_error(self) -> None:
        aead = make_aead_dict()
        aead["version"] = 999
        data = make_storage_dict(aead = aead)

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_dict(data)

    def test_nested_aead_unsupported_algorithm_raises_unsupported_format_error(self) -> None:
        aead = make_aead_dict()
        aead["algorithm"] = "unsupported"
        data = make_storage_dict(aead = aead)

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_dict(data)


class TestStorageFieldEnvelopeSerializedInput:
    @pytest.mark.parametrize("bad_input", [None, "{}", 123, bytearray(b"{}")])
    def test_from_bytes_non_bytes_input_raises_invalid_input_error(self, bad_input: object) -> None:
        with pytest.raises(InvalidInputError):
            StorageFieldEnvelope.from_bytes(bad_input)

    def test_from_bytes_invalid_utf8_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_bytes(b"\xff\xfe\xfd")

    def test_from_bytes_invalid_json_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_bytes(b"{not-json")

    @pytest.mark.parametrize(
        "serialized",
        [
            b"null",
            b"[]",
            b'"string"',
            b"123",
            b"true",
        ],
    )
    def test_from_bytes_json_not_object_raises_malformed_data_error(
            self,
            serialized: bytes,
    ) -> None:
        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_bytes(serialized)

    def test_from_bytes_missing_required_field_raises_malformed_data_error(self) -> None:
        data = make_storage_dict()
        del data["key_id"]

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_bytes(json.dumps(data).encode("utf-8"))

    def test_from_bytes_extra_field_raises_malformed_data_error(self) -> None:
        data = make_storage_dict()
        data["extra"] = "not-allowed"

        with pytest.raises(MalformedDataError):
            StorageFieldEnvelope.from_bytes(json.dumps(data).encode("utf-8"))

    def test_from_bytes_unsupported_version_raises_unsupported_format_error(self) -> None:
        data = make_storage_dict()
        data["version"] = 999

        with pytest.raises(UnsupportedFormatError):
            StorageFieldEnvelope.from_bytes(json.dumps(data).encode("utf-8"))

from __future__ import annotations

import json

import pytest

from mesh_crypto.core import KeyIdHelpers
from mesh_crypto.errors import (
    InvalidInputError,
    MalformedDataError,
    UnsupportedFormatError,
)
from mesh_crypto.primitives import AeadEnvelope
from mesh_crypto.sessions import DirectMessageEnvelope


def make_aead_envelope() -> AeadEnvelope:
    return AeadEnvelope(
        version = 1,
        algorithm = "aesgcm",
        nonce = b"0123456789ab",
        ciphertext = b"ciphertext-with-authentication-tag",
    )


def make_direct_message_envelope(
        *,
        version: int = 1,
        envelope_type: str = "direct_message",
        session_id = None,
        counter: int = 0,
        previous_chain_length: int = 0,
        algorithm: str = "mesh-direct-v1",
        ratchet_pub: bytes = b"r" * 32,
        aead: AeadEnvelope | None = None,
) -> DirectMessageEnvelope:
    if session_id is None:
        session_id = KeyIdHelpers.new_key_id()
    if aead is None:
        aead = make_aead_envelope()

    return DirectMessageEnvelope(
        version = version,
        type = envelope_type,
        session_id = session_id,
        counter = counter,
        previous_chain_length = previous_chain_length,
        algorithm = algorithm,
        ratchet_pub = ratchet_pub,
        aead = aead,
    )


def make_direct_message_dict() -> dict[str, object]:
    return make_direct_message_envelope().to_dict()


class TestDirectMessageEnvelopeHappyPath:
    def test_valid_envelope_to_dict_from_dict_roundtrip(self) -> None:
        original = make_direct_message_envelope(
            session_id = KeyIdHelpers.new_key_id(),
            counter = 7,
            previous_chain_length = 3,
            ratchet_pub = b"x" * 32,
        )

        restored = DirectMessageEnvelope.from_dict(original.to_dict())

        assert restored == original
        assert restored.to_dict() == original.to_dict()
        assert restored.aead.to_dict() == original.aead.to_dict()

    def test_valid_envelope_to_bytes_from_bytes_roundtrip(self) -> None:
        original = make_direct_message_envelope(
            session_id = KeyIdHelpers.new_key_id(),
            counter = 9,
            previous_chain_length = 4,
            ratchet_pub = b"y" * 32,
        )

        serialized = original.to_bytes()
        restored = DirectMessageEnvelope.from_bytes(serialized)

        assert isinstance(serialized, bytes)
        assert restored == original
        assert restored.to_dict() == original.to_dict()

    def test_from_dict_normalizes_session_id_from_string(self) -> None:
        session_id = KeyIdHelpers.new_key_id()
        data = make_direct_message_dict()
        data["session_id"] = str(session_id)

        envelope = DirectMessageEnvelope.from_dict(data)

        assert envelope.session_id == session_id

    def test_direct_constructor_normalizes_session_id_from_bytes(self) -> None:
        session_id = KeyIdHelpers.new_key_id()

        envelope = make_direct_message_envelope(
            session_id = KeyIdHelpers.key_id_to_bytes(session_id),
        )

        assert envelope.session_id == session_id

    def test_to_bytes_returns_json_object_bytes(self) -> None:
        envelope = make_direct_message_envelope()

        serialized = envelope.to_bytes()
        decoded = json.loads(serialized.decode("utf-8"))

        assert isinstance(serialized, bytes)
        assert decoded == envelope.to_dict()


class TestDirectMessageEnvelopeSerializedInput:
    @pytest.mark.parametrize("bad_input", [None, "{}", 123, bytearray(b"{}")])
    def test_from_bytes_non_bytes_input_raises_invalid_input_error(self, bad_input) -> None:
        with pytest.raises(InvalidInputError):
            DirectMessageEnvelope.from_bytes(bad_input)

    def test_from_bytes_invalid_utf8_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_bytes(b"\xff\xfe\xfd")

    def test_from_bytes_invalid_json_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_bytes(b"{not-json")

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
    def test_from_bytes_json_not_object_raises_malformed_data_error(self, serialized: bytes) -> None:
        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_bytes(serialized)


class TestDirectMessageEnvelopeRequiredKeys:
    @pytest.mark.parametrize(
        "missing_key",
        [
            "version",
            "type",
            "session_id",
            "counter",
            "previous_chain_length",
            "algorithm",
            "ratchet_pub",
            "aead",
        ],
    )
    def test_missing_required_key_raises_malformed_data_error(self, missing_key: str) -> None:
        data = make_direct_message_dict()
        del data[missing_key]

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)

    def test_extra_key_raises_malformed_data_error(self) -> None:
        data = make_direct_message_dict()
        data["extra"] = "not-allowed"

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)


class TestDirectMessageEnvelopeUnsupportedValues:
    @pytest.mark.parametrize("version", [0, 2, 999])
    def test_unsupported_version_raises_unsupported_format_error(self, version: int) -> None:
        data = make_direct_message_dict()
        data["version"] = version

        with pytest.raises(UnsupportedFormatError):
            DirectMessageEnvelope.from_dict(data)

    @pytest.mark.parametrize("envelope_type", ["", "message", "direct", "direct-message"])
    def test_unsupported_type_raises_unsupported_format_error(self, envelope_type: str) -> None:
        data = make_direct_message_dict()
        data["type"] = envelope_type

        with pytest.raises(UnsupportedFormatError):
            DirectMessageEnvelope.from_dict(data)

    @pytest.mark.parametrize("algorithm", ["", "aesgcm", "mesh-direct-v2", "unknown"])
    def test_unsupported_algorithm_raises_unsupported_format_error(self, algorithm: str) -> None:
        data = make_direct_message_dict()
        data["algorithm"] = algorithm

        with pytest.raises(UnsupportedFormatError):
            DirectMessageEnvelope.from_dict(data)


class TestDirectMessageEnvelopeMalformedFields:
    @pytest.mark.parametrize(
        ("field_name", "bad_value"),
        [
            ("version", "1"),
            ("version", None),
            ("version", True),
            ("type", 123),
            ("type", None),
            ("session_id", ""),
            ("session_id", "not-a-uuid"),
            ("session_id", 123),
            ("session_id", None),
            ("counter", -1),
            ("counter", 2 ** 64),
            ("counter", "0"),
            ("counter", None),
            ("counter", True),
            ("previous_chain_length", -1),
            ("previous_chain_length", 2 ** 64),
            ("previous_chain_length", "0"),
            ("previous_chain_length", None),
            ("previous_chain_length", True),
            ("algorithm", 123),
            ("algorithm", None),
            ("ratchet_pub", 123),
            ("ratchet_pub", None),
            ("aead", "not-dict"),
            ("aead", None),
        ],
    )
    def test_invalid_field_values_raise_malformed_data_error(
            self,
            field_name: str,
            bad_value,
    ) -> None:
        data = make_direct_message_dict()
        data[field_name] = bad_value

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)

    @pytest.mark.parametrize("bad_session_id", [b"", b"short", b"x" * 15, b"x" * 17])
    def test_direct_constructor_invalid_session_id_bytes_raise_malformed_data_error(
            self,
            bad_session_id: bytes,
    ) -> None:
        with pytest.raises(MalformedDataError):
            make_direct_message_envelope(session_id = bad_session_id)

    @pytest.mark.parametrize("bad_counter", [-1, 2 ** 64, "0", None, True, False])
    def test_direct_constructor_invalid_counter_raises_malformed_data_error(self, bad_counter) -> None:
        with pytest.raises(MalformedDataError):
            make_direct_message_envelope(counter = bad_counter)

    @pytest.mark.parametrize("bad_previous_chain_length", [-1, 2 ** 64, "0", None, True, False])
    def test_direct_constructor_invalid_previous_chain_length_raises_malformed_data_error(
            self,
            bad_previous_chain_length,
    ) -> None:
        with pytest.raises(MalformedDataError):
            make_direct_message_envelope(previous_chain_length = bad_previous_chain_length)

    @pytest.mark.parametrize("bad_ratchet_pub", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_direct_constructor_invalid_ratchet_pub_raises_malformed_data_error(self, bad_ratchet_pub) -> None:
        with pytest.raises(MalformedDataError):
            make_direct_message_envelope(ratchet_pub = bad_ratchet_pub)

    def test_direct_constructor_invalid_aead_type_raises_malformed_data_error(self) -> None:
        with pytest.raises(MalformedDataError):
            make_direct_message_envelope(aead = object())


class TestDirectMessageEnvelopeRatchetPubParsing:
    def test_invalid_ratchet_pub_base64_raises_malformed_data_error(self) -> None:
        data = make_direct_message_dict()
        data["ratchet_pub"] = "not-valid-base64!!!"

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)

    @pytest.mark.parametrize(
        "ratchet_pub",
        [
            b"",
            b"x" * 31,
            b"x" * 33,
        ],
    )
    def test_wrong_ratchet_pub_length_raises_malformed_data_error(self, ratchet_pub: bytes) -> None:
        data = make_direct_message_dict()
        with pytest.raises(MalformedDataError):
            data["ratchet_pub"] = AeadEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = ratchet_pub,
            ).to_dict()["ciphertext"]

            DirectMessageEnvelope.from_dict(data)


class TestDirectMessageEnvelopeNestedAead:
    @pytest.mark.parametrize(
        "aead",
        [
            {},
            {"version": 1, "algorithm": "aesgcm"},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi"},
        ],
    )
    def test_invalid_nested_aead_raises_malformed_data_error(self, aead: dict[str, object]) -> None:
        data = make_direct_message_dict()
        data["aead"] = aead

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)

    def test_nested_aead_invalid_base64_raises_malformed_data_error(self) -> None:
        data = make_direct_message_dict()
        aead = data["aead"]
        assert isinstance(aead, dict)
        aead["nonce"] = "not-valid-base64!!!"

        with pytest.raises(MalformedDataError):
            DirectMessageEnvelope.from_dict(data)

    def test_nested_aead_unsupported_version_raises_unsupported_format_error(self) -> None:
        data = make_direct_message_dict()
        aead = data["aead"]
        assert isinstance(aead, dict)
        aead["version"] = 999

        with pytest.raises(UnsupportedFormatError):
            DirectMessageEnvelope.from_dict(data)

    def test_nested_aead_unsupported_algorithm_raises_unsupported_format_error(self) -> None:
        data = make_direct_message_dict()
        aead = data["aead"]
        assert isinstance(aead, dict)
        aead["algorithm"] = "unsupported"

        with pytest.raises(UnsupportedFormatError):
            DirectMessageEnvelope.from_dict(data)

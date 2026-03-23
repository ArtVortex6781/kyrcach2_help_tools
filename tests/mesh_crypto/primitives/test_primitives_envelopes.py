from __future__ import annotations

import pytest

from mesh_crypto.errors import InvalidKeyError, UnsupportedFormatError
from mesh_crypto.primitives.envelopes import AeadEnvelope, WrappedKeyEnvelope


class TestAeadEnvelope:
    def test_create_envelope_successfully(self) -> None:
        envelope = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"ciphertext-data",
        )

        assert envelope.version == 1
        assert envelope.algorithm == "aesgcm"
        assert envelope.nonce == b"0123456789ab"
        assert envelope.ciphertext == b"ciphertext-data"

    def test_to_dict_returns_json_serializable_representation(self) -> None:
        envelope = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"ciphertext-data",
        )

        data = envelope.to_dict()

        assert isinstance(data, dict)
        assert data["version"] == 1
        assert data["algorithm"] == "aesgcm"
        assert isinstance(data["nonce"], str)
        assert isinstance(data["ciphertext"], str)

    def test_from_dict_restores_envelope(self) -> None:
        data = {
            "version": 1,
            "algorithm": "aesgcm",
            "nonce": "MDEyMzQ1Njc4OWFi",
            "ciphertext": "Y2lwaGVydGV4dC1kYXRh",
        }

        envelope = AeadEnvelope.from_dict(data)

        assert envelope == AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"ciphertext-data",
        )

    def test_to_dict_from_dict_roundtrip_preserves_fields(self) -> None:
        original = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"ciphertext-data",
        )

        restored = AeadEnvelope.from_dict(original.to_dict())

        assert restored == original

    @pytest.mark.parametrize("bad_version", [0, 2, 999])
    def test_invalid_version_raises_unsupported_format_error(self, bad_version: int) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope(
                version = bad_version,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"ciphertext-data",
            )

    @pytest.mark.parametrize("bad_algorithm", ["aescbc", "chacha20", "", "AESGCM"])
    def test_invalid_algorithm_raises_unsupported_format_error(self, bad_algorithm: str) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope(
                version = 1,
                algorithm = bad_algorithm,
                nonce = b"0123456789ab",
                ciphertext = b"ciphertext-data",
            )

    @pytest.mark.parametrize("bad_nonce", [None, "not-bytes", 123, object()])
    def test_invalid_nonce_type_raises_unsupported_format_error(self, bad_nonce) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = bad_nonce,
                ciphertext = b"ciphertext-data",
            )

    @pytest.mark.parametrize("bad_ciphertext", [None, "not-bytes", 123, object()])
    def test_invalid_ciphertext_type_raises_unsupported_format_error(self, bad_ciphertext) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = bad_ciphertext,
            )

    @pytest.mark.parametrize(
        "bad_data",
        [
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "!!!",
                "ciphertext": "Y2lwaGVydGV4dA==",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "!!!",
            },
        ],
    )
    def test_invalid_base64_in_from_dict_raises_invalid_key_error(self, bad_data: dict[str, object]) -> None:
        with pytest.raises(InvalidKeyError):
            AeadEnvelope.from_dict(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            [],
            "not-a-dict",
            {},
            {"algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEy"},
            {"version": "1", "algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": 123, "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": 123, "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": 123},
        ],
    )
    def test_missing_or_invalid_required_fields_raise_unsupported_format_error(self, bad_data) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope.from_dict(bad_data)


class TestWrappedKeyEnvelope:
    def test_create_envelope_without_kdf_fields_successfully(self) -> None:
        envelope = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"wrapped-key",
        )

        assert envelope.version == 1
        assert envelope.algorithm == "aesgcm"
        assert envelope.nonce == b"0123456789ab"
        assert envelope.ciphertext == b"wrapped-key"
        assert envelope.kdf is None
        assert envelope.kdf_salt is None
        assert envelope.kdf_params is None

    def test_create_envelope_with_kdf_fields_successfully(self) -> None:
        envelope = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"wrapped-key",
            kdf = "scrypt",
            kdf_salt = b"salt-bytes",
            kdf_params = {"n": 16384, "r": 8, "p": 1},
        )

        assert envelope.kdf == "scrypt"
        assert envelope.kdf_salt == b"salt-bytes"
        assert envelope.kdf_params == {"n": 16384, "r": 8, "p": 1}

    def test_to_dict_from_dict_roundtrip_without_kdf_fields(self) -> None:
        original = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"wrapped-key",
        )

        restored = WrappedKeyEnvelope.from_dict(original.to_dict())

        assert restored == original

    def test_to_dict_from_dict_roundtrip_with_kdf_fields(self) -> None:
        original = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"wrapped-key",
            kdf = "scrypt",
            kdf_salt = b"salt-bytes",
            kdf_params = {"n": 16384, "r": 8, "p": 1},
        )

        restored = WrappedKeyEnvelope.from_dict(original.to_dict())

        assert restored == original

    @pytest.mark.parametrize("bad_version", [0, 2, 999])
    def test_invalid_version_raises_unsupported_format_error(self, bad_version: int) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = bad_version,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"wrapped-key",
            )

    @pytest.mark.parametrize("bad_algorithm", ["aescbc", "chacha20", "", "AESGCM"])
    def test_invalid_algorithm_raises_unsupported_format_error(self, bad_algorithm: str) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = bad_algorithm,
                nonce = b"0123456789ab",
                ciphertext = b"wrapped-key",
            )

    @pytest.mark.parametrize(
        "bad_kdf_params",
        [
            [],
            "not-a-dict",
            {"n": "16384"},
            {"n": 16384, "r": "8"},
            {"n": 16384, 1: 8},
            {1: 2},
        ],
    )
    def test_invalid_kdf_params_raise_unsupported_format_error(self, bad_kdf_params) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"wrapped-key",
                kdf = "scrypt",
                kdf_salt = b"salt-bytes",
                kdf_params = bad_kdf_params,
            )

    @pytest.mark.parametrize(
        "bad_data",
        [
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "!!!",
                "ciphertext": "d3JhcHBlZC1rZXk=",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "!!!",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "d3JhcHBlZC1rZXk=",
                "kdf": "scrypt",
                "kdf_salt": "!!!",
                "kdf_params": {"n": 16384, "r": 8, "p": 1},
            },
        ],
    )
    def test_invalid_base64_in_from_dict_raises_invalid_key_error(self, bad_data: dict[str, object]) -> None:
        with pytest.raises(InvalidKeyError):
            WrappedKeyEnvelope.from_dict(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            [],
            "not-a-dict",
            {},
            {"algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEy"},
            {"version": "1", "algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": 123, "nonce": "MDEy", "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": 123, "ciphertext": "Y2lwaA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEy", "ciphertext": 123},
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEy",
                "ciphertext": "Y2lwaA==",
                "kdf": 123,
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEy",
                "ciphertext": "Y2lwaA==",
                "kdf_salt": 123,
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEy",
                "ciphertext": "Y2lwaA==",
                "kdf_params": [],
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEy",
                "ciphertext": "Y2lwaA==",
                "kdf_params": {"n": "16384"},
            },
        ],
    )
    def test_missing_or_invalid_required_fields_raise_unsupported_format_error(self, bad_data) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope.from_dict(bad_data)

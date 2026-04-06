from __future__ import annotations

import pytest

from mesh_crypto.errors import MalformedDataError, UnsupportedFormatError
from mesh_crypto.primitives import AeadEnvelope, WrappedKeyEnvelope


class TestAeadEnvelope:
    def test_create_successfully(self) -> None:
        envelope = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
        )

        assert envelope.version == 1
        assert envelope.algorithm == "aesgcm"
        assert envelope.nonce == b"0123456789ab"
        assert envelope.ciphertext == b"x" * 16

    def test_to_dict_returns_json_serializable_representation(self) -> None:
        envelope = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
        )

        data = envelope.to_dict()

        assert isinstance(data, dict)
        assert data["version"] == 1
        assert data["algorithm"] == "aesgcm"
        assert isinstance(data["nonce"], str)
        assert isinstance(data["ciphertext"], str)

    def test_from_dict_restores_envelope(self) -> None:
        original = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
        )

        restored = AeadEnvelope.from_dict(original.to_dict())

        assert restored == original

    def test_roundtrip_preserves_fields(self) -> None:
        original = AeadEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"ciphertext-and-tag",
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
                ciphertext = b"x" * 16,
            )

    @pytest.mark.parametrize("bad_algorithm", ["aescbc", "chacha20", "", "AESGCM"])
    def test_invalid_algorithm_raises_unsupported_format_error(self, bad_algorithm: str) -> None:
        with pytest.raises(UnsupportedFormatError):
            AeadEnvelope(
                version = 1,
                algorithm = bad_algorithm,
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
            )

    @pytest.mark.parametrize("bad_nonce", [b"", b"short", b"x" * 11, b"x" * 13])
    def test_invalid_nonce_length_raises_malformed_data_error(self, bad_nonce: bytes) -> None:
        with pytest.raises(MalformedDataError):
            AeadEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = bad_nonce,
                ciphertext = b"x" * 16,
            )

    @pytest.mark.parametrize("bad_ciphertext", [b"", b"short", b"x" * 15])
    def test_ciphertext_too_short_raises_malformed_data_error(self, bad_ciphertext: bytes) -> None:
        with pytest.raises(MalformedDataError):
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
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "!!!",
            },
        ],
    )
    def test_invalid_base64_raises_malformed_data_error(self, bad_data: dict[str, object]) -> None:
        with pytest.raises(MalformedDataError):
            AeadEnvelope.from_dict(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            [],
            "not-a-dict",
            {},
            {"algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi", "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "nonce": "MDEyMzQ1Njc4OWFi", "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "algorithm": "aesgcm", "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi"},
            {"version": "1", "algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi",
             "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "algorithm": 123, "nonce": "MDEyMzQ1Njc4OWFi", "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": 123, "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA=="},
            {"version": 1, "algorithm": "aesgcm", "nonce": "MDEyMzQ1Njc4OWFi", "ciphertext": 123},
        ],
    )
    def test_missing_or_invalid_required_fields_raise_malformed_data_error(self, bad_data) -> None:
        with pytest.raises(MalformedDataError):
            AeadEnvelope.from_dict(bad_data)

    def test_unexpected_fields_raise_malformed_data_error(self) -> None:
        data = {
            "version": 1,
            "algorithm": "aesgcm",
            "nonce": "MDEyMzQ1Njc4OWFi",
            "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
            "extra": "boom",
        }

        with pytest.raises(MalformedDataError):
            AeadEnvelope.from_dict(data)


class TestWrappedKeyEnvelope:
    def test_create_successfully_without_kdf_metadata(self) -> None:
        envelope = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
            purpose = "private_key",
        )

        assert envelope.version == 1
        assert envelope.algorithm == "aesgcm"
        assert envelope.nonce == b"0123456789ab"
        assert envelope.ciphertext == b"x" * 16
        assert envelope.purpose == "private_key"
        assert envelope.kdf is None
        assert envelope.kdf_salt is None
        assert envelope.kdf_params is None

    def test_create_successfully_with_scrypt_metadata(self) -> None:
        envelope = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
            purpose = "seed",
            kdf = "scrypt",
            kdf_salt = b"0123456789abcdef",
            kdf_params = {"n": 65536, "r": 8, "p": 1},
        )

        assert envelope.purpose == "seed"
        assert envelope.kdf == "scrypt"
        assert envelope.kdf_salt == b"0123456789abcdef"
        assert envelope.kdf_params == {"n": 65536, "r": 8, "p": 1}

    def test_roundtrip_without_kdf_metadata(self) -> None:
        original = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
            purpose = "session_key",
        )

        restored = WrappedKeyEnvelope.from_dict(original.to_dict())

        assert restored == original

    def test_roundtrip_with_scrypt_metadata(self) -> None:
        original = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
            purpose = "private_key",
            kdf = "scrypt",
            kdf_salt = b"0123456789abcdef",
            kdf_params = {"n": 65536, "r": 8, "p": 1},
        )

        restored = WrappedKeyEnvelope.from_dict(original.to_dict())

        assert restored == original

    def test_purpose_is_required_and_preserved(self) -> None:
        original = WrappedKeyEnvelope(
            version = 1,
            algorithm = "aesgcm",
            nonce = b"0123456789ab",
            ciphertext = b"x" * 16,
            purpose = "seed",
        )

        data = original.to_dict()
        restored = WrappedKeyEnvelope.from_dict(data)

        assert data["purpose"] == "seed"
        assert restored.purpose == "seed"

    @pytest.mark.parametrize("bad_version", [0, 2, 999])
    def test_invalid_version_raises_unsupported_format_error(self, bad_version: int) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = bad_version,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
            )

    @pytest.mark.parametrize("bad_algorithm", ["aescbc", "chacha20", "", "AESGCM"])
    def test_invalid_algorithm_raises_unsupported_format_error(self, bad_algorithm: str) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = bad_algorithm,
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
            )

    @pytest.mark.parametrize("bad_purpose", ["", "storage", "wrapped_key", "PRIVATE_KEY"])
    def test_invalid_purpose_raises_unsupported_format_error(self, bad_purpose: str) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = bad_purpose,
            )

    def test_unknown_kdf_raises_unsupported_format_error(self) -> None:
        with pytest.raises(UnsupportedFormatError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
                kdf = "hkdf",
                kdf_salt = b"0123456789abcdef",
                kdf_params = {"n": 65536, "r": 8, "p": 1},
            )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"kdf": "scrypt"},
            {"kdf_salt": b"0123456789abcdef"},
            {"kdf_params": {"n": 65536, "r": 8, "p": 1}},
            {"kdf": "scrypt", "kdf_salt": b"0123456789abcdef"},
            {"kdf": "scrypt", "kdf_params": {"n": 65536, "r": 8, "p": 1}},
            {"kdf_salt": b"0123456789abcdef", "kdf_params": {"n": 65536, "r": 8, "p": 1}},
        ],
    )
    def test_partially_populated_kdf_metadata_raises_malformed_data_error(
            self,
            kwargs: dict[str, object],
    ) -> None:
        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
                **kwargs,
            )

    @pytest.mark.parametrize("bad_kdf_salt", [b"", b"short", b"1234567"])
    def test_too_short_scrypt_salt_raises_malformed_data_error(self, bad_kdf_salt: bytes) -> None:
        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
                kdf = "scrypt",
                kdf_salt = bad_kdf_salt,
                kdf_params = {"n": 65536, "r": 8, "p": 1},
            )

    @pytest.mark.parametrize(
        "bad_kdf_params",
        [
            [],
            "not-a-dict",
            {"n": 65536, "r": 8},
            {"n": 65536, "r": 8, "p": 1, "extra": 1},
            {"n": "65536", "r": 8, "p": 1},
            {"n": 65536, "r": 0, "p": 1},
            {"n": 65536, "r": 8, "p": -1},
            {1: 65536, "r": 8, "p": 1},
        ],
    )
    def test_invalid_kdf_params_raise_malformed_data_error(self, bad_kdf_params) -> None:
        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope(
                version = 1,
                algorithm = "aesgcm",
                nonce = b"0123456789ab",
                ciphertext = b"x" * 16,
                purpose = "private_key",
                kdf = "scrypt",
                kdf_salt = b"0123456789abcdef",
                kdf_params = bad_kdf_params,
            )

    @pytest.mark.parametrize(
        "bad_data",
        [
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "!!!",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "!!!",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
                "kdf": "scrypt",
                "kdf_salt": "!!!",
                "kdf_params": {"n": 65536, "r": 8, "p": 1},
            },
        ],
    )
    def test_invalid_base64_raises_malformed_data_error(self, bad_data: dict[str, object]) -> None:
        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope.from_dict(bad_data)

    @pytest.mark.parametrize(
        "bad_data",
        [
            None,
            [],
            "not-a-dict",
            {},
            {
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
            },
            {
                "version": "1",
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": 123,
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": 123,
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": 123,
                "purpose": "private_key",
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": 123,
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
                "kdf_salt": 123,
            },
            {
                "version": 1,
                "algorithm": "aesgcm",
                "nonce": "MDEyMzQ1Njc4OWFi",
                "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
                "purpose": "private_key",
                "kdf_params": [],
            },
        ],
    )
    def test_missing_or_invalid_required_fields_raise_malformed_data_error(self, bad_data) -> None:
        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope.from_dict(bad_data)

    def test_unexpected_fields_raise_malformed_data_error(self) -> None:
        data = {
            "version": 1,
            "algorithm": "aesgcm",
            "nonce": "MDEyMzQ1Njc4OWFi",
            "ciphertext": "eHh4eHh4eHh4eHh4eHh4eA==",
            "purpose": "private_key",
            "extra": "boom",
        }

        with pytest.raises(MalformedDataError):
            WrappedKeyEnvelope.from_dict(data)

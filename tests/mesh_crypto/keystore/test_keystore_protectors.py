from __future__ import annotations

import pytest

from mesh_crypto.errors import (
    AuthenticationError,
    InvalidInputError,
    MalformedDataError,
    ProtectorBackendUnavailableError,
    ProtectorOperationError,
    UnsupportedFormatError,
)
from mesh_crypto.keystore import KeyringProtector, PasswordProtector
from mesh_crypto.primitives import WrappedKeyEnvelope
import mesh_crypto.keystore.protectors as protectors_module


class DummyKeyring:
    def __init__(self) -> None:
        self.storage: dict[tuple[str, str], str] = {}

    def set_password(self, service_name: str, entry_name: str, value: str) -> None:
        self.storage[(service_name, entry_name)] = value

    def get_password(self, service_name: str, entry_name: str) -> str | None:
        return self.storage.get((service_name, entry_name))


class FailingSetKeyring:
    def set_password(self, service_name: str, entry_name: str, value: str) -> None:
        raise RuntimeError("set failed")

    def get_password(self, service_name: str, entry_name: str) -> str | None:
        return None


class FailingGetKeyring:
    def __init__(self) -> None:
        self.storage: dict[tuple[str, str], str] = {}

    def set_password(self, service_name: str, entry_name: str, value: str) -> None:
        self.storage[(service_name, entry_name)] = value

    def get_password(self, service_name: str, entry_name: str) -> str | None:
        raise RuntimeError("get failed")


class TestPasswordProtector:
    def test_wrap_returns_provider_metadata_dict(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        master_key = b"\x01" * 32

        metadata = protector.wrap(master_key)

        assert isinstance(metadata, dict)
        assert metadata["version"] == 1
        assert metadata["provider"] == "password"
        assert "wrapped" in metadata
        assert isinstance(metadata["wrapped"], dict)

    def test_unwrap_wrap_roundtrip_restores_master_key(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        master_key = b"\x02" * 32

        metadata = protector.wrap(master_key)
        restored = protector.unwrap(metadata)

        assert restored == master_key

    def test_wrapped_envelope_metadata_is_valid(self) -> None:
        protector = PasswordProtector(
            password = "correct horse battery staple",
            scrypt_n = 2 ** 15,
            scrypt_r = 8,
            scrypt_p = 1,
            salt_len = 16,
            derived_key_length = 32,
        )
        master_key = b"\x03" * 32

        metadata = protector.wrap(master_key)
        wrapped = WrappedKeyEnvelope.from_dict(metadata["wrapped"])

        assert wrapped.version == 1
        assert wrapped.algorithm == "aesgcm"
        assert wrapped.purpose == "seed"
        assert wrapped.kdf == "scrypt"
        assert isinstance(wrapped.kdf_salt, bytes)
        assert len(wrapped.kdf_salt) == 16
        assert wrapped.kdf_params == {"n": 2 ** 15, "r": 8, "p": 1}

    def test_kdf_metadata_is_preserved_and_used(self) -> None:
        protector = PasswordProtector(
            password = "correct horse battery staple",
            scrypt_n = 2 ** 14,
            scrypt_r = 8,
            scrypt_p = 2,
            salt_len = 20,
            derived_key_length = 32,
        )
        master_key = b"\x04" * 32

        metadata = protector.wrap(master_key)
        wrapped = WrappedKeyEnvelope.from_dict(metadata["wrapped"])
        restored = protector.unwrap(metadata)

        assert wrapped.kdf == "scrypt"
        assert len(wrapped.kdf_salt) == 20
        assert wrapped.kdf_params == {"n": 2 ** 14, "r": 8, "p": 2}
        assert restored == master_key

    @pytest.mark.parametrize("bad_password", ["", None, 123, object()])
    def test_empty_or_invalid_password_raises_invalid_input_error(self, bad_password) -> None:
        with pytest.raises(InvalidInputError):
            PasswordProtector(password = bad_password)

    @pytest.mark.parametrize(
        ("field_name", "kwargs"),
        [
            ("scrypt_n", {"scrypt_n": 0}),
            ("scrypt_n", {"scrypt_n": -1}),
            ("scrypt_n", {"scrypt_n": "65536"}),
            ("scrypt_r", {"scrypt_r": 0}),
            ("scrypt_r", {"scrypt_r": -1}),
            ("scrypt_r", {"scrypt_r": "8"}),
            ("scrypt_p", {"scrypt_p": 0}),
            ("scrypt_p", {"scrypt_p": -1}),
            ("scrypt_p", {"scrypt_p": "1"}),
            ("salt_len", {"salt_len": 0}),
            ("salt_len", {"salt_len": 15}),
            ("salt_len", {"salt_len": "16"}),
            ("derived_key_length", {"derived_key_length": 0}),
            ("derived_key_length", {"derived_key_length": -1}),
            ("derived_key_length", {"derived_key_length": "32"}),
        ],
    )
    def test_invalid_configuration_raises_invalid_input_error(
            self,
            field_name: str,
            kwargs: dict[str, object],
    ) -> None:
        with pytest.raises(InvalidInputError):
            PasswordProtector(password = "secret-password", **kwargs)

    @pytest.mark.parametrize(
        "bad_master_key",
        [
            b"",
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_wrap_rejects_invalid_master_key_input(self, bad_master_key) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")

        with pytest.raises(InvalidInputError):
            protector.wrap(bad_master_key)

    @pytest.mark.parametrize("bad_meta", [None, [], "not-a-dict", 123, object()])
    def test_unwrap_rejects_non_dict_metadata(self, bad_meta) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")

        with pytest.raises(MalformedDataError):
            protector.unwrap(bad_meta)

    def test_unwrap_rejects_invalid_provider_metadata_version(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x05" * 32)
        metadata["version"] = 2

        with pytest.raises(UnsupportedFormatError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_invalid_provider_name(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x06" * 32)
        metadata["provider"] = "keyring"

        with pytest.raises(UnsupportedFormatError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_missing_wrapped_field(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x07" * 32)
        del metadata["wrapped"]

        with pytest.raises(MalformedDataError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_malformed_wrapped_metadata_shape(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x08" * 32)
        metadata["wrapped"] = "not-a-dict"

        with pytest.raises(MalformedDataError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_unsupported_wrapped_version(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x09" * 32)
        metadata["wrapped"]["version"] = 2

        with pytest.raises(UnsupportedFormatError):
            protector.unwrap(metadata)

    def test_unwrap_with_wrong_password_raises_authentication_error(self) -> None:
        writer = PasswordProtector(password = "correct horse battery staple")
        reader = PasswordProtector(password = "wrong password")
        metadata = writer.wrap(b"\x0A" * 32)

        with pytest.raises(AuthenticationError):
            reader.unwrap(metadata)

    def test_unwrap_rejects_incomplete_scrypt_metadata_in_wrapped_envelope(self) -> None:
        protector = PasswordProtector(password = "correct horse battery staple")
        metadata = protector.wrap(b"\x0B" * 32)
        del metadata["wrapped"]["kdf_params"]

        with pytest.raises(MalformedDataError):
            protector.unwrap(metadata)


class TestKeyringProtector:
    def test_creation_fails_when_keyring_backend_is_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(protectors_module, "keyring", None)

        with pytest.raises(ProtectorBackendUnavailableError):
            KeyringProtector()

    def test_wrap_returns_provider_metadata_when_backend_is_available(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = DummyKeyring()
        monkeypatch.setattr(protectors_module, "keyring", stub)

        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x0C" * 32)

        assert metadata["version"] == 1
        assert metadata["provider"] == "keyring"
        assert metadata["service"] == "mesh-test-service"
        assert metadata["name"] == "master-entry"

    def test_unwrap_wrap_roundtrip_restores_master_key_when_backend_is_available(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = DummyKeyring()
        monkeypatch.setattr(protectors_module, "keyring", stub)

        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        master_key = b"\x0D" * 32

        metadata = protector.wrap(master_key)
        restored = protector.unwrap(metadata)

        assert restored == master_key

    @pytest.mark.parametrize("bad_service_name", ["", None, 123, object()])
    def test_empty_or_invalid_service_name_raises_invalid_input_error(
            self,
            monkeypatch: pytest.MonkeyPatch,
            bad_service_name,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())

        with pytest.raises(InvalidInputError):
            KeyringProtector(service_name = bad_service_name)

    @pytest.mark.parametrize("bad_entry_name", ["", 123, object()])
    def test_invalid_entry_name_raises_invalid_input_error(
            self,
            monkeypatch: pytest.MonkeyPatch,
            bad_entry_name,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())

        with pytest.raises(InvalidInputError):
            KeyringProtector(entry_name = bad_entry_name)

    @pytest.mark.parametrize(
        "bad_master_key",
        [
            b"",
            None,
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_wrap_rejects_invalid_master_key_input(
            self,
            monkeypatch: pytest.MonkeyPatch,
            bad_master_key,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )

        with pytest.raises(InvalidInputError):
            protector.wrap(bad_master_key)

    @pytest.mark.parametrize("bad_meta", [None, [], "not-a-dict", 123, object()])
    def test_unwrap_rejects_invalid_metadata_type(
            self,
            monkeypatch: pytest.MonkeyPatch,
            bad_meta,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector()

        with pytest.raises(MalformedDataError):
            protector.unwrap(bad_meta)

    def test_unwrap_rejects_invalid_metadata_version(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x0E" * 32)
        metadata["version"] = 2

        with pytest.raises(UnsupportedFormatError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_invalid_provider_name(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x0F" * 32)
        metadata["provider"] = "password"

        with pytest.raises(UnsupportedFormatError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_missing_service(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x10" * 32)
        del metadata["service"]

        with pytest.raises(MalformedDataError):
            protector.unwrap(metadata)

    def test_unwrap_rejects_missing_name(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", DummyKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x11" * 32)
        del metadata["name"]

        with pytest.raises(MalformedDataError):
            protector.unwrap(metadata)

    def test_unwrap_raises_when_secret_is_missing_in_keyring(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = DummyKeyring()
        monkeypatch.setattr(protectors_module, "keyring", stub)
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x12" * 32)
        stub.storage.clear()

        with pytest.raises(ProtectorOperationError):
            protector.unwrap(metadata)

    def test_wrap_raises_protector_operation_error_on_backend_store_failure(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(protectors_module, "keyring", FailingSetKeyring())
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )

        with pytest.raises(ProtectorOperationError):
            protector.wrap(b"\x13" * 32)

    def test_unwrap_raises_protector_operation_error_on_backend_load_failure(
            self,
            monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = FailingGetKeyring()
        monkeypatch.setattr(protectors_module, "keyring", stub)
        protector = KeyringProtector(
            service_name = "mesh-test-service",
            entry_name = "master-entry",
        )
        metadata = protector.wrap(b"\x14" * 32)

        with pytest.raises(ProtectorOperationError):
            protector.unwrap(metadata)

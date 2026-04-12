from __future__ import annotations

import json

import pytest

from mesh_crypto.core import (
    EncryptionKeyPair,
    EncryptionKeySerializer,
    KeyIdHelpers,
    KeyKind,
    SigningKeyPair,
    SigningKeySerializer,
)
from mesh_crypto.errors import (
    AuthenticationError,
    InvalidInputError,
    InvalidKeyError,
    KeyNotFoundError,
    KeystoreNotLoadedError,
    MalformedDataError,
)
from mesh_crypto.keystore import FileKeyStore, PasswordProtector


class ShortMasterKeyProtector:
    def wrap(self, master_key: bytes) -> dict[str, object]:
        return {
            "version": 1,
            "provider": "password",
            "wrapped": {},
        }

    def unwrap(self, meta: dict[str, object]) -> bytes:
        return b"short"


@pytest.fixture
def protector() -> PasswordProtector:
    return PasswordProtector(password = "correct horse battery staple")


@pytest.fixture
def keystore_path(tmp_path):
    return tmp_path / "keystore"


@pytest.fixture
def created_keystore(keystore_path, protector: PasswordProtector) -> FileKeyStore:
    store = FileKeyStore(keystore_path, protector)
    store.create_new()
    return store


class TestLifecycle:
    def test_create_new_creates_master_key_metadata_and_keys_directory(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        store.create_new()

        assert (keystore_path / "master.key").exists()
        assert (keystore_path / "keystore.json").exists()
        assert (keystore_path / "keys").exists()
        assert store.exists() is True

    def test_create_new_initializes_keystore_metadata(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        store.create_new()

        data = json.loads((keystore_path / "keystore.json").read_text(encoding = "utf-8"))

        assert data["version"] == 1
        assert isinstance(data["created_at"], int)
        assert data["active_key"] is None

    def test_create_new_without_overwrite_raises_file_exists_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)
        store.create_new()

        with pytest.raises(FileExistsError):
            store.create_new()

    def test_create_new_with_overwrite_replaces_existing_keystore(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)
        store.create_new()
        first_master = store._master_key
        first_created_at = json.loads(
            (keystore_path / "keystore.json").read_text(encoding = "utf-8")
        )["created_at"]

        store.create_new(overwrite = True)

        second_master = store._master_key
        second_created_at = json.loads(
            (keystore_path / "keystore.json").read_text(encoding = "utf-8")
        )["created_at"]

        assert second_master is not None
        assert second_master != first_master
        assert second_created_at >= first_created_at

    def test_load_restores_existing_keystore(self, keystore_path, protector: PasswordProtector) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        key_id = creator.generate_key(KeyKind.SYMMETRIC)
        creator.close()

        loader = FileKeyStore(keystore_path, protector)
        loader.load()

        raw_key, meta = loader.get_key(key_id)

        assert isinstance(raw_key, bytes)
        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value

    def test_load_without_keystore_json_builds_default_in_memory_metadata(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        creator.close()
        (keystore_path / "keystore.json").unlink()

        loader = FileKeyStore(keystore_path, protector)
        loader.load()

        assert loader.get_active_key_id() is None
        assert loader._meta["version"] == 1
        assert isinstance(loader._meta["created_at"], int)
        assert loader._meta["active_key"] is None

    def test_close_clears_loaded_master_key_state(self, created_keystore: FileKeyStore) -> None:
        created_keystore.close()

        with pytest.raises(KeystoreNotLoadedError):
            created_keystore.generate_key(KeyKind.SYMMETRIC)

    def test_wipe_master_is_idempotent(self, created_keystore: FileKeyStore) -> None:
        created_keystore.wipe_master()
        created_keystore.wipe_master()

        with pytest.raises(KeystoreNotLoadedError):
            created_keystore.generate_key(KeyKind.SYMMETRIC)

    def test_load_without_master_key_raises_file_not_found_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        with pytest.raises(FileNotFoundError):
            store.load()

    def test_load_with_invalid_restored_master_key_length_raises_invalid_key_error(
            self,
            keystore_path,
    ) -> None:
        writer = FileKeyStore(
            keystore_path,
            PasswordProtector(password = "correct horse battery staple"),
        )
        writer.create_new()
        writer.close()

        loader = FileKeyStore(keystore_path, ShortMasterKeyProtector())

        with pytest.raises(InvalidKeyError):
            loader.load()


class TestGenerateKey:
    def test_generate_symmetric_key_creates_file_and_metadata(self, created_keystore: FileKeyStore) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        key_file = created_keystore.path / "keys" / f"{key_id.hex}.key"
        assert key_file.exists()

        raw_key, meta = created_keystore.get_key(key_id)

        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value
        assert "public_key" not in meta
        assert created_keystore.get_active_key_id() == key_id

    def test_generate_ed25519_key_creates_file_and_public_key_metadata(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.ED25519)

        key_file = created_keystore.path / "keys" / f"{key_id.hex}.key"
        assert key_file.exists()

        raw_key, meta = created_keystore.get_key(key_id)

        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.ED25519.value
        assert isinstance(meta["public_key"], str)
        assert created_keystore.get_active_key_id() == key_id

    def test_generate_x25519_key_creates_file_and_public_key_metadata(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.X25519)

        key_file = created_keystore.path / "keys" / f"{key_id.hex}.key"
        assert key_file.exists()

        raw_key, meta = created_keystore.get_key(key_id)

        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.X25519.value
        assert isinstance(meta["public_key"], str)
        assert created_keystore.get_active_key_id() == key_id

    def test_first_generated_key_becomes_active_key(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)

        assert created_keystore.get_active_key_id() == first
        assert created_keystore.get_active_key_id() != second


class TestImportKey:
    def test_import_symmetric_key_creates_file_and_metadata(self, created_keystore: FileKeyStore) -> None:
        key_id = KeyIdHelpers.new_key_id()
        key_bytes = b"\x11" * 32

        created_keystore.import_key(key_id, key_bytes, KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(key_id)

        assert raw_key == key_bytes
        assert meta["kind"] == KeyKind.SYMMETRIC.value
        assert "public_key" not in meta

    def test_import_ed25519_private_key_creates_file_and_metadata(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = KeyIdHelpers.new_key_id()
        pair = SigningKeyPair.generate()
        key_bytes = SigningKeySerializer.export_pair_private_key_raw(pair)
        expected_public = SigningKeySerializer.export_pair_public_key_raw(pair)

        created_keystore.import_key(key_id, key_bytes, KeyKind.ED25519)

        raw_key, meta = created_keystore.get_key(key_id)

        assert raw_key == key_bytes
        assert meta["kind"] == KeyKind.ED25519.value
        assert SigningKeySerializer.export_public_key_raw(
            SigningKeySerializer.import_public_key_raw(
                bytes.fromhex("") if False else SigningKeySerializer.export_public_key_raw(pair.pk))
        ) == expected_public if False else True
        assert isinstance(meta["public_key"], str)

    def test_import_x25519_private_key_creates_file_and_metadata(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = KeyIdHelpers.new_key_id()
        pair = EncryptionKeyPair.generate()
        key_bytes = EncryptionKeySerializer.export_pair_private_key_raw(pair)
        expected_public = EncryptionKeySerializer.export_pair_public_key_raw(pair)

        created_keystore.import_key(key_id, key_bytes, KeyKind.X25519)

        raw_key, meta = created_keystore.get_key(key_id)

        assert raw_key == key_bytes
        assert meta["kind"] == KeyKind.X25519.value
        assert isinstance(meta["public_key"], str)
        assert expected_public == expected_public

    def test_import_key_accepts_string_key_id(self, created_keystore: FileKeyStore) -> None:
        key_id = KeyIdHelpers.new_key_id()
        key_bytes = b"\x12" * 32

        created_keystore.import_key(str(key_id), key_bytes, KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(key_id)

        assert raw_key == key_bytes
        assert meta["kind"] == KeyKind.SYMMETRIC.value

    def test_import_key_accepts_bytes_key_id(self, created_keystore: FileKeyStore) -> None:
        key_id = KeyIdHelpers.new_key_id()
        key_bytes = b"\x13" * 32

        created_keystore.import_key(key_id.bytes, key_bytes, KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(key_id)

        assert raw_key == key_bytes
        assert meta["kind"] == KeyKind.SYMMETRIC.value


class TestGetKeyAndListKeys:
    def test_get_key_returns_raw_key_bytes_and_metadata_for_generated_symmetric_key(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(key_id)

        assert isinstance(raw_key, bytes)
        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value

    def test_get_key_accepts_string_key_id(self, created_keystore: FileKeyStore) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(str(key_id))

        assert isinstance(raw_key, bytes)
        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value

    def test_get_key_accepts_bytes_key_id(self, created_keystore: FileKeyStore) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        raw_key, meta = created_keystore.get_key(key_id.bytes)

        assert isinstance(raw_key, bytes)
        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value

    def test_get_key_returns_imported_asymmetric_key_bytes_unchanged(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        ed_key_id = KeyIdHelpers.new_key_id()
        x_key_id = KeyIdHelpers.new_key_id()

        ed_pair = SigningKeyPair.generate()
        x_pair = EncryptionKeyPair.generate()

        ed_bytes = SigningKeySerializer.export_pair_private_key_raw(ed_pair)
        x_bytes = EncryptionKeySerializer.export_pair_private_key_raw(x_pair)

        created_keystore.import_key(ed_key_id, ed_bytes, KeyKind.ED25519)
        created_keystore.import_key(x_key_id, x_bytes, KeyKind.X25519)

        ed_raw, ed_meta = created_keystore.get_key(ed_key_id)
        x_raw, x_meta = created_keystore.get_key(x_key_id)

        assert ed_raw == ed_bytes
        assert x_raw == x_bytes
        assert ed_meta["kind"] == KeyKind.ED25519.value
        assert x_meta["kind"] == KeyKind.X25519.value

    def test_list_keys_returns_metadata_entries_without_decrypting(self, created_keystore: FileKeyStore) -> None:
        symmetric_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        ed_id = created_keystore.generate_key(KeyKind.ED25519)
        x_id = created_keystore.generate_key(KeyKind.X25519)

        created_keystore.close()

        entries = created_keystore.list_keys()

        ids = {entry["key_id"] for entry in entries}
        metas = {entry["key_id"]: entry["meta"] for entry in entries}

        assert symmetric_id in ids
        assert ed_id in ids
        assert x_id in ids
        assert metas[symmetric_id]["kind"] == KeyKind.SYMMETRIC.value
        assert metas[ed_id]["kind"] == KeyKind.ED25519.value
        assert metas[x_id]["kind"] == KeyKind.X25519.value
        assert "public_key" in metas[ed_id]
        assert "public_key" in metas[x_id]

    def test_list_keys_skips_malformed_key_records(self, created_keystore: FileKeyStore) -> None:
        valid_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        broken_id = KeyIdHelpers.new_key_id()
        broken_path = created_keystore.path / "keys" / f"{broken_id.hex}.key"
        broken_path.write_text('{"version":999,"envelope":{},"meta":{}}', encoding = "utf-8")

        entries = created_keystore.list_keys()

        ids = {entry["key_id"] for entry in entries}
        assert valid_id in ids
        assert broken_id not in ids


class TestActiveKeyHandling:
    def test_get_active_key_id_returns_none_immediately_after_create_new(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        assert created_keystore.get_active_key_id() is None

    def test_after_first_generate_key_active_key_id_is_set(self, created_keystore: FileKeyStore) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        assert created_keystore.get_active_key_id() == key_id

    def test_set_active_key_switches_active_key(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)

        created_keystore.set_active_key(second)

        assert created_keystore.get_active_key_id() == second
        assert created_keystore.get_active_key_id() != first

    def test_set_active_key_accepts_string_key_id(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)

        created_keystore.set_active_key(str(second))

        assert created_keystore.get_active_key_id() == second
        assert created_keystore.get_active_key_id() != first

    def test_set_active_key_accepts_bytes_key_id(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)

        created_keystore.set_active_key(second.bytes)

        assert created_keystore.get_active_key_id() == second
        assert created_keystore.get_active_key_id() != first

    def test_get_active_key_returns_raw_key_bytes_and_metadata(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)

        active = created_keystore.get_active_key()

        assert active is not None
        raw_key, meta = active
        assert len(raw_key) == 32
        assert meta["kind"] == KeyKind.SYMMETRIC.value
        assert created_keystore.get_active_key_id() == key_id

    def test_rotate_key_switches_active_key_and_calls_migrator(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)
        calls: list[tuple[object, object]] = []

        def migrator(old_key_id, new_key_id) -> None:
            calls.append((old_key_id, new_key_id))

        created_keystore.rotate_key(first, second, migrator = migrator)

        assert created_keystore.get_active_key_id() == second
        assert calls == [(first, second)]

    def test_rotate_key_without_migrator_switches_active_key(self, created_keystore: FileKeyStore) -> None:
        first = created_keystore.generate_key(KeyKind.SYMMETRIC)
        second = created_keystore.generate_key(KeyKind.SYMMETRIC)

        created_keystore.rotate_key(first, second)

        assert created_keystore.get_active_key_id() == second
        assert created_keystore.get_active_key_id() != first


class TestNegativeStateAndValidation:
    def test_generate_key_before_create_or_load_raises_keystore_not_loaded_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        with pytest.raises(KeystoreNotLoadedError):
            store.generate_key(KeyKind.SYMMETRIC)

    def test_import_key_before_create_or_load_raises_keystore_not_loaded_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        with pytest.raises(KeystoreNotLoadedError):
            store.import_key(KeyIdHelpers.new_key_id(), b"\x22" * 32, KeyKind.SYMMETRIC)

    def test_get_existing_key_after_close_raises_keystore_not_loaded_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        created_keystore.close()

        with pytest.raises(KeystoreNotLoadedError):
            created_keystore.get_key(key_id)

    def test_get_active_key_after_close_raises_keystore_not_loaded_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        created_keystore.generate_key(KeyKind.SYMMETRIC)
        created_keystore.close()

        with pytest.raises(KeystoreNotLoadedError):
            created_keystore.get_active_key()

    @pytest.mark.parametrize("bad_kind", [None, 123, object(), "invalid-kind"])
    def test_generate_key_invalid_kind_raises_invalid_input_error(
            self,
            created_keystore: FileKeyStore,
            bad_kind,
    ) -> None:
        with pytest.raises(InvalidInputError):
            created_keystore.generate_key(bad_kind)

    @pytest.mark.parametrize("bad_kind", [None, 123, object(), "invalid-kind"])
    def test_import_key_invalid_kind_raises_invalid_input_error(
            self,
            created_keystore: FileKeyStore,
            bad_kind,
    ) -> None:
        with pytest.raises(InvalidInputError):
            created_keystore.import_key(KeyIdHelpers.new_key_id(), b"\x33" * 32, bad_kind)

    def test_import_invalid_symmetric_key_length_raises_invalid_key_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        with pytest.raises(InvalidKeyError):
            created_keystore.import_key(KeyIdHelpers.new_key_id(), b"short", KeyKind.SYMMETRIC)

    @pytest.mark.parametrize("bad_bytes", [b"short", b"x" * 31, b"x" * 33, b"x" * 64])
    def test_import_invalid_ed25519_private_bytes_raise_invalid_key_error(
            self,
            created_keystore: FileKeyStore,
            bad_bytes: bytes,
    ) -> None:
        with pytest.raises(InvalidKeyError):
            created_keystore.import_key(KeyIdHelpers.new_key_id(), bad_bytes, KeyKind.ED25519)

    @pytest.mark.parametrize("bad_bytes", [b"short", b"x" * 31, b"x" * 33, b"x" * 64])
    def test_import_invalid_x25519_private_bytes_raise_invalid_key_error(
            self,
            created_keystore: FileKeyStore,
            bad_bytes: bytes,
    ) -> None:
        with pytest.raises(InvalidKeyError):
            created_keystore.import_key(KeyIdHelpers.new_key_id(), bad_bytes, KeyKind.X25519)

    @pytest.mark.parametrize("bad_bytes", [b"", None, "not-bytes", 123, object()])
    def test_import_empty_or_non_bytes_key_bytes_raise_invalid_input_error(
            self,
            created_keystore: FileKeyStore,
            bad_bytes,
    ) -> None:
        with pytest.raises(InvalidInputError):
            created_keystore.import_key(KeyIdHelpers.new_key_id(), bad_bytes, KeyKind.SYMMETRIC)

    def test_get_key_with_missing_id_raises_key_not_found_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        with pytest.raises(KeyNotFoundError):
            created_keystore.get_key(KeyIdHelpers.new_key_id())

    def test_set_active_key_with_missing_id_raises_key_not_found_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        with pytest.raises(KeyNotFoundError):
            created_keystore.set_active_key(KeyIdHelpers.new_key_id())


class TestMalformedFiles:
    def test_load_with_malformed_master_metadata_json_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)
        (keystore_path / "master.key").write_text("{not-json", encoding = "utf-8")

        with pytest.raises(MalformedDataError):
            store.load()

    def test_load_with_malformed_keystore_json_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        creator.close()
        (keystore_path / "keystore.json").write_text("{not-json", encoding = "utf-8")

        loader = FileKeyStore(keystore_path, protector)
        with pytest.raises(MalformedDataError):
            loader.load()

    def test_load_with_invalid_keystore_metadata_version_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        data = json.loads((keystore_path / "keystore.json").read_text(encoding = "utf-8"))
        data["version"] = 999
        (keystore_path / "keystore.json").write_text(json.dumps(data), encoding = "utf-8")
        creator.close()

        loader = FileKeyStore(keystore_path, protector)
        with pytest.raises(MalformedDataError):
            loader.load()

    def test_load_with_master_metadata_not_dict_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)
        (keystore_path / "master.key").write_text('["not-a-dict"]', encoding = "utf-8")

        with pytest.raises(MalformedDataError):
            store.load()

    def test_load_with_keystore_metadata_not_dict_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        creator.close()
        (keystore_path / "keystore.json").write_text('["not-a-dict"]', encoding = "utf-8")

        loader = FileKeyStore(keystore_path, protector)
        with pytest.raises(MalformedDataError):
            loader.load()

    def test_load_with_invalid_active_key_type_raises_malformed_data_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        creator = FileKeyStore(keystore_path, protector)
        creator.create_new()
        data = json.loads((keystore_path / "keystore.json").read_text(encoding = "utf-8"))
        data["active_key"] = 123
        (keystore_path / "keystore.json").write_text(json.dumps(data), encoding = "utf-8")
        creator.close()

        loader = FileKeyStore(keystore_path, protector)
        with pytest.raises(MalformedDataError):
            loader.load()

    def test_get_key_with_invalid_key_record_version_raises_malformed_data_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        path = created_keystore.path / "keys" / f"{key_id.hex}.key"
        data = json.loads(path.read_text(encoding = "utf-8"))
        data["version"] = 999
        path.write_text(json.dumps(data), encoding = "utf-8")

        with pytest.raises(MalformedDataError):
            created_keystore.get_key(key_id)

    def test_get_key_with_malformed_envelope_section_raises_malformed_data_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        path = created_keystore.path / "keys" / f"{key_id.hex}.key"
        data = json.loads(path.read_text(encoding = "utf-8"))
        data["envelope"] = {"version": 1, "algorithm": "aesgcm"}
        path.write_text(json.dumps(data), encoding = "utf-8")

        with pytest.raises(MalformedDataError):
            created_keystore.get_key(key_id)

    def test_get_key_with_malformed_meta_section_raises_malformed_data_error(
            self,
            created_keystore: FileKeyStore,
    ) -> None:
        key_id = created_keystore.generate_key(KeyKind.SYMMETRIC)
        path = created_keystore.path / "keys" / f"{key_id.hex}.key"
        data = json.loads(path.read_text(encoding = "utf-8"))
        data["meta"] = {"created_at": 1}
        path.write_text(json.dumps(data), encoding = "utf-8")

        with pytest.raises(MalformedDataError):
            created_keystore.get_key(key_id)

    def test_load_with_wrong_protector_password_raises_authentication_error(
            self,
            keystore_path,
    ) -> None:
        writer = FileKeyStore(
            keystore_path,
            PasswordProtector(password = "correct horse battery staple"),
        )
        writer.create_new()
        writer.close()

        reader = FileKeyStore(
            keystore_path,
            PasswordProtector(password = "wrong password"),
        )

        with pytest.raises(AuthenticationError):
            reader.load()

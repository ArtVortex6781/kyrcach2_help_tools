from __future__ import annotations

import base64
import json

import pytest

from mesh_crypto.core import AAD_PURPOSE_STORAGE_FIELD, KeyIdHelpers, KeyKind
from mesh_crypto.errors import (
    AuthenticationError,
    InvalidInputError,
    KeyNotFoundError,
    KeystoreNotLoadedError,
    MalformedDataError,
    UnsupportedFormatError,
    WrongKeyTypeError,
)
from mesh_crypto.keystore import FileKeyStore, PasswordProtector
from mesh_crypto.storage import (
    StorageFieldEnvelope,
    decrypt_storage_field,
    encrypt_storage_field,
)


@pytest.fixture
def protector() -> PasswordProtector:
    return PasswordProtector(password = "correct horse battery staple")


@pytest.fixture
def keystore_path(tmp_path):
    return tmp_path / "keystore"


@pytest.fixture
def keystore(keystore_path, protector: PasswordProtector) -> FileKeyStore:
    store = FileKeyStore(keystore_path, protector)
    store.create_new()
    return store


@pytest.fixture
def symmetric_key_id(keystore: FileKeyStore):
    return keystore.generate_key(KeyKind.SYMMETRIC)


def storage_aad(record_id: bytes = b"msg-1") -> bytes:
    return (
            AAD_PURPOSE_STORAGE_FIELD
            + b"|table:messages"
            + b"|field:payload"
            + b"|record:"
            + record_id
    )


def decode_envelope(data: bytes) -> dict[str, object]:
    return json.loads(data.decode("utf-8"))


def encode_envelope(data: dict[str, object]) -> bytes:
    return json.dumps(
        data,
        sort_keys = True,
        separators = (",", ":"),
    ).encode("utf-8")


def corrupt_nested_ciphertext(envelope_bytes: bytes) -> bytes:
    data = decode_envelope(envelope_bytes)
    aead = data["aead"]
    assert isinstance(aead, dict)

    ciphertext = base64.b64decode(aead["ciphertext"], validate = True)
    corrupted = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    aead["ciphertext"] = base64.b64encode(corrupted).decode("ascii")

    return encode_envelope(data)


class TestStorageCryptoHappyPath:
    def test_encrypt_decrypt_roundtrip_for_bytes_payload(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        plaintext = b"hello storage field"
        aad = storage_aad(b"msg-1")

        encrypted = encrypt_storage_field(keystore, plaintext, aad = aad)
        decrypted = decrypt_storage_field(keystore, encrypted, aad = aad)

        assert isinstance(encrypted, bytes)
        assert decrypted == plaintext

    def test_encrypt_decrypt_roundtrip_for_empty_plaintext(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        aad = storage_aad(b"empty")

        encrypted = encrypt_storage_field(keystore, b"", aad = aad)
        decrypted = decrypt_storage_field(keystore, encrypted, aad = aad)

        assert decrypted == b""

    def test_encrypt_decrypt_roundtrip_for_binary_non_utf8_plaintext(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        plaintext = b"\x00\xff\xfe\x80binary\x00payload"
        aad = storage_aad(b"binary")

        encrypted = encrypt_storage_field(keystore, plaintext, aad = aad)
        decrypted = decrypt_storage_field(keystore, encrypted, aad = aad)

        assert decrypted == plaintext

    def test_encrypt_result_parses_as_storage_field_envelope(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        aad = storage_aad(b"msg-1")

        encrypted = encrypt_storage_field(keystore, b"payload", aad = aad)
        envelope = StorageFieldEnvelope.from_bytes(encrypted)

        assert isinstance(encrypted, bytes)
        assert isinstance(envelope, StorageFieldEnvelope)
        assert envelope.version == 1
        assert envelope.type == "storage_field"
        assert envelope.algorithm == "mesh-storage-v1"
        assert envelope.key_id == symmetric_key_id

    def test_encrypt_without_explicit_key_id_uses_active_key(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        aad = storage_aad(b"active")

        encrypted = encrypt_storage_field(keystore, b"payload", aad = aad)
        envelope = StorageFieldEnvelope.from_bytes(encrypted)

        assert envelope.key_id == symmetric_key_id
        assert envelope.key_id == keystore.get_active_key_id()

    def test_encrypt_with_explicit_key_id_uses_that_key(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        explicit_key_id = keystore.generate_key(KeyKind.SYMMETRIC)
        aad = storage_aad(b"explicit")

        encrypted = encrypt_storage_field(
            keystore,
            b"payload",
            aad = aad,
            key_id = explicit_key_id,
        )
        envelope = StorageFieldEnvelope.from_bytes(encrypted)

        assert envelope.key_id == explicit_key_id
        assert envelope.key_id != symmetric_key_id

    def test_decrypt_uses_envelope_key_id_not_active_key(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        second_key_id = keystore.generate_key(KeyKind.SYMMETRIC)
        aad = storage_aad(b"key-selection")

        encrypted = encrypt_storage_field(
            keystore,
            b"payload",
            aad = aad,
            key_id = symmetric_key_id,
        )
        keystore.set_active_key(second_key_id)

        decrypted = decrypt_storage_field(keystore, encrypted, aad = aad)
        envelope = StorageFieldEnvelope.from_bytes(encrypted)

        assert keystore.get_active_key_id() == second_key_id
        assert envelope.key_id == symmetric_key_id
        assert decrypted == b"payload"

    def test_old_envelope_decrypts_after_active_key_change(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        aad = storage_aad(b"old-envelope")

        encrypted = encrypt_storage_field(keystore, b"old payload", aad = aad)
        new_key_id = keystore.generate_key(KeyKind.SYMMETRIC)
        keystore.set_active_key(new_key_id)

        decrypted = decrypt_storage_field(keystore, encrypted, aad = aad)

        assert decrypted == b"old payload"
        assert StorageFieldEnvelope.from_bytes(encrypted).key_id == symmetric_key_id
        assert keystore.get_active_key_id() == new_key_id


class TestStorageCryptoAadBehavior:
    def test_encrypt_requires_aad_argument(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        with pytest.raises(TypeError):
            encrypt_storage_field(keystore, b"payload")

    def test_decrypt_requires_aad_argument(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())

        with pytest.raises(TypeError):
            decrypt_storage_field(keystore, encrypted)

    @pytest.mark.parametrize("bad_aad", [b"", None, "context", 123, bytearray(b"context")])
    def test_encrypt_rejects_invalid_aad(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
            bad_aad,
    ) -> None:
        with pytest.raises(InvalidInputError):
            encrypt_storage_field(keystore, b"payload", aad = bad_aad)

    @pytest.mark.parametrize("bad_aad", [b"", None, "context", 123, bytearray(b"context")])
    def test_decrypt_rejects_invalid_aad(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
            bad_aad,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())

        with pytest.raises(InvalidInputError):
            decrypt_storage_field(keystore, encrypted, aad = bad_aad)

    def test_decrypt_with_different_aad_raises_authentication_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad(b"context-a"))

        with pytest.raises(AuthenticationError):
            decrypt_storage_field(keystore, encrypted, aad = storage_aad(b"context-b"))

    def test_moving_ciphertext_to_another_storage_context_fails(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(
            keystore,
            b"payload",
            aad = storage_aad(b"msg-1"),
        )

        with pytest.raises(AuthenticationError):
            decrypt_storage_field(
                keystore,
                encrypted,
                aad = storage_aad(b"msg-2"),
            )


class TestStorageCryptoFailureCases:
    def test_corrupted_ciphertext_raises_authentication_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        corrupted = corrupt_nested_ciphertext(encrypted)

        with pytest.raises(AuthenticationError):
            decrypt_storage_field(keystore, corrupted, aad = storage_aad())

    def test_malformed_envelope_raises_malformed_data_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        with pytest.raises(MalformedDataError):
            decrypt_storage_field(keystore, b"{not-json", aad = storage_aad())

    def test_unsupported_envelope_version_raises_unsupported_format_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        data = decode_envelope(encrypted)
        data["version"] = 999

        with pytest.raises(UnsupportedFormatError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    def test_unsupported_envelope_type_raises_unsupported_format_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        data = decode_envelope(encrypted)
        data["type"] = "wrong-type"

        with pytest.raises(UnsupportedFormatError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    def test_unsupported_envelope_algorithm_raises_unsupported_format_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        data = decode_envelope(encrypted)
        data["algorithm"] = "wrong-algorithm"

        with pytest.raises(UnsupportedFormatError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    def test_envelope_without_key_id_raises_malformed_data_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        data = decode_envelope(encrypted)
        del data["key_id"]

        with pytest.raises(MalformedDataError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    def test_envelope_with_invalid_key_id_raises_malformed_data_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        data = decode_envelope(encrypted)
        data["key_id"] = "not-a-uuid"

        with pytest.raises(MalformedDataError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    def test_decrypt_with_missing_key_id_in_keystore_raises_key_not_found_error(
            self,
            tmp_path,
    ) -> None:
        aad = storage_aad(b"missing-key")

        writer = FileKeyStore(
            tmp_path / "writer",
            PasswordProtector(password = "writer password"),
        )
        writer.create_new()
        writer.generate_key(KeyKind.SYMMETRIC)

        encrypted = encrypt_storage_field(writer, b"payload", aad = aad)

        reader = FileKeyStore(
            tmp_path / "reader",
            PasswordProtector(password = "reader password"),
        )
        reader.create_new()
        reader.generate_key(KeyKind.SYMMETRIC)

        with pytest.raises(KeyNotFoundError):
            decrypt_storage_field(reader, encrypted, aad = aad)

    def test_encrypt_with_non_symmetric_key_raises_wrong_key_type_error(
            self,
            keystore: FileKeyStore,
    ) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)

        with pytest.raises(WrongKeyTypeError):
            encrypt_storage_field(
                keystore,
                b"payload",
                aad = storage_aad(b"non-symmetric-encrypt"),
                key_id = key_id,
            )

    def test_decrypt_with_non_symmetric_envelope_key_raises_wrong_key_type_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
    ) -> None:
        encrypted = encrypt_storage_field(keystore, b"payload", aad = storage_aad())
        non_symmetric_key_id = keystore.generate_key(KeyKind.X25519)

        data = decode_envelope(encrypted)
        data["key_id"] = str(non_symmetric_key_id)

        with pytest.raises(WrongKeyTypeError):
            decrypt_storage_field(keystore, encode_envelope(data), aad = storage_aad())

    @pytest.mark.parametrize("bad_keystore", [None, object(), "keystore"])
    def test_encrypt_rejects_invalid_keystore_object(self, bad_keystore) -> None:
        with pytest.raises(InvalidInputError):
            encrypt_storage_field(
                bad_keystore,
                b"payload",
                aad = storage_aad(b"invalid-keystore-encrypt"),
            )

    @pytest.mark.parametrize("bad_keystore", [None, object(), "keystore"])
    def test_decrypt_rejects_invalid_keystore_object(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
            bad_keystore,
    ) -> None:
        encrypted = encrypt_storage_field(
            keystore,
            b"payload",
            aad = storage_aad(b"invalid-keystore-decrypt"),
        )

        with pytest.raises(InvalidInputError):
            decrypt_storage_field(bad_keystore, encrypted, aad = storage_aad(b"invalid-keystore-decrypt"))

    def test_encrypt_with_unloaded_keystore_raises_keystore_not_loaded_error(
            self,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)
        key_id = KeyIdHelpers.new_key_id()

        with pytest.raises(KeystoreNotLoadedError):
            encrypt_storage_field(
                store,
                b"payload",
                aad = storage_aad(b"unloaded-encrypt"),
                key_id = key_id,
            )

    def test_decrypt_with_unloaded_keystore_raises_keystore_not_loaded_error(
            self,
            keystore: FileKeyStore,
            symmetric_key_id,
            keystore_path,
            protector: PasswordProtector,
    ) -> None:
        aad = storage_aad(b"unloaded-decrypt")
        encrypted = encrypt_storage_field(keystore, b"payload", aad = aad)
        unloaded = FileKeyStore(keystore_path, protector)

        with pytest.raises(KeystoreNotLoadedError):
            decrypt_storage_field(unloaded, encrypted, aad = aad)

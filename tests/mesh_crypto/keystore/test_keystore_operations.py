from __future__ import annotations

import pytest

from mesh_crypto.core import (
    KeyIdHelpers,
    KeyKind,
    SigningKeySerializer,
    SIGNING_CONTEXT_METADATA,
)
from mesh_crypto.errors import (
    InvalidInputError,
    KeystoreNotLoadedError,
    WrongKeyTypeError,
)
from mesh_crypto.keystore import FileKeyStore, PasswordProtector, sign_with_key
from mesh_crypto.primitives import verify


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


def assert_signature_valid(
    keystore: FileKeyStore,
    key_id,
    *,
    context: bytes,
    data: bytes,
    signature: bytes,
) -> None:
    key_bytes, _meta = keystore.get_key(key_id)
    key_pair = SigningKeySerializer.restore_pair_from_private_bytes(key_bytes)

    verify(context, data, signature, key_pair.pk)


class TestSignWithKeySuccess:
    def test_sign_with_ed25519_key_returns_valid_signature(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)
        context = SIGNING_CONTEXT_METADATA
        data = b"metadata payload"

        signature = sign_with_key(
            keystore,
            key_id,
            context = context,
            data = data,
        )

        assert isinstance(signature, bytes)
        assert len(signature) > 0

        assert_signature_valid(
            keystore,
            key_id,
            context = context,
            data = data,
            signature = signature,
        )


class TestSignWithKeyKeystoreLifecycle:
    def test_uninitialized_keystore_raises_keystore_not_loaded_error(
        self,
        keystore_path,
        protector: PasswordProtector,
    ) -> None:
        store = FileKeyStore(keystore_path, protector)

        with pytest.raises(KeystoreNotLoadedError):
            sign_with_key(
                store,
                KeyIdHelpers.new_key_id(),
                context = SIGNING_CONTEXT_METADATA,
                data = b"payload",
            )


class TestSignWithKeyWrongKeyKind:
    @pytest.mark.parametrize("kind", [KeyKind.SYMMETRIC, KeyKind.X25519])
    def test_non_ed25519_key_raises_wrong_key_type_error(
        self,
        keystore: FileKeyStore,
        kind: KeyKind,
    ) -> None:
        key_id = keystore.generate_key(kind)

        with pytest.raises(WrongKeyTypeError):
            sign_with_key(
                keystore,
                key_id,
                context = SIGNING_CONTEXT_METADATA,
                data = b"payload",
            )


class TestSignWithKeyKeyIdNormalization:
    def test_accepts_key_id_object(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)
        context = SIGNING_CONTEXT_METADATA
        data = b"payload"

        signature = sign_with_key(
            keystore,
            key_id,
            context = context,
            data = data,
        )

        assert_signature_valid(
            keystore,
            key_id,
            context = context,
            data = data,
            signature = signature,
        )

    def test_accepts_key_id_string(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)
        context = SIGNING_CONTEXT_METADATA
        data = b"payload"

        signature = sign_with_key(
            keystore,
            str(key_id),
            context = context,
            data = data,
        )

        assert_signature_valid(
            keystore,
            key_id,
            context = context,
            data = data,
            signature = signature,
        )

    def test_accepts_key_id_bytes(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)
        context = SIGNING_CONTEXT_METADATA
        data = b"payload"

        signature = sign_with_key(
            keystore,
            KeyIdHelpers.key_id_to_bytes(key_id),
            context = context,
            data = data,
        )

        assert_signature_valid(
            keystore,
            key_id,
            context = context,
            data = data,
            signature = signature,
        )


class TestSignWithKeyDelegatedInputValidation:
    def test_empty_context_raises_invalid_input_error(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)

        with pytest.raises(InvalidInputError):
            sign_with_key(
                keystore,
                key_id,
                context = b"",
                data = b"payload",
            )

    def test_non_bytes_data_raises_invalid_input_error(self, keystore: FileKeyStore) -> None:
        key_id = keystore.generate_key(KeyKind.ED25519)

        with pytest.raises(InvalidInputError):
            sign_with_key(
                keystore,
                key_id,
                context = SIGNING_CONTEXT_METADATA,
                data = "not-bytes",
            )
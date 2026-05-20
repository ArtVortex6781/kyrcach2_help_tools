from __future__ import annotations

import uuid

import pytest

from mesh_node_db import (
    CallableStorageCryptoProvider,
    EncryptedFieldConfigurationError,
    EncryptedFieldError,
    InvalidRecordError,
    NodeDBCryptoAdapter,
    StorageCryptoConfigurationError,
    StorageCryptoProviderError,
)
from mesh_node_db.crypto_adapter import build_storage_field_aad


class EchoStorageProvider:
    def __init__(self) -> None:
        self.encrypt_calls: list[dict[str, object]] = []
        self.decrypt_calls: list[dict[str, object]] = []

    def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
        self.encrypt_calls.append(
            {
                "plaintext": plaintext,
                "aad": aad,
                "key_id": key_id,
            }
        )
        return b"encrypted:" + plaintext

    def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
        self.decrypt_calls.append(
            {
                "envelope": envelope,
                "aad": aad,
            }
        )
        prefix = b"encrypted:"
        if envelope.startswith(prefix):
            return envelope[len(prefix):]
        return envelope


class FailingProvider:
    def __init__(self, *, operation: str, cause_type: str = "ProviderFailure") -> None:
        self.operation = operation
        self.cause_type = cause_type

    def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
        raise StorageCryptoProviderError(
            "provider encrypt failed",
            operation = "encrypt",
            cause_type = self.cause_type,
        )

    def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
        raise StorageCryptoProviderError(
            "provider decrypt failed",
            operation = "decrypt",
            cause_type = self.cause_type,
        )


class InvalidUtf8Provider:
    def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
        return b"encrypted"

    def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
        return b"\xff\xfe\xfd"


class TestBuildStorageFieldAAD:
    @staticmethod
    def frame(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    def test_build_storage_field_aad_is_stable(self) -> None:
        first = build_storage_field_aad("peers", "display_name", "peer-1")
        second = build_storage_field_aad("peers", "display_name", "peer-1")

        assert first == second
        assert first == (
                self.frame(b"mesh_node_db:v1")
                + self.frame(b"peers")
                + self.frame(b"display_name")
                + self.frame(b"peer-1")
        )

    def test_build_storage_field_aad_accepts_bytes_record_id(self) -> None:
        aad = build_storage_field_aad("messages", "payload", b"msg-1")

        assert aad == (
                self.frame(b"mesh_node_db:v1")
                + self.frame(b"messages")
                + self.frame(b"payload")
                + self.frame(b"msg-1")
        )

    def test_build_storage_field_aad_differs_by_table(self) -> None:
        peer_aad = build_storage_field_aad("peers", "display_name", "record-1")
        chat_aad = build_storage_field_aad("chats", "chat_name", "record-1")

        assert peer_aad != chat_aad

    def test_build_storage_field_aad_differs_by_field(self) -> None:
        message_aad = build_storage_field_aad("messages", "payload", "record-1")
        peer_aad = build_storage_field_aad("peers", "display_name", "record-1")

        assert message_aad != peer_aad

    def test_build_storage_field_aad_differs_by_record_id(self) -> None:
        first = build_storage_field_aad("messages", "payload", "msg-1")
        second = build_storage_field_aad("messages", "payload", "msg-2")

        assert first != second

    def test_framing_prevents_ambiguous_aad_composition(self) -> None:
        first = build_storage_field_aad("peers", "display_name", "ab")
        second = build_storage_field_aad("peers", "display_name", "a" + "b")

        assert first == second

        different_table_field_split = (
                self.frame(b"mesh_node_db:v1")
                + self.frame(b"peer")
                + self.frame(b"sdisplay_name")
                + self.frame(b"ab")
        )

        assert first != different_table_field_split

    @pytest.mark.parametrize(
        ("table", "field"),
        [
            ("attachments", "file_path"),
            ("peers", "public_key"),
            ("chats", "chat_type"),
            ("messages", "sender_id"),
        ],
    )
    def test_unsupported_table_field_pair_raises_encrypted_field_configuration_error(
            self,
            table: str,
            field: str,
    ) -> None:
        with pytest.raises(EncryptedFieldConfigurationError):
            build_storage_field_aad(table, field, "record-1")

    @pytest.mark.parametrize(
        ("table", "field", "record_id"),
        [
            ("", "display_name", "peer-1"),
            ("peers", "", "peer-1"),
            ("peers", "display_name", ""),
            ("peers", "display_name", b""),
            ("peers", "display_name", None),
            (b"peers", "display_name", "peer-1"),
            ("peers", b"display_name", "peer-1"),
        ],
    )
    def test_invalid_aad_inputs_raise_invalid_record_error(
            self,
            table,
            field,
            record_id,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            build_storage_field_aad(table, field, record_id)


class TestCallableStorageCryptoProviderConfiguration:
    def test_valid_configuration_can_be_created(self) -> None:
        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        assert provider is not None

    def test_none_keystore_raises_storage_crypto_configuration_error(self) -> None:
        with pytest.raises(StorageCryptoConfigurationError):
            CallableStorageCryptoProvider(
                keystore = None,
                encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
                decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
            )

    def test_non_callable_encrypt_raises_storage_crypto_configuration_error(self) -> None:
        with pytest.raises(StorageCryptoConfigurationError):
            CallableStorageCryptoProvider(
                keystore = object(),
                encrypt_storage_field = object(),
                decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
            )

    def test_non_callable_decrypt_raises_storage_crypto_configuration_error(self) -> None:
        with pytest.raises(StorageCryptoConfigurationError):
            CallableStorageCryptoProvider(
                keystore = object(),
                encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
                decrypt_storage_field = object(),
            )


class TestCallableStorageCryptoProviderOperations:
    def test_encrypt_field_calls_configured_encrypt_callable_with_expected_arguments(self) -> None:
        calls: list[dict[str, object]] = []
        keystore = object()
        key_id = uuid.uuid4()

        def encrypt_storage_field(keystore_arg, plaintext: bytes, *, aad: bytes, key_id):
            calls.append(
                {
                    "keystore": keystore_arg,
                    "plaintext": plaintext,
                    "aad": aad,
                    "key_id": key_id,
                }
            )
            return b"encrypted-payload"

        provider = CallableStorageCryptoProvider(
            keystore = keystore,
            encrypt_storage_field = encrypt_storage_field,
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        encrypted = provider.encrypt_field(
            b"payload",
            aad = b"aad",
            key_id = key_id,
        )

        assert encrypted == b"encrypted-payload"
        assert calls == [
            {
                "keystore": keystore,
                "plaintext": b"payload",
                "aad": b"aad",
                "key_id": key_id,
            }
        ]

    def test_decrypt_field_calls_configured_decrypt_callable_with_expected_arguments(self) -> None:
        calls: list[dict[str, object]] = []
        keystore = object()

        def decrypt_storage_field(keystore_arg, envelope: bytes, *, aad: bytes):
            calls.append(
                {
                    "keystore": keystore_arg,
                    "envelope": envelope,
                    "aad": aad,
                }
            )
            return b"plaintext"

        provider = CallableStorageCryptoProvider(
            keystore = keystore,
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = decrypt_storage_field,
        )

        plaintext = provider.decrypt_field(
            b"encrypted",
            aad = b"aad",
        )

        assert plaintext == b"plaintext"
        assert calls == [
            {
                "keystore": keystore,
                "envelope": b"encrypted",
                "aad": b"aad",
            }
        ]

    def test_encrypt_callable_failure_is_wrapped_as_storage_crypto_provider_error(self) -> None:
        def encrypt_storage_field(keystore, plaintext: bytes, *, aad: bytes, key_id):
            raise RuntimeError("boom")

        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = encrypt_storage_field,
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        with pytest.raises(StorageCryptoProviderError) as exc_info:
            provider.encrypt_field(
                b"payload",
                aad = b"aad",
                key_id = uuid.uuid4(),
            )

        assert exc_info.value.operation == "encrypt"
        assert exc_info.value.cause_type == "RuntimeError"

    def test_decrypt_callable_failure_is_wrapped_as_storage_crypto_provider_error(self) -> None:
        def decrypt_storage_field(keystore, envelope: bytes, *, aad: bytes):
            raise ValueError("boom")

        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = decrypt_storage_field,
        )

        with pytest.raises(StorageCryptoProviderError) as exc_info:
            provider.decrypt_field(
                b"encrypted",
                aad = b"aad",
            )

        assert exc_info.value.operation == "decrypt"
        assert exc_info.value.cause_type == "ValueError"

    def test_encrypt_callable_non_bytes_output_raises_storage_crypto_provider_error(self) -> None:
        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: "not-bytes",
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        with pytest.raises(StorageCryptoProviderError) as exc_info:
            provider.encrypt_field(
                b"payload",
                aad = b"aad",
                key_id = uuid.uuid4(),
            )

        assert exc_info.value.operation == "encrypt"
        assert exc_info.value.cause_type == "InvalidProviderOutput"

    def test_decrypt_callable_non_bytes_output_raises_storage_crypto_provider_error(self) -> None:
        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = lambda keystore, envelope, *, aad: "not-bytes",
        )

        with pytest.raises(StorageCryptoProviderError) as exc_info:
            provider.decrypt_field(
                b"encrypted",
                aad = b"aad",
            )

        assert exc_info.value.operation == "decrypt"
        assert exc_info.value.cause_type == "InvalidProviderOutput"

    @pytest.mark.parametrize(
        ("plaintext", "aad", "key_id"),
        [
            ("payload", b"aad", uuid.uuid4()),
            (b"payload", b"", uuid.uuid4()),
            (b"payload", b"aad", None),
            (b"payload", b"aad", ""),
            (b"payload", b"aad", b""),
            (b"payload", b"aad", object()),
        ],
    )
    def test_encrypt_field_invalid_inputs_raise_expected_configuration_or_record_error(
            self,
            plaintext,
            aad,
            key_id,
    ) -> None:
        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        expected_error = (
            StorageCryptoConfigurationError
            if key_id in (None, "", b"") or not isinstance(key_id, (uuid.UUID, str, bytes))
            else InvalidRecordError
        )

        with pytest.raises(expected_error):
            provider.encrypt_field(
                plaintext,
                aad = aad,
                key_id = key_id,
            )

    @pytest.mark.parametrize(
        ("envelope", "aad"),
        [
            ("encrypted", b"aad"),
            (b"encrypted", b""),
        ],
    )
    def test_decrypt_field_invalid_inputs_raise_invalid_record_error(
            self,
            envelope,
            aad,
    ) -> None:
        provider = CallableStorageCryptoProvider(
            keystore = object(),
            encrypt_storage_field = lambda keystore, plaintext, *, aad, key_id: b"encrypted",
            decrypt_storage_field = lambda keystore, envelope, *, aad: b"plaintext",
        )

        with pytest.raises(InvalidRecordError):
            provider.decrypt_field(envelope, aad = aad)


class TestNodeDBCryptoAdapterConfiguration:
    def test_valid_configuration_can_be_created(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        assert adapter is not None

    def test_none_provider_raises_storage_crypto_configuration_error(self) -> None:
        with pytest.raises(StorageCryptoConfigurationError):
            NodeDBCryptoAdapter(
                provider = None,
                active_storage_key_id = uuid.uuid4(),
            )

    @pytest.mark.parametrize("bad_key_id", [None, "", b"", object()])
    def test_invalid_active_storage_key_id_raises_storage_crypto_configuration_error(
            self,
            bad_key_id,
    ) -> None:
        with pytest.raises(StorageCryptoConfigurationError):
            NodeDBCryptoAdapter(
                provider = EchoStorageProvider(),
                active_storage_key_id = bad_key_id,
            )


class TestNodeDBCryptoAdapterPeerDisplayName:
    def test_encrypt_and_decrypt_peer_display_name_roundtrip(self) -> None:
        provider = EchoStorageProvider()
        key_id = uuid.uuid4()
        adapter = NodeDBCryptoAdapter(
            provider = provider,
            active_storage_key_id = key_id,
        )

        encrypted = adapter.encrypt_peer_display_name("peer-1", "Alice")
        decrypted = adapter.decrypt_peer_display_name("peer-1", encrypted)

        expected_aad = build_storage_field_aad("peers", "display_name", "peer-1")

        assert encrypted == b"encrypted:Alice"
        assert decrypted == "Alice"
        assert provider.encrypt_calls[-1] == {
            "plaintext": b"Alice",
            "aad": expected_aad,
            "key_id": key_id,
        }
        assert provider.decrypt_calls[-1] == {
            "envelope": encrypted,
            "aad": expected_aad,
        }

    @pytest.mark.parametrize(
        ("peer_id", "display_name"),
        [
            ("", "Alice"),
            ("peer-1", ""),
            ("peer-1", b"Alice"),
        ],
    )
    def test_encrypt_peer_display_name_invalid_inputs_raise_invalid_record_error(
            self,
            peer_id,
            display_name,
    ) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(InvalidRecordError):
            adapter.encrypt_peer_display_name(peer_id, display_name)

    def test_decrypt_peer_display_name_invalid_utf8_raises_encrypted_field_error(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = InvalidUtf8Provider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.decrypt_peer_display_name("peer-1", b"encrypted")

        assert exc_info.value.field_name == "peers.display_name"
        assert exc_info.value.operation == "decode"
        assert exc_info.value.cause_type == "UnicodeDecodeError"


class TestNodeDBCryptoAdapterChatName:
    def test_encrypt_and_decrypt_chat_name_roundtrip(self) -> None:
        provider = EchoStorageProvider()
        key_id = uuid.uuid4()
        adapter = NodeDBCryptoAdapter(
            provider = provider,
            active_storage_key_id = key_id,
        )

        encrypted = adapter.encrypt_chat_name("chat-1", "Direct chat")
        decrypted = adapter.decrypt_chat_name("chat-1", encrypted)

        expected_aad = build_storage_field_aad("chats", "chat_name", "chat-1")

        assert encrypted == b"encrypted:Direct chat"
        assert decrypted == "Direct chat"
        assert provider.encrypt_calls[-1] == {
            "plaintext": b"Direct chat",
            "aad": expected_aad,
            "key_id": key_id,
        }
        assert provider.decrypt_calls[-1] == {
            "envelope": encrypted,
            "aad": expected_aad,
        }

    @pytest.mark.parametrize(
        ("chat_id", "chat_name"),
        [
            ("", "Direct chat"),
            ("chat-1", ""),
            ("chat-1", None),
            ("chat-1", b"Direct chat"),
        ],
    )
    def test_encrypt_chat_name_invalid_inputs_raise_invalid_record_error(
            self,
            chat_id,
            chat_name,
    ) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(InvalidRecordError):
            adapter.encrypt_chat_name(chat_id, chat_name)

    @pytest.mark.parametrize(
        ("chat_id", "envelope"),
        [
            ("", b"encrypted"),
            ("chat-1", "encrypted"),
            ("chat-1", None),
        ],
    )
    def test_decrypt_chat_name_invalid_inputs_raise_invalid_record_error(
            self,
            chat_id,
            envelope,
    ) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(InvalidRecordError):
            adapter.decrypt_chat_name(chat_id, envelope)

    def test_decrypt_chat_name_invalid_utf8_raises_encrypted_field_error(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = InvalidUtf8Provider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.decrypt_chat_name("chat-1", b"encrypted")

        assert exc_info.value.field_name == "chats.chat_name"
        assert exc_info.value.operation == "decode"
        assert exc_info.value.cause_type == "UnicodeDecodeError"


class TestNodeDBCryptoAdapterMessagePayload:
    def test_encrypt_and_decrypt_message_payload_roundtrip(self) -> None:
        provider = EchoStorageProvider()
        key_id = uuid.uuid4()
        adapter = NodeDBCryptoAdapter(
            provider = provider,
            active_storage_key_id = key_id,
        )

        encrypted = adapter.encrypt_message_payload("msg-1", b"\x00hello\xff")
        decrypted = adapter.decrypt_message_payload("msg-1", encrypted)

        expected_aad = build_storage_field_aad("messages", "payload", "msg-1")

        assert encrypted == b"encrypted:\x00hello\xff"
        assert decrypted == b"\x00hello\xff"
        assert provider.encrypt_calls[-1] == {
            "plaintext": b"\x00hello\xff",
            "aad": expected_aad,
            "key_id": key_id,
        }
        assert provider.decrypt_calls[-1] == {
            "envelope": encrypted,
            "aad": expected_aad,
        }

    def test_encrypt_message_payload_accepts_empty_payload(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        encrypted = adapter.encrypt_message_payload("msg-1", b"")
        decrypted = adapter.decrypt_message_payload("msg-1", encrypted)

        assert encrypted == b"encrypted:"
        assert decrypted == b""

    @pytest.mark.parametrize(
        ("message_id", "payload"),
        [
            ("", b"payload"),
            ("msg-1", "payload"),
        ],
    )
    def test_encrypt_message_payload_invalid_inputs_raise_invalid_record_error(
            self,
            message_id,
            payload,
    ) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(InvalidRecordError):
            adapter.encrypt_message_payload(message_id, payload)

    @pytest.mark.parametrize(
        ("message_id", "envelope"),
        [
            ("", b"encrypted"),
            ("msg-1", "encrypted"),
            ("msg-1", None),
        ],
    )
    def test_decrypt_message_payload_invalid_inputs_raise_invalid_record_error(
            self,
            message_id,
            envelope,
    ) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = EchoStorageProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(InvalidRecordError):
            adapter.decrypt_message_payload(message_id, envelope)


class TestNodeDBCryptoAdapterErrorWrapping:
    def test_provider_encrypt_failure_is_wrapped_as_encrypted_field_error(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = FailingProvider(operation = "encrypt", cause_type = "AuthenticationError"),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.encrypt_message_payload("msg-1", b"payload")

        assert exc_info.value.field_name == "messages.payload"
        assert exc_info.value.operation == "encrypt"
        assert exc_info.value.cause_type == "AuthenticationError"

    def test_provider_decrypt_failure_is_wrapped_as_encrypted_field_error(self) -> None:
        adapter = NodeDBCryptoAdapter(
            provider = FailingProvider(operation = "decrypt", cause_type = "AuthenticationError"),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.decrypt_message_payload("msg-1", b"encrypted")

        assert exc_info.value.field_name == "messages.payload"
        assert exc_info.value.operation == "decrypt"
        assert exc_info.value.cause_type == "AuthenticationError"

    def test_unexpected_provider_encrypt_exception_is_wrapped_as_encrypted_field_error(self) -> None:
        class UnexpectedEncryptProvider:
            def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
                raise RuntimeError("unexpected")

            def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
                return b"plaintext"

        adapter = NodeDBCryptoAdapter(
            provider = UnexpectedEncryptProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.encrypt_peer_display_name("peer-1", "Alice")

        assert exc_info.value.field_name == "peers.display_name"
        assert exc_info.value.operation == "encrypt"
        assert exc_info.value.cause_type == "RuntimeError"

    def test_unexpected_provider_decrypt_exception_is_wrapped_as_encrypted_field_error(self) -> None:
        class UnexpectedDecryptProvider:
            def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
                return b"encrypted"

            def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
                raise ValueError("unexpected")

        adapter = NodeDBCryptoAdapter(
            provider = UnexpectedDecryptProvider(),
            active_storage_key_id = uuid.uuid4(),
        )

        with pytest.raises(EncryptedFieldError) as exc_info:
            adapter.decrypt_chat_name("chat-1", b"encrypted")

        assert exc_info.value.field_name == "chats.chat_name"
        assert exc_info.value.operation == "decrypt"
        assert exc_info.value.cause_type == "ValueError"

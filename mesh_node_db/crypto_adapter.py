from __future__ import annotations

from typing import Callable, Protocol
from uuid import UUID

from ._validation import (
    require_bytes,
    require_non_empty_bytes,
    require_non_empty_str,
    require_optional_str,
)
from .errors import (
    EncryptedFieldConfigurationError,
    EncryptedFieldError,
    InvalidRecordError,
    StorageCryptoConfigurationError,
    StorageCryptoProviderError,
)

__all__ = [
    "StorageKeyId",
    "StorageCryptoProvider",
    "CallableStorageCryptoProvider",
    "NodeDBCryptoAdapter",
    "build_storage_field_aad",
]

StorageKeyId = UUID | str | bytes

_ALLOWED_ENCRYPTED_FIELDS = {
    ("messages", "payload"),
    ("peers", "display_name"),
    ("chats", "chat_name"),
}

_AAD_PREFIX = b"mesh_node_db:v1"


class StorageCryptoProvider(Protocol):
    """Protocol for storage-field encryption providers used by mesh_node_db."""

    def encrypt_field(self, plaintext: bytes, *,
                      aad: bytes, key_id: StorageKeyId) -> bytes:
        """
        Encrypt one storage field.

        :param plaintext: plaintext field bytes
        :param aad: authenticated associated data
        :param key_id: active storage encryption key identifier
        :return: encrypted storage envelope bytes
        :raises StorageCryptoProviderError: if provider encryption fails.
        """
        ...

    def decrypt_field(self, envelope: bytes, *,
                      aad: bytes) -> bytes:
        """
        Decrypt one storage field.

        :param envelope: encrypted storage envelope bytes
        :param aad: authenticated associated data
        :return: decrypted plaintext bytes
        :raises StorageCryptoProviderError: if provider decryption fails.
        """
        ...


class CallableStorageCryptoProvider:
    """
    StorageCryptoProvider implementation backed by external callables.

    This class intentionally does not import mesh_crypto. The concrete
    encryption/decryption functions and keystore are injected from outside.
    """

    def __init__(self, *, keystore: object, encrypt_storage_field: Callable[..., bytes],
                 decrypt_storage_field: Callable[..., bytes]) -> None:
        """
        Initialize callable-backed storage crypto provider.

        :param keystore: external keystore object used by the callables
        :param encrypt_storage_field: callable compatible with storage field encryption API
        :param decrypt_storage_field: callable compatible with storage field decryption API
        :raises StorageCryptoConfigurationError: if provider configuration is invalid.
        """
        if keystore is None:
            raise StorageCryptoConfigurationError("keystore must not be None.")
        if not callable(encrypt_storage_field):
            raise StorageCryptoConfigurationError(
                "encrypt_storage_field must be callable."
            )
        if not callable(decrypt_storage_field):
            raise StorageCryptoConfigurationError(
                "decrypt_storage_field must be callable."
            )

        self._keystore = keystore
        self._encrypt_storage_field = encrypt_storage_field
        self._decrypt_storage_field = decrypt_storage_field

    def encrypt_field(self, plaintext: bytes, *,
                      aad: bytes, key_id: StorageKeyId) -> bytes:
        """
        Encrypt one storage field through the configured callable.

        :param plaintext: plaintext field bytes
        :param aad: authenticated associated data
        :param key_id: active storage encryption key identifier
        :return: encrypted storage envelope bytes
        :raises InvalidRecordError: if plaintext or aad is invalid.
        :raises StorageCryptoConfigurationError: if key_id is invalid.
        :raises StorageCryptoProviderError: if provider encryption fails.
        """
        require_bytes(plaintext, field_name = "plaintext")
        require_non_empty_bytes(aad, field_name = "aad")
        _require_key_id(key_id)

        try:
            encrypted = self._encrypt_storage_field(
                self._keystore,
                plaintext,
                aad = aad,
                key_id = key_id,
            )
        except Exception as exc:
            raise StorageCryptoProviderError(
                "Storage field encryption failed.",
                operation = "encrypt",
                cause_type = type(exc).__name__,
            ) from exc

        _require_provider_output_bytes(
            encrypted,
            operation = "encrypt",
            output_name = "encrypted",
        )
        return encrypted

    def decrypt_field(self, envelope: bytes, *,
                      aad: bytes) -> bytes:
        """
        Decrypt one storage field through the configured callable.

        :param envelope: encrypted storage envelope bytes
        :param aad: authenticated associated data
        :return: decrypted plaintext bytes
        :raises InvalidRecordError: if envelope or aad is invalid.
        :raises StorageCryptoProviderError: if provider decryption fails.
        """
        require_bytes(envelope, field_name = "envelope")
        require_non_empty_bytes(aad, field_name = "aad")

        try:
            plaintext = self._decrypt_storage_field(
                self._keystore,
                envelope,
                aad = aad,
            )
        except Exception as exc:
            raise StorageCryptoProviderError(
                "Storage field decryption failed.",
                operation = "decrypt",
                cause_type = type(exc).__name__,
            ) from exc

        _require_provider_output_bytes(
            plaintext,
            operation = "decrypt",
            output_name = "plaintext",
        )
        return plaintext


def build_storage_field_aad(table: str, field: str,
                            record_id: str | bytes) -> bytes:
    """
    Build deterministic AAD for one encrypted mesh_node_db storage field.

    :param table: logical table name
    :param field: logical encrypted field name
    :param record_id: stable record identifier
    :return: authenticated associated data bytes
    :raises InvalidRecordError: if table, field or record_id shape is invalid.
    :raises EncryptedFieldConfigurationError: if encrypted field pair is unsupported.
    """
    require_non_empty_str(table, field_name = "table")
    require_non_empty_str(field, field_name = "field")

    if (table, field) not in _ALLOWED_ENCRYPTED_FIELDS:
        raise EncryptedFieldConfigurationError(
            f"Encrypted field is not supported: {table}.{field}"
        )

    record_id_bytes = _record_id_to_bytes(record_id)

    return b":".join(
        (
            _AAD_PREFIX,
            table.encode("utf-8"),
            field.encode("utf-8"),
            record_id_bytes,
        )
    )


class NodeDBCryptoAdapter:
    """
    DB-specific encrypted-field adapter for mesh_node_db.

    Responsibilities:
    - build AAD for encrypted database fields
    - encrypt/decrypt message payloads
    - encrypt/decrypt peer display names
    - encrypt/decrypt chat names
    - encode/decode logical string fields
    - wrap provider/decode failures into EncryptedFieldError
    """

    def __init__(self, *, provider: StorageCryptoProvider,
                 active_storage_key_id: StorageKeyId) -> None:
        """
        Initialize DB crypto adapter.

        :param provider: storage crypto provider
        :param active_storage_key_id: active storage encryption key identifier
        :raises StorageCryptoConfigurationError: if adapter configuration is invalid.
        """
        if provider is None:
            raise StorageCryptoConfigurationError("provider must not be None.")

        _require_key_id(active_storage_key_id)

        self._provider = provider
        self._active_storage_key_id = active_storage_key_id

    def encrypt_message_payload(self, message_id: str,
                                payload: bytes) -> bytes:
        """
        Encrypt messages.payload.

        :param message_id: stable message identifier
        :param payload: plaintext message payload bytes
        :return: encrypted storage envelope bytes
        :raises InvalidRecordError: if message_id or payload is invalid.
        :raises EncryptedFieldError: if encryption fails.
        """
        require_non_empty_str(message_id, field_name = "message_id")
        require_bytes(payload, field_name = "payload")

        aad = build_storage_field_aad("messages", "payload", message_id)
        return self._encrypt_field(
            payload,
            aad = aad,
            field_name = "messages.payload",
        )

    def decrypt_message_payload(self, message_id: str,
                                envelope: bytes) -> bytes:
        """
        Decrypt messages.payload.

        :param message_id: stable message identifier
        :param envelope: encrypted storage envelope bytes
        :return: plaintext message payload bytes
        :raises InvalidRecordError: if message_id or envelope is invalid.
        :raises EncryptedFieldError: if decryption fails.
        """
        require_non_empty_str(message_id, field_name = "message_id")
        require_bytes(envelope, field_name = "envelope")

        aad = build_storage_field_aad("messages", "payload", message_id)
        return self._decrypt_field(
            envelope,
            aad = aad,
            field_name = "messages.payload",
        )

    def encrypt_peer_display_name(self, peer_id: str,
                                  display_name: str) -> bytes:
        """
        Encrypt peers.display_name.

        :param peer_id: stable peer identifier
        :param display_name: logical peer display name
        :return: encrypted storage envelope bytes
        :raises InvalidRecordError: if peer_id or display_name is invalid.
        :raises EncryptedFieldError: if encryption fails.
        """
        require_non_empty_str(peer_id, field_name = "peer_id")
        require_non_empty_str(display_name, field_name = "display_name")

        plaintext = display_name.encode("utf-8")
        aad = build_storage_field_aad("peers", "display_name", peer_id)

        return self._encrypt_field(
            plaintext,
            aad = aad,
            field_name = "peers.display_name",
        )

    def decrypt_peer_display_name(self, peer_id: str,
                                  envelope: bytes) -> str:
        """
        Decrypt peers.display_name.

        :param peer_id: stable peer identifier
        :param envelope: encrypted storage envelope bytes
        :return: logical peer display name
        :raises InvalidRecordError: if peer_id or envelope is invalid.
        :raises EncryptedFieldError: if decryption or UTF-8 decoding fails.
        """
        require_non_empty_str(peer_id, field_name = "peer_id")
        require_bytes(envelope, field_name = "envelope")

        aad = build_storage_field_aad("peers", "display_name", peer_id)
        plaintext = self._decrypt_field(
            envelope,
            aad = aad,
            field_name = "peers.display_name",
        )

        return self._decode_utf8_field(
            plaintext,
            field_name = "peers.display_name",
        )

    def encrypt_chat_name(self, chat_id: str,
                          chat_name: str | None) -> bytes | None:
        """
        Encrypt chats.chat_name.

        None is stored as SQLite NULL and is not encrypted.

        :param chat_id: stable chat identifier
        :param chat_name: logical chat name or None
        :return: encrypted storage envelope bytes or None
        :raises InvalidRecordError: if chat_id or chat_name is invalid.
        :raises EncryptedFieldError: if encryption fails.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_optional_str(chat_name, field_name = "chat_name")

        if chat_name is None:
            return None

        plaintext = chat_name.encode("utf-8")
        aad = build_storage_field_aad("chats", "chat_name", chat_id)

        return self._encrypt_field(
            plaintext,
            aad = aad,
            field_name = "chats.chat_name",
        )

    def decrypt_chat_name(self, chat_id: str,
                          envelope: bytes | None) -> str | None:
        """
        Decrypt chats.chat_name.

        SQLite NULL is returned as None.

        :param chat_id: stable chat identifier
        :param envelope: encrypted storage envelope bytes or None
        :return: logical chat name or None
        :raises InvalidRecordError: if chat_id or envelope is invalid.
        :raises EncryptedFieldError: if decryption or UTF-8 decoding fails.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")

        if envelope is None:
            return None

        require_bytes(envelope, field_name = "envelope")

        aad = build_storage_field_aad("chats", "chat_name", chat_id)
        plaintext = self._decrypt_field(
            envelope,
            aad = aad,
            field_name = "chats.chat_name",
        )

        return self._decode_utf8_field(
            plaintext,
            field_name = "chats.chat_name",
        )

    def _encrypt_field(self, plaintext: bytes, *,
                       aad: bytes, field_name: str) -> bytes:
        """
        Encrypt one DB field via provider.

        :param plaintext: plaintext field bytes
        :param aad: authenticated associated data
        :param field_name: logical field name for error messages
        :return: encrypted storage envelope bytes
        :raises EncryptedFieldError: if provider encryption fails.
        """
        try:
            return self._provider.encrypt_field(
                plaintext,
                aad = aad,
                key_id = self._active_storage_key_id,
            )
        except StorageCryptoProviderError as exc:
            raise EncryptedFieldError(
                f"Failed to encrypt {field_name}.",
                field_name = field_name,
                operation = "encrypt",
                cause_type = exc.cause_type,
            ) from exc
        except Exception as exc:
            raise EncryptedFieldError(
                f"Unexpected encryption failure for {field_name}.",
                field_name = field_name,
                operation = "encrypt",
                cause_type = type(exc).__name__,
            ) from exc

    def _decrypt_field(self, envelope: bytes, *,
                       aad: bytes, field_name: str) -> bytes:
        """
        Decrypt one DB field via provider.

        :param envelope: encrypted storage envelope bytes
        :param aad: authenticated associated data
        :param field_name: logical field name for error messages
        :return: plaintext field bytes
        :raises EncryptedFieldError: if provider decryption fails.
        """
        try:
            return self._provider.decrypt_field(
                envelope,
                aad = aad,
            )
        except StorageCryptoProviderError as exc:
            raise EncryptedFieldError(
                f"Failed to decrypt {field_name}.",
                field_name = field_name,
                operation = "decrypt",
                cause_type = exc.cause_type,
            ) from exc
        except Exception as exc:
            raise EncryptedFieldError(
                f"Unexpected decryption failure for {field_name}.",
                field_name = field_name,
                operation = "decrypt",
                cause_type = type(exc).__name__,
            ) from exc

    @staticmethod
    def _decode_utf8_field(plaintext: bytes, *,
                           field_name: str) -> str:
        """
        Decode UTF-8 plaintext field.

        :param plaintext: plaintext bytes
        :param field_name: logical field name for error messages
        :return: decoded string
        :raises EncryptedFieldError: if UTF-8 decoding fails.
        """
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EncryptedFieldError(
                f"Failed to decode decrypted {field_name} as UTF-8.",
                field_name = field_name,
                operation = "decode",
                cause_type = type(exc).__name__,
            ) from exc


def _record_id_to_bytes(record_id: str | bytes) -> bytes:
    """
    Convert storage record id to deterministic AAD bytes.

    :param record_id: record identifier
    :return: record identifier bytes
    :raises InvalidRecordError: if record_id is invalid.
    """
    if isinstance(record_id, str):
        require_non_empty_str(record_id, field_name = "record_id")
        return record_id.encode("utf-8")

    if isinstance(record_id, bytes):
        require_non_empty_bytes(record_id, field_name = "record_id")
        return record_id

    raise InvalidRecordError("record_id must be str or bytes.")


def _require_key_id(key_id: object) -> None:
    """
    Validate active storage key identifier presence and supported DB-level type.

    Detailed key id format validation is delegated to the storage crypto provider.

    :param key_id: storage key identifier
    :raises StorageCryptoConfigurationError: if key_id is missing or unsupported.
    """
    if key_id is None:
        raise StorageCryptoConfigurationError(
            "active_storage_key_id must not be None."
        )

    if isinstance(key_id, UUID):
        return

    if isinstance(key_id, str):
        if key_id == "":
            raise StorageCryptoConfigurationError(
                "active_storage_key_id must not be empty."
            )
        return

    if isinstance(key_id, bytes):
        if key_id == b"":
            raise StorageCryptoConfigurationError(
                "active_storage_key_id must not be empty."
            )
        return

    raise StorageCryptoConfigurationError(
        "active_storage_key_id must be UUID, str or bytes."
    )


def _require_provider_output_bytes(value: object, *,
                                   operation: str, output_name: str) -> None:
    """
    Validate provider output bytes.

    :param value: provider output value
    :param operation: provider operation name
    :param output_name: logical provider output name
    :raises StorageCryptoProviderError: if provider output is not bytes.
    """
    if not isinstance(value, bytes):
        raise StorageCryptoProviderError(
            f"Storage crypto provider returned invalid {output_name}.",
            operation = operation,
            cause_type = "InvalidProviderOutput",
        )

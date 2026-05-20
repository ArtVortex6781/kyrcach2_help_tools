from __future__ import annotations

import sqlite3

import pytest

from mesh_crypto.core import KeyKind
from mesh_crypto.keystore import FileKeyStore, PasswordProtector
from mesh_crypto.storage import decrypt_storage_field, encrypt_storage_field

from mesh_node_db import (
    AttachmentRecord,
    CallableStorageCryptoProvider,
    ChatMessageWithSenderRecord,
    ChatParticipantRecord,
    ChatRecord,
    ChatWithParticipantCountRecord,
    ConstraintError,
    EncryptedFieldError,
    InvalidRecordError,
    MessageRecord,
    NodeDatabase,
    NodeDBCryptoAdapter,
    PeerRecord,
)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "node.db"


@pytest.fixture
def storage_keystore(tmp_path) -> FileKeyStore:
    keystore = FileKeyStore(
        tmp_path / "storage-keystore",
        PasswordProtector(password = "correct horse battery staple"),
    )
    keystore.create_new()
    keystore.generate_key(KeyKind.SYMMETRIC)
    return keystore


@pytest.fixture
def crypto_adapter(storage_keystore: FileKeyStore) -> NodeDBCryptoAdapter:
    active_key_id = storage_keystore.get_active_key_id()
    assert active_key_id is not None

    provider = CallableStorageCryptoProvider(
        keystore = storage_keystore,
        encrypt_storage_field = encrypt_storage_field,
        decrypt_storage_field = decrypt_storage_field,
    )

    return NodeDBCryptoAdapter(
        provider = provider,
        active_storage_key_id = active_key_id,
    )


@pytest.fixture
def db(db_path, crypto_adapter: NodeDBCryptoAdapter) -> NodeDatabase:
    database = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
    database.open()
    database.initialize()
    return database


def make_peer(
        peer_id: str,
        display_name: str,
        public_key: bytes | None = None,
        created_at: int = 100,
        updated_at: int = 100,
        is_deleted: bool = False,
        deleted_at: int | None = None,
) -> PeerRecord:
    return PeerRecord(
        peer_id = peer_id,
        display_name = display_name,
        public_key = public_key if public_key is not None else f"pk:{peer_id}".encode(),
        created_at = created_at,
        updated_at = updated_at,
        is_deleted = is_deleted,
        deleted_at = deleted_at,
    )


def make_chat(
        chat_id: str,
        chat_type: str = "group",
        chat_name: str | None = None,
        created_at: int = 100,
        updated_at: int = 100,
) -> ChatRecord:
    return ChatRecord(
        chat_id = chat_id,
        chat_type = chat_type,
        chat_name = chat_name if chat_name is not None else f"chat:{chat_id}",
        created_at = created_at,
        updated_at = updated_at,
    )


def make_participant(chat_id: str, peer_id: str, joined_at: int) -> ChatParticipantRecord:
    return ChatParticipantRecord(
        chat_id = chat_id,
        peer_id = peer_id,
        joined_at = joined_at,
    )


def make_attachment(attachment_hash: str, file_path: str) -> AttachmentRecord:
    return AttachmentRecord(
        attachment_hash = attachment_hash,
        file_path = file_path,
    )


def make_message(
        message_id: str,
        chat_id: str,
        sender_id: str,
        created_at: int,
        updated_at: int,
        payload: bytes = b"payload",
        attachment_hash: str | None = None,
) -> MessageRecord:
    ts = created_at if updated_at is None else updated_at
    return MessageRecord(
        message_id = message_id,
        chat_id = chat_id,
        sender_id = sender_id,
        created_at = created_at,
        updated_at = ts,
        payload = payload,
        attachment_hash = attachment_hash,
    )


def fetch_raw_value(db_path, table_name: str, column_name: str, key_column: str, key_value: str):
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            f"SELECT {column_name} FROM {table_name} WHERE {key_column} = ?",
            (key_value,),
        ).fetchone()
        return None if row is None else row[0]
    finally:
        conn.close()


def overwrite_raw_value(
        db_path,
        *,
        table_name: str,
        column_name: str,
        key_column: str,
        key_value: str,
        value,
) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            f"UPDATE {table_name} SET {column_name} = ? WHERE {key_column} = ?",
            (value, key_value),
        )
        conn.commit()
    finally:
        conn.close()


class TestMessageQueries:
    def test_list_by_chat_returns_only_chat_messages_sorted_desc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.chats.add(make_chat("chat-1"))
        db.chats.add(make_chat("chat-2"))

        msg_a = make_message("msg-a", "chat-1", "peer-1", 100, 100, b"a")
        msg_c = make_message("msg-c", "chat-1", "peer-2", 200, 220, b"c")
        msg_b = make_message("msg-b", "chat-1", "peer-1", 200, 210, b"b")
        other = make_message("msg-z", "chat-2", "peer-1", 999, 999, b"z")

        db.messages.add(msg_a)
        db.messages.add(msg_c)
        db.messages.add(msg_b)
        db.messages.add(other)

        assert db.messages.list_by_chat("chat-1") == [msg_c, msg_b, msg_a]

    def test_list_by_chat_limit_and_pagination_do_not_overlap(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))

        messages = [
            make_message("msg-1", "chat-1", "peer-1", 300, 300, b"1"),
            make_message("msg-3", "chat-1", "peer-1", 200, 230, b"3"),
            make_message("msg-2", "chat-1", "peer-1", 200, 220, b"2"),
            make_message("msg-0", "chat-1", "peer-1", 100, 100, b"0"),
        ]
        for message in messages:
            db.messages.add(message)

        first_page = db.messages.list_by_chat("chat-1", limit = 2)
        cursor = first_page[-1]
        second_page = db.messages.list_by_chat(
            "chat-1",
            limit = 2,
            before_created_at = cursor.created_at,
            before_message_id = cursor.message_id,
        )

        assert first_page == [messages[0], messages[1]]
        assert second_page == [messages[2], messages[3]]
        assert {message.message_id for message in first_page}.isdisjoint(
            {message.message_id for message in second_page}
        )

    def test_list_by_chat_invalid_pagination_arguments_raise_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat("chat-1", before_created_at = 100)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat("chat-1", before_message_id = "msg-1")

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat("chat-1", limit = 0)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat("chat-1", before_created_at = -1, before_message_id = "msg-1")

    def test_list_by_sender_returns_messages_sorted_desc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.chats.add(make_chat("chat-1"))
        db.chats.add(make_chat("chat-2"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, 100, b"a")
        msg_3 = make_message("msg-3", "chat-2", "peer-1", 200, 210, b"c")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 200, 205, b"b")
        msg_other = make_message("msg-x", "chat-1", "peer-2", 500, 500, b"x")

        for message in (msg_1, msg_3, msg_2, msg_other):
            db.messages.add(message)

        assert db.messages.list_by_sender("peer-1") == [msg_3, msg_2, msg_1]

    def test_list_by_chat_and_time_range_is_inclusive_and_sorted_asc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, 100, b"a")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 150, 170, b"b")
        msg_3 = make_message("msg-3", "chat-1", "peer-1", 200, 220, b"c")
        msg_4 = make_message("msg-4", "chat-1", "peer-1", 250, 260, b"d")

        for message in (msg_1, msg_2, msg_3, msg_4):
            db.messages.add(message)

        assert db.messages.list_by_chat_and_time_range("chat-1", 150, 250) == [msg_2, msg_3, msg_4]

    def test_list_by_chat_and_time_range_invalid_range_raises_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_and_time_range("chat-1", 200, 100)

    def test_list_by_chat_and_time_range_negative_timestamps_raise_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_and_time_range("chat-1", -1, 100)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_and_time_range("chat-1", 0, -1)


class TestJoinQueries:
    def test_list_by_chat_with_sender_display_name_returns_projection_records(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.chats.add(make_chat("chat-1"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, 105, b"a")
        msg_3 = make_message("msg-3", "chat-1", "peer-2", 200, 215, b"c")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 200, 210, b"b")

        for message in (msg_1, msg_3, msg_2):
            db.messages.add(message)

        rows = db.messages.list_by_chat_with_sender_display_name("chat-1")

        assert all(isinstance(row, ChatMessageWithSenderRecord) for row in rows)
        assert rows[0].message_id == "msg-3"
        assert rows[0].sender_display_name == "Bob"
        assert rows[0].payload == b"c"
        assert rows[0].updated_at == 215
        assert rows[1].message_id == "msg-2"
        assert rows[1].sender_display_name == "Alice"
        assert rows[1].payload == b"b"
        assert rows[1].updated_at == 210
        assert rows[2].message_id == "msg-1"
        assert rows[2].sender_display_name == "Alice"
        assert rows[2].payload == b"a"
        assert rows[2].updated_at == 105

    def test_list_by_chat_with_sender_display_name_limit_and_pagination(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))

        for message in (
                make_message("msg-1", "chat-1", "peer-1", 300, 300, b"1"),
                make_message("msg-3", "chat-1", "peer-1", 200, 230, b"3"),
                make_message("msg-2", "chat-1", "peer-1", 200, 220, b"2"),
                make_message("msg-0", "chat-1", "peer-1", 100, 100, b"0"),
        ):
            db.messages.add(message)

        first_page = db.messages.list_by_chat_with_sender_display_name("chat-1", limit = 2)
        cursor = first_page[-1]
        second_page = db.messages.list_by_chat_with_sender_display_name(
            "chat-1",
            limit = 2,
            before_created_at = cursor.created_at,
            before_message_id = cursor.message_id,
        )

        assert [row.message_id for row in first_page] == ["msg-1", "msg-3"]
        assert [row.payload for row in first_page] == [b"1", b"3"]
        assert [row.message_id for row in second_page] == ["msg-2", "msg-0"]
        assert [row.payload for row in second_page] == [b"2", b"0"]
        assert {row.message_id for row in first_page}.isdisjoint({row.message_id for row in second_page})

    def test_list_by_chat_with_sender_display_name_invalid_pagination_arguments_raise_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_with_sender_display_name("chat-1", before_created_at = 100)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_with_sender_display_name("chat-1", before_message_id = "msg-1")

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_with_sender_display_name("chat-1", limit = 0)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_with_sender_display_name(
                "chat-1",
                before_created_at = -1,
                before_message_id = "msg-1",
            )

    def test_list_with_participant_count_returns_projection_records_and_zero_counts(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.peers.add(make_peer("peer-3", "Carol"))

        chat_a = make_chat("chat-a", chat_name = "Alpha", created_at = 100, updated_at = 100)
        chat_b = make_chat("chat-b", chat_name = "Beta", created_at = 200, updated_at = 200)
        chat_c = make_chat("chat-c", chat_name = "Gamma", created_at = 300, updated_at = 300)

        db.chats.add(chat_a)
        db.chats.add(chat_b)
        db.chats.add(chat_c)

        db.chat_participants.add(make_participant("chat-a", "peer-1", 10))
        db.chat_participants.add(make_participant("chat-a", "peer-2", 20))
        db.chat_participants.add(make_participant("chat-b", "peer-3", 30))

        rows = db.chats.list_with_participant_count()

        assert all(isinstance(row, ChatWithParticipantCountRecord) for row in rows)
        assert [(row.chat_id, row.chat_name, row.participant_count) for row in rows] == [
            ("chat-a", "Alpha", 2),
            ("chat-b", "Beta", 1),
            ("chat-c", "Gamma", 0),
        ]

    def test_list_with_participant_count_invalid_limit_or_offset_raise_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.chats.list_with_participant_count(limit = 0)

        with pytest.raises(InvalidRecordError):
            db.chats.list_with_participant_count(offset = -1)


class TestRealEncryptedStorageBehavior:
    def test_raw_database_values_are_real_encrypted_storage_envelopes_and_read_as_logical_records(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        peer = make_peer("peer-1", "Alice")
        chat = make_chat("chat-1", chat_name = "Secret chat")
        attachment = make_attachment("hash-1", "/tmp/file.bin")
        message = make_message(
            "msg-1",
            "chat-1",
            "peer-1",
            100,
            100,
            b"\x00binary payload\xff",
            "hash-1",
        )

        db.peers.add(peer)
        db.chats.add(chat)
        db.attachments.add(attachment)
        db.messages.add(message)

        raw_display_name = fetch_raw_value(db_path, "peers", "display_name", "peer_id", "peer-1")
        raw_chat_name = fetch_raw_value(db_path, "chats", "chat_name", "chat_id", "chat-1")
        raw_payload = fetch_raw_value(db_path, "messages", "payload", "message_id", "msg-1")
        raw_file_path = fetch_raw_value(db_path, "attachments", "file_path", "attachment_hash", "hash-1")

        assert isinstance(raw_display_name, bytes)
        assert isinstance(raw_chat_name, bytes)
        assert isinstance(raw_payload, bytes)
        assert raw_display_name != b"Alice"
        assert raw_chat_name != b"Secret chat"
        assert raw_payload != b"\x00binary payload\xff"
        assert raw_file_path == "/tmp/file.bin"

        assert db.peers.read("peer-1") == peer
        assert db.chats.read("chat-1") == chat
        assert db.attachments.read("hash-1") == attachment
        assert db.messages.read("msg-1") == message


class TestEncryptedFieldAadBinding:
    def test_copying_peer_display_name_ciphertext_to_other_peer_fails_decryption(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))

        peer_1_blob = fetch_raw_value(db_path, "peers", "display_name", "peer_id", "peer-1")
        overwrite_raw_value(
            db_path,
            table_name = "peers",
            column_name = "display_name",
            key_column = "peer_id",
            key_value = "peer-2",
            value = peer_1_blob,
        )

        with pytest.raises(EncryptedFieldError):
            db.peers.read("peer-2")

    def test_copying_chat_name_ciphertext_to_other_chat_fails_decryption(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        db.chats.add(make_chat("chat-1", chat_name = "Alpha"))
        db.chats.add(make_chat("chat-2", chat_name = "Beta"))

        chat_1_blob = fetch_raw_value(db_path, "chats", "chat_name", "chat_id", "chat-1")
        overwrite_raw_value(
            db_path,
            table_name = "chats",
            column_name = "chat_name",
            key_column = "chat_id",
            key_value = "chat-2",
            value = chat_1_blob,
        )

        with pytest.raises(EncryptedFieldError):
            db.chats.read("chat-2")

    def test_copying_message_payload_ciphertext_to_other_message_fails_decryption(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))

        db.messages.add(make_message("msg-1", "chat-1", "peer-1", 100, 100, b"one"))
        db.messages.add(make_message("msg-2", "chat-1", "peer-1", 200, 200, b"two"))

        msg_1_blob = fetch_raw_value(db_path, "messages", "payload", "message_id", "msg-1")
        overwrite_raw_value(
            db_path,
            table_name = "messages",
            column_name = "payload",
            key_column = "message_id",
            key_value = "msg-2",
            value = msg_1_blob,
        )

        with pytest.raises(EncryptedFieldError):
            db.messages.read("msg-2")

    def test_copying_peer_display_name_ciphertext_to_chat_name_fails_decryption(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1", chat_name = "Chat"))

        peer_blob = fetch_raw_value(db_path, "peers", "display_name", "peer_id", "peer-1")
        overwrite_raw_value(
            db_path,
            table_name = "chats",
            column_name = "chat_name",
            key_column = "chat_id",
            key_value = "chat-1",
            value = peer_blob,
        )

        with pytest.raises(EncryptedFieldError):
            db.chats.read("chat-1")

    def test_corrupted_message_payload_blob_fails_decryption(
            self,
            db: NodeDatabase,
            db_path,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))
        db.messages.add(make_message("msg-1", "chat-1", "peer-1", 100, 100, b"payload"))

        raw_payload = fetch_raw_value(db_path, "messages", "payload", "message_id", "msg-1")
        corrupted = bytes([raw_payload[0] ^ 0x01]) + raw_payload[1:]

        overwrite_raw_value(
            db_path,
            table_name = "messages",
            column_name = "payload",
            key_column = "message_id",
            key_value = "msg-1",
            value = corrupted,
        )

        with pytest.raises(EncryptedFieldError):
            db.messages.read("msg-1")


class TestConstraintsAndReferentialBehavior:
    def test_add_message_with_missing_chat_raises_constraint_error(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))

        with pytest.raises(ConstraintError):
            db.messages.add(make_message("msg-1", "missing-chat", "peer-1", 100, 100, b"a"))

    def test_add_message_with_missing_sender_raises_constraint_error(self, db: NodeDatabase) -> None:
        db.chats.add(make_chat("chat-1"))

        with pytest.raises(ConstraintError):
            db.messages.add(make_message("msg-1", "chat-1", "missing-peer", 100, 100, b"a"))

    def test_add_participant_with_missing_chat_or_peer_raises_constraint_error(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))

        with pytest.raises(ConstraintError):
            db.chat_participants.add(make_participant("missing-chat", "peer-1", 100))

        with pytest.raises(ConstraintError):
            db.chat_participants.add(make_participant("chat-1", "missing-peer", 100))

    def test_attachment_delete_sets_message_attachment_hash_to_none(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.chats.add(make_chat("chat-1"))
        db.attachments.add(make_attachment("hash-1", "/tmp/file.bin"))
        db.messages.add(make_message("msg-1", "chat-1", "peer-1", 100, 100, b"a", "hash-1"))

        db.attachments.delete("hash-1")

        restored = db.messages.read("msg-1")
        assert restored is not None
        assert restored.attachment_hash is None

    def test_chat_delete_cascades_to_participants_and_messages(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.chats.add(make_chat("chat-1"))

        participant_1 = make_participant("chat-1", "peer-1", 100)
        participant_2 = make_participant("chat-1", "peer-2", 200)
        message_1 = make_message("msg-1", "chat-1", "peer-1", 100, 100, b"a")
        message_2 = make_message("msg-2", "chat-1", "peer-2", 200, 200, b"b")

        db.chat_participants.add(participant_1)
        db.chat_participants.add(participant_2)
        db.messages.add(message_1)
        db.messages.add(message_2)

        db.chats.delete("chat-1")

        assert db.chat_participants.read("chat-1", "peer-1") is None
        assert db.chat_participants.read("chat-1", "peer-2") is None
        assert db.messages.read("msg-1") is None
        assert db.messages.read("msg-2") is None

    def test_soft_delete_peer_keeps_messages_and_removes_memberships(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", "Alice"))
        db.peers.add(make_peer("peer-2", "Bob"))
        db.chats.add(make_chat("chat-1"))

        participant = make_participant("chat-1", "peer-1", 100)
        message = make_message("msg-1", "chat-1", "peer-1", 200, 220, b"hello")

        db.chat_participants.add(participant)
        db.messages.add(message)

        db.peers.soft_delete("peer-1", deleted_at = 300)

        restored_peer = db.peers.read("peer-1")
        restored_message = db.messages.read("msg-1")

        assert restored_peer is not None
        assert restored_peer.is_deleted is True
        assert db.chat_participants.read("chat-1", "peer-1") is None
        assert restored_message == message

from __future__ import annotations

import pytest

from mesh_node_db import (
    AttachmentRecord,
    ChatParticipantRecord,
    ChatRecord,
    InvalidRecordError,
    MessageRecord,
    NodeDatabase,
    PeerRecord,
    RecordNotFoundError,
)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "node.db"


@pytest.fixture
def db(db_path) -> NodeDatabase:
    database = NodeDatabase(str(db_path))
    database.open()
    database.initialize()
    return database


def make_peer(
    peer_id: str,
    display_name: bytes = b"Alice",
    public_key: bytes = b"alice-pk",
    created_at: int = 100,
    updated_at: int = 100,
    is_deleted: bool = False,
    deleted_at: int | None = None,
) -> PeerRecord:
    return PeerRecord(
        peer_id = peer_id,
        display_name = display_name,
        public_key = public_key,
        created_at = created_at,
        updated_at = updated_at,
        is_deleted = is_deleted,
        deleted_at = deleted_at,
    )


def make_chat(
    chat_id: str,
    chat_type: str = "group",
    chat_name: bytes = b"Group chat",
    created_at: int = 200,
    updated_at: int = 200,
) -> ChatRecord:
    return ChatRecord(
        chat_id = chat_id,
        chat_type = chat_type,
        chat_name = chat_name,
        created_at = created_at,
        updated_at = updated_at,
    )


def make_participant(
    chat_id: str,
    peer_id: str,
    joined_at: int = 300,
) -> ChatParticipantRecord:
    return ChatParticipantRecord(
        chat_id = chat_id,
        peer_id = peer_id,
        joined_at = joined_at,
    )


def make_attachment(
    attachment_hash: str,
    file_path: bytes = b"/tmp/file.bin",
) -> AttachmentRecord:
    return AttachmentRecord(
        attachment_hash = attachment_hash,
        file_path = file_path,
    )


def make_message(
    message_id: str,
    chat_id: str,
    sender_id: str,
    created_at: int = 400,
    payload: bytes = b"payload",
    attachment_hash: str | None = None,
) -> MessageRecord:
    return MessageRecord(
        message_id = message_id,
        chat_id = chat_id,
        sender_id = sender_id,
        created_at = created_at,
        payload = payload,
        attachment_hash = attachment_hash,
    )


class TestPeerRepository:
    def test_add_read_update_list_active_and_list_deleted(self, db: NodeDatabase) -> None:
        first = make_peer("peer-1", b"Alice", b"pk-1", 100, 101)
        second = make_peer("peer-2", b"Bob", b"pk-2", 200, 201)

        db.peers.add(first)
        db.peers.add(second)

        assert db.peers.read("peer-1") == first
        assert db.peers.read("peer-2") == second
        assert db.peers.list_active() == [first, second]
        assert db.peers.list_deleted() == []

        updated = make_peer("peer-1", b"Alice Updated", b"pk-1-new", 100, 150)
        db.peers.update(updated)

        restored = db.peers.read("peer-1")
        assert restored == updated
        assert db.peers.list_active() == [updated, second]

    def test_update_does_not_change_created_at(self, db: NodeDatabase) -> None:
        original = make_peer("peer-1", b"Alice", b"pk-1", 100, 110)
        db.peers.add(original)

        db.peers.update(
            make_peer(
                "peer-1",
                b"Alice Updated",
                b"pk-1-new",
                created_at = 300,
                updated_at = 400,
            )
        )

        restored = db.peers.read("peer-1")
        assert restored is not None
        assert restored.created_at == 100
        assert restored.updated_at == 400
        assert restored.display_name == b"Alice Updated"
        assert restored.public_key == b"pk-1-new"

    def test_soft_delete_marks_peer_deleted_removes_memberships_and_keeps_messages(
        self,
        db: NodeDatabase,
    ) -> None:
        peer = make_peer("peer-1", b"Alice", b"pk-1", 100, 100)
        other_peer = make_peer("peer-2", b"Bob", b"pk-2", 110, 110)
        chat = make_chat("chat-1", "group", b"Group", 200, 200)
        participant = make_participant("chat-1", "peer-1", 300)
        message = make_message("msg-1", "chat-1", "peer-1", 400, b"hello")

        db.peers.add(peer)
        db.peers.add(other_peer)
        db.chats.add(chat)
        db.chat_participants.add(participant)
        db.messages.add(message)

        db.peers.soft_delete("peer-1", deleted_at = 500)

        restored_peer = db.peers.read("peer-1")
        restored_message = db.messages.read("msg-1")

        assert restored_peer is not None
        assert restored_peer.is_deleted is True
        assert restored_peer.deleted_at == 500
        assert restored_peer.updated_at == 500
        assert db.chat_participants.read("chat-1", "peer-1") is None
        assert restored_message == message
        assert db.peers.list_active() == [other_peer]
        assert db.peers.list_deleted() == [restored_peer]

    def test_read_missing_returns_none(self, db: NodeDatabase) -> None:
        assert db.peers.read("missing-peer") is None

    def test_update_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.peers.update(make_peer("missing-peer"))

    def test_soft_delete_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.peers.soft_delete("missing-peer", deleted_at = 100)


class TestChatRepository:
    def test_add_read_update_list_all_and_list_by_type(self, db: NodeDatabase) -> None:
        first = make_chat("chat-1", "direct", b"Direct", 100, 101)
        second = make_chat("chat-2", "group", b"Group", 200, 201)
        third = make_chat("chat-3", "group", b"Group 2", 300, 301)

        db.chats.add(first)
        db.chats.add(second)
        db.chats.add(third)

        assert db.chats.read("chat-1") == first
        assert db.chats.read("chat-2") == second
        assert db.chats.list_all() == [first, second, third]
        assert db.chats.list_by_type("group") == [second, third]

        db.chats.update(make_chat("chat-2", "other-type", b"Group Updated", 240, 250))

        restored = db.chats.read("chat-2")
        assert restored is not None
        assert restored.chat_id == "chat-2"
        assert restored.chat_type == "group"
        assert restored.chat_name == b"Group Updated"
        assert restored.created_at == 200
        assert restored.updated_at == 250

    def test_delete_removes_chat(self, db: NodeDatabase) -> None:
        chat = make_chat("chat-1", "group", b"Group", 100, 100)
        db.chats.add(chat)

        db.chats.delete("chat-1")

        assert db.chats.read("chat-1") is None

    def test_read_missing_returns_none(self, db: NodeDatabase) -> None:
        assert db.chats.read("missing-chat") is None

    def test_update_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.chats.update(make_chat("missing-chat"))

    def test_delete_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.chats.delete("missing-chat")


class TestChatParticipantRepository:
    def test_add_read_delete_list_by_chat_and_list_by_peer(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1", "group"))
        db.chats.add(make_chat("chat-2", "group"))

        first = make_participant("chat-1", "peer-1", 100)
        second = make_participant("chat-1", "peer-2", 200)
        third = make_participant("chat-2", "peer-1", 300)

        db.chat_participants.add(first)
        db.chat_participants.add(second)
        db.chat_participants.add(third)

        assert db.chat_participants.read("chat-1", "peer-1") == first
        assert db.chat_participants.read("chat-1", "peer-2") == second
        assert db.chat_participants.list_by_chat("chat-1") == [first, second]
        assert db.chat_participants.list_by_peer("peer-1") == [first, third]

        db.chat_participants.delete("chat-1", "peer-2")

        assert db.chat_participants.read("chat-1", "peer-2") is None
        assert db.chat_participants.list_by_chat("chat-1") == [first]

    def test_read_missing_returns_none(self, db: NodeDatabase) -> None:
        assert db.chat_participants.read("missing-chat", "missing-peer") is None

    def test_delete_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.chat_participants.delete("missing-chat", "missing-peer")


class TestAttachmentRepository:
    def test_add_read_and_delete(self, db: NodeDatabase) -> None:
        attachment = make_attachment("hash-1", b"/tmp/a.bin")

        db.attachments.add(attachment)

        assert db.attachments.read("hash-1") == attachment

        db.attachments.delete("hash-1")

        assert db.attachments.read("hash-1") is None

    def test_read_missing_returns_none(self, db: NodeDatabase) -> None:
        assert db.attachments.read("missing-hash") is None

    def test_delete_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.attachments.delete("missing-hash")


class TestMessageRepository:
    def test_add_read_update_delete(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1", "group"))
        db.attachments.add(make_attachment("hash-1", b"/tmp/a.bin"))
        db.attachments.add(make_attachment("hash-2", b"/tmp/b.bin"))

        original = make_message(
            "msg-1",
            "chat-1",
            "peer-1",
            created_at = 500,
            payload = b"hello",
            attachment_hash = "hash-1",
        )
        db.messages.add(original)

        assert db.messages.read("msg-1") == original

        updated = make_message(
            "msg-1",
            "other-chat-ignored",
            "other-peer-ignored",
            created_at = 999999,
            payload = b"updated payload",
            attachment_hash = "hash-2",
        )
        db.messages.update(updated)

        restored = db.messages.read("msg-1")
        assert restored is not None
        assert restored.message_id == "msg-1"
        assert restored.chat_id == "chat-1"
        assert restored.sender_id == "peer-1"
        assert restored.created_at == 500
        assert restored.payload == b"updated payload"
        assert restored.attachment_hash == "hash-2"

        db.messages.delete("msg-1")

        assert db.messages.read("msg-1") is None

    def test_list_by_sender(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1", "group"))

        first = make_message("msg-1", "chat-1", "peer-1", created_at = 100, payload = b"a")
        second = make_message("msg-2", "chat-1", "peer-1", created_at = 200, payload = b"b")
        third = make_message("msg-3", "chat-1", "peer-2", created_at = 300, payload = b"c")

        db.messages.add(first)
        db.messages.add(second)
        db.messages.add(third)

        assert db.messages.list_by_sender("peer-1") == [second, first]
        assert db.messages.list_by_sender("peer-2") == [third]

    def test_read_missing_returns_none(self, db: NodeDatabase) -> None:
        assert db.messages.read("missing-message") is None

    def test_update_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.messages.update(
                make_message(
                    "missing-message",
                    "chat-1",
                    "peer-1",
                    payload = b"updated",
                )
            )

    def test_delete_missing_raises_record_not_found_error(self, db: NodeDatabase) -> None:
        with pytest.raises(RecordNotFoundError):
            db.messages.delete("missing-message")


class TestRepositoryValidation:
    def test_invalid_identifiers_raise_invalid_record_error(self, db: NodeDatabase) -> None:
        with pytest.raises(InvalidRecordError):
            db.peers.read("")

        with pytest.raises(InvalidRecordError):
            db.chats.read("")

        with pytest.raises(InvalidRecordError):
            db.chat_participants.read("", "peer-1")

        with pytest.raises(InvalidRecordError):
            db.attachments.read("")

        with pytest.raises(InvalidRecordError):
            db.messages.read("")

    def test_invalid_list_arguments_raise_invalid_record_error(self, db: NodeDatabase) -> None:
        with pytest.raises(InvalidRecordError):
            db.peers.list_active(limit = 0)

        with pytest.raises(InvalidRecordError):
            db.peers.list_deleted(offset = -1)

        with pytest.raises(InvalidRecordError):
            db.chats.list_all(limit = 1001)

        with pytest.raises(InvalidRecordError):
            db.chats.list_by_type("", limit = 10)

        with pytest.raises(InvalidRecordError):
            db.messages.list_by_sender("peer-1", limit = 0)
from __future__ import annotations

import pytest

from mesh_node_db import (
    AttachmentRecord,
    ChatMessageWithSenderRecord,
    ChatParticipantRecord,
    ChatRecord,
    ChatWithParticipantCountRecord,
    ConstraintError,
    InvalidRecordError,
    MessageRecord,
    NodeDatabase,
    PeerRecord,
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
        display_name: bytes,
        public_key: bytes | None = None,
        created_at: int = 100,
        updated_at: int = 100,
) -> PeerRecord:
    return PeerRecord(
        peer_id = peer_id,
        display_name = display_name,
        public_key = public_key if public_key is not None else f"pk:{peer_id}".encode(),
        created_at = created_at,
        updated_at = updated_at,
    )


def make_chat(
        chat_id: str,
        chat_type: str = "group",
        chat_name: bytes | None = None,
        created_at: int = 100,
        updated_at: int = 100,
) -> ChatRecord:
    return ChatRecord(
        chat_id = chat_id,
        chat_type = chat_type,
        chat_name = chat_name if chat_name is not None else f"chat:{chat_id}".encode(),
        created_at = created_at,
        updated_at = updated_at,
    )


def make_participant(chat_id: str, peer_id: str, joined_at: int) -> ChatParticipantRecord:
    return ChatParticipantRecord(
        chat_id = chat_id,
        peer_id = peer_id,
        joined_at = joined_at,
    )


def make_attachment(attachment_hash: str, file_path: bytes) -> AttachmentRecord:
    return AttachmentRecord(
        attachment_hash = attachment_hash,
        file_path = file_path,
    )


def make_message(
        message_id: str,
        chat_id: str,
        sender_id: str,
        created_at: int,
        payload: bytes,
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


class TestMessageQueries:
    def test_list_by_chat_returns_only_chat_messages_sorted_desc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1"))
        db.chats.add(make_chat("chat-2"))

        msg_a = make_message("msg-a", "chat-1", "peer-1", 100, b"a")
        msg_c = make_message("msg-c", "chat-1", "peer-2", 200, b"c")
        msg_b = make_message("msg-b", "chat-1", "peer-1", 200, b"b")
        other = make_message("msg-z", "chat-2", "peer-1", 999, b"z")

        db.messages.add(msg_a)
        db.messages.add(msg_c)
        db.messages.add(msg_b)
        db.messages.add(other)

        assert db.messages.list_by_chat("chat-1") == [msg_c, msg_b, msg_a]

    def test_list_by_chat_limit_and_pagination_do_not_overlap(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1"))

        messages = [
            make_message("msg-1", "chat-1", "peer-1", 300, b"1"),
            make_message("msg-3", "chat-1", "peer-1", 200, b"3"),
            make_message("msg-2", "chat-1", "peer-1", 200, b"2"),
            make_message("msg-0", "chat-1", "peer-1", 100, b"0"),
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

    def test_list_by_sender_returns_messages_sorted_desc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1"))
        db.chats.add(make_chat("chat-2"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, b"a")
        msg_3 = make_message("msg-3", "chat-2", "peer-1", 200, b"c")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 200, b"b")
        msg_other = make_message("msg-x", "chat-1", "peer-2", 500, b"x")

        for message in (msg_1, msg_3, msg_2, msg_other):
            db.messages.add(message)

        assert db.messages.list_by_sender("peer-1") == [msg_3, msg_2, msg_1]

    def test_list_by_chat_and_time_range_is_inclusive_and_sorted_asc(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, b"a")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 150, b"b")
        msg_3 = make_message("msg-3", "chat-1", "peer-1", 200, b"c")
        msg_4 = make_message("msg-4", "chat-1", "peer-1", 250, b"d")

        for message in (msg_1, msg_2, msg_3, msg_4):
            db.messages.add(message)

        assert db.messages.list_by_chat_and_time_range("chat-1", 150, 250) == [msg_2, msg_3, msg_4]

    def test_list_by_chat_and_time_range_invalid_range_raises_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.messages.list_by_chat_and_time_range("chat-1", 200, 100)


class TestJoinQueries:
    def test_list_by_chat_with_sender_display_name_returns_projection_records(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1"))

        msg_1 = make_message("msg-1", "chat-1", "peer-1", 100, b"a")
        msg_3 = make_message("msg-3", "chat-1", "peer-2", 200, b"c")
        msg_2 = make_message("msg-2", "chat-1", "peer-1", 200, b"b")

        for message in (msg_1, msg_3, msg_2):
            db.messages.add(message)

        rows = db.messages.list_by_chat_with_sender_display_name("chat-1")

        assert all(isinstance(row, ChatMessageWithSenderRecord) for row in rows)
        assert rows[0].message_id == "msg-3"
        assert rows[0].sender_display_name == b"Bob"
        assert rows[1].message_id == "msg-2"
        assert rows[1].sender_display_name == b"Alice"
        assert rows[2].message_id == "msg-1"
        assert rows[2].sender_display_name == b"Alice"

    def test_list_by_chat_with_sender_display_name_limit_and_pagination(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1"))

        for message in (
                make_message("msg-1", "chat-1", "peer-1", 300, b"1"),
                make_message("msg-3", "chat-1", "peer-1", 200, b"3"),
                make_message("msg-2", "chat-1", "peer-1", 200, b"2"),
                make_message("msg-0", "chat-1", "peer-1", 100, b"0"),
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
        assert [row.message_id for row in second_page] == ["msg-2", "msg-0"]
        assert {row.message_id for row in first_page}.isdisjoint({row.message_id for row in second_page})

    def test_list_with_participant_count_returns_projection_records_and_zero_counts(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.peers.add(make_peer("peer-3", b"Carol"))

        chat_a = make_chat("chat-a", created_at = 100)
        chat_b = make_chat("chat-b", created_at = 200)
        chat_c = make_chat("chat-c", created_at = 300)

        db.chats.add(chat_a)
        db.chats.add(chat_b)
        db.chats.add(chat_c)

        db.chat_participants.add(make_participant("chat-a", "peer-1", 10))
        db.chat_participants.add(make_participant("chat-a", "peer-2", 20))
        db.chat_participants.add(make_participant("chat-b", "peer-3", 30))

        rows = db.chats.list_with_participant_count()

        assert all(isinstance(row, ChatWithParticipantCountRecord) for row in rows)
        assert [(row.chat_id, row.participant_count) for row in rows] == [
            ("chat-a", 2),
            ("chat-b", 1),
            ("chat-c", 0),
        ]

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


class TestConstraintsAndReferentialBehavior:
    def test_add_message_with_missing_chat_raises_constraint_error(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))

        with pytest.raises(ConstraintError):
            db.messages.add(make_message("msg-1", "missing-chat", "peer-1", 100, b"a"))

    def test_add_message_with_missing_sender_raises_constraint_error(self, db: NodeDatabase) -> None:
        db.chats.add(make_chat("chat-1"))

        with pytest.raises(ConstraintError):
            db.messages.add(make_message("msg-1", "chat-1", "missing-peer", 100, b"a"))

    def test_add_participant_with_missing_chat_or_peer_raises_constraint_error(
            self,
            db: NodeDatabase,
    ) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1"))

        with pytest.raises(ConstraintError):
            db.chat_participants.add(make_participant("missing-chat", "peer-1", 100))

        with pytest.raises(ConstraintError):
            db.chat_participants.add(make_participant("chat-1", "missing-peer", 100))

    def test_attachment_delete_sets_message_attachment_hash_to_none(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.chats.add(make_chat("chat-1"))
        db.attachments.add(make_attachment("hash-1", b"/tmp/file.bin"))
        db.messages.add(make_message("msg-1", "chat-1", "peer-1", 100, b"a", "hash-1"))

        db.attachments.delete("hash-1")

        restored = db.messages.read("msg-1")
        assert restored is not None
        assert restored.attachment_hash is None

    def test_chat_delete_cascades_to_participants_and_messages(self, db: NodeDatabase) -> None:
        db.peers.add(make_peer("peer-1", b"Alice"))
        db.peers.add(make_peer("peer-2", b"Bob"))
        db.chats.add(make_chat("chat-1"))

        participant_1 = make_participant("chat-1", "peer-1", 100)
        participant_2 = make_participant("chat-1", "peer-2", 200)
        message_1 = make_message("msg-1", "chat-1", "peer-1", 100, b"a")
        message_2 = make_message("msg-2", "chat-1", "peer-2", 200, b"b")

        db.chat_participants.add(participant_1)
        db.chat_participants.add(participant_2)
        db.messages.add(message_1)
        db.messages.add(message_2)

        db.chats.delete("chat-1")

        assert db.chat_participants.read("chat-1", "peer-1") is None
        assert db.chat_participants.read("chat-1", "peer-2") is None
        assert db.messages.read("msg-1") is None
        assert db.messages.read("msg-2") is None


class TestQueryValidation:
    def test_list_with_participant_count_invalid_limit_or_offset_raise_invalid_record_error(
            self,
            db: NodeDatabase,
    ) -> None:
        with pytest.raises(InvalidRecordError):
            db.chats.list_with_participant_count(limit = 0)

        with pytest.raises(InvalidRecordError):
            db.chats.list_with_participant_count(offset = -1)

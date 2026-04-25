from __future__ import annotations

import dataclasses

import pytest

from mesh_node_db import (
    AttachmentRecord,
    ChatMessageWithSenderRecord,
    ChatParticipantRecord,
    ChatRecord,
    ChatWithParticipantCountRecord,
    InvalidRecordError,
    MessageRecord,
    PeerRecord,
)


class TestPeerRecord:
    def test_create_active_peer_record(self) -> None:
        record = PeerRecord(
            peer_id = "peer-1",
            display_name = b"Alice",
            public_key = b"alice-pk",
            created_at = 100,
            updated_at = 100,
            is_deleted = False,
            deleted_at = None,
        )

        assert record.peer_id == "peer-1"
        assert record.display_name == b"Alice"
        assert record.public_key == b"alice-pk"
        assert record.created_at == 100
        assert record.updated_at == 100
        assert record.is_deleted is False
        assert record.deleted_at is None

    def test_create_deleted_peer_record(self) -> None:
        record = PeerRecord(
            peer_id = "peer-2",
            display_name = b"Bob",
            public_key = b"bob-pk",
            created_at = 100,
            updated_at = 200,
            is_deleted = True,
            deleted_at = 200,
        )

        assert record.is_deleted is True
        assert record.deleted_at == 200

    def test_is_deleted_false_with_deleted_at_raises_invalid_record_error(self) -> None:
        with pytest.raises(InvalidRecordError):
            PeerRecord(
                peer_id = "peer-1",
                display_name = b"Alice",
                public_key = b"alice-pk",
                created_at = 100,
                updated_at = 100,
                is_deleted = False,
                deleted_at = 150,
            )

    def test_is_deleted_true_without_deleted_at_raises_invalid_record_error(self) -> None:
        with pytest.raises(InvalidRecordError):
            PeerRecord(
                peer_id = "peer-1",
                display_name = b"Alice",
                public_key = b"alice-pk",
                created_at = 100,
                updated_at = 100,
                is_deleted = True,
                deleted_at = None,
            )

    def test_updated_at_less_than_created_at_raises_invalid_record_error(self) -> None:
        with pytest.raises(InvalidRecordError):
            PeerRecord(
                peer_id = "peer-1",
                display_name = b"Alice",
                public_key = b"alice-pk",
                created_at = 200,
                updated_at = 100,
                is_deleted = False,
                deleted_at = None,
            )

    def test_is_deleted_must_be_bool(self) -> None:
        with pytest.raises(InvalidRecordError):
            PeerRecord(
                peer_id = "peer-1",
                display_name = b"Alice",
                public_key = b"alice-pk",
                created_at = 100,
                updated_at = 100,
                is_deleted = 0,
                deleted_at = None,
            )


class TestOtherRecords:
    def test_chat_record_creation_and_frozen_behavior(self) -> None:
        record = ChatRecord(
            chat_id = "chat-1",
            chat_type = "group",
            chat_name = b"Group",
            created_at = 100,
            updated_at = 101,
        )

        assert record.chat_id == "chat-1"
        assert record.chat_type == "group"
        assert record.chat_name == b"Group"

        with pytest.raises(dataclasses.FrozenInstanceError):
            record.chat_name = b"Other"

    def test_chat_record_updated_at_must_be_greater_or_equal_created_at(self) -> None:
        with pytest.raises(InvalidRecordError):
            ChatRecord(
                chat_id = "chat-1",
                chat_type = "group",
                chat_name = b"Group",
                created_at = 200,
                updated_at = 100,
            )

    def test_chat_participant_record_joined_at_must_be_non_negative(self) -> None:
        with pytest.raises(InvalidRecordError):
            ChatParticipantRecord(
                chat_id = "chat-1",
                peer_id = "peer-1",
                joined_at = -1,
            )

    def test_message_record_creation(self) -> None:
        record = MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "peer-1",
            created_at = 100,
            payload = b"hello",
            attachment_hash = None,
        )

        assert record.message_id == "msg-1"
        assert record.chat_id == "chat-1"
        assert record.sender_id == "peer-1"
        assert record.payload == b"hello"
        assert record.attachment_hash is None

    def test_message_record_negative_created_at_raises_invalid_record_error(self) -> None:
        with pytest.raises(InvalidRecordError):
            MessageRecord(
                message_id = "msg-1",
                chat_id = "chat-1",
                sender_id = "peer-1",
                created_at = -1,
                payload = b"hello",
                attachment_hash = None,
            )

    def test_attachment_record_creation(self) -> None:
        record = AttachmentRecord(
            attachment_hash = "hash-1",
            file_path = b"/tmp/file.bin",
        )

        assert record.attachment_hash == "hash-1"
        assert record.file_path == b"/tmp/file.bin"

    def test_chat_message_with_sender_record_creation(self) -> None:
        record = ChatMessageWithSenderRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "peer-1",
            sender_display_name = b"Alice",
            created_at = 100,
            payload = b"hello",
            attachment_hash = None,
        )

        assert record.sender_display_name == b"Alice"
        assert record.payload == b"hello"

    def test_chat_with_participant_count_record_creation(self) -> None:
        record = ChatWithParticipantCountRecord(
            chat_id = "chat-1",
            chat_type = "group",
            chat_name = b"Group",
            created_at = 100,
            updated_at = 100,
            participant_count = 2,
        )

        assert record.chat_id == "chat-1"
        assert record.participant_count == 2

    def test_chat_with_participant_count_negative_count_raises_invalid_record_error(self) -> None:
        with pytest.raises(InvalidRecordError):
            ChatWithParticipantCountRecord(
                chat_id = "chat-1",
                chat_type = "group",
                chat_name = b"Group",
                created_at = 100,
                updated_at = 100,
                participant_count = -1,
            )

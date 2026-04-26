from __future__ import annotations

import pytest

from mesh_node_db import (
    ChatParticipantRecord,
    ChatRecord,
    ConstraintError,
    MessageRecord,
    NodeDatabase,
    PeerRecord,
    TransactionError,
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
        created_at: int = 100,
        updated_at: int | None = None,
        is_deleted: bool = False,
        deleted_at: int | None = None,
) -> PeerRecord:
    ts = created_at if updated_at is None else updated_at
    return PeerRecord(
        peer_id = peer_id,
        display_name = display_name,
        public_key = f"pk:{peer_id}".encode(),
        created_at = created_at,
        updated_at = ts,
        is_deleted = is_deleted,
        deleted_at = deleted_at,
    )


def make_chat(
        chat_id: str,
        created_at: int = 100,
        updated_at: int | None = None,
) -> ChatRecord:
    ts = created_at if updated_at is None else updated_at
    return ChatRecord(
        chat_id = chat_id,
        chat_type = "group",
        chat_name = f"chat:{chat_id}".encode(),
        created_at = created_at,
        updated_at = ts,
    )


def make_participant(
        chat_id: str,
        peer_id: str,
        joined_at: int = 100,
) -> ChatParticipantRecord:
    return ChatParticipantRecord(
        chat_id = chat_id,
        peer_id = peer_id,
        joined_at = joined_at,
    )


def make_message(
        message_id: str,
        chat_id: str,
        sender_id: str,
        created_at: int = 100,
        updated_at: int = 100,
        payload: bytes = b"payload",
) -> MessageRecord:
    ts = created_at if updated_at is None else updated_at
    return MessageRecord(
        message_id = message_id,
        chat_id = chat_id,
        sender_id = sender_id,
        created_at = created_at,
        updated_at = ts,
        payload = payload,
        attachment_hash = None,
    )


class TestDirectSingleWrites:
    def test_direct_single_writes_work_without_run_in_transaction(self, db: NodeDatabase) -> None:
        peer = make_peer("peer-1", b"Alice")
        chat = make_chat("chat-1")
        message = make_message("msg-1", "chat-1", "peer-1", 200, 200, b"hello")

        db.peers.add(peer)
        db.chats.add(chat)
        db.messages.add(message)

        assert db.peers.read("peer-1") == peer
        assert db.chats.read("chat-1") == chat
        assert db.messages.read("msg-1") == message


class TestRunInTransaction:
    def test_run_in_transaction_success_persists_all_records(self, db: NodeDatabase) -> None:
        peer = make_peer("peer-1", b"Alice")
        chat = make_chat("chat-1")
        participant = make_participant("chat-1", "peer-1", 300)
        message = make_message("msg-1", "chat-1", "peer-1", 400, 400, b"hello")

        def callback(tx: NodeDatabase) -> None:
            tx.peers.add(peer)
            tx.chats.add(chat)
            tx.chat_participants.add(participant)
            tx.messages.add(message)

        db.run_in_transaction(callback)

        assert db.peers.read("peer-1") == peer
        assert db.chats.read("chat-1") == chat
        assert db.chat_participants.read("chat-1", "peer-1") == participant
        assert db.messages.read("msg-1") == message

    def test_run_in_transaction_rolls_back_all_records_on_arbitrary_exception(self, db: NodeDatabase) -> None:
        peer = make_peer("peer-1", b"Alice")
        chat = make_chat("chat-1")
        participant = make_participant("chat-1", "peer-1", 300)
        message = make_message("msg-1", "chat-1", "peer-1", 400, 400, b"hello")

        def callback(tx: NodeDatabase) -> None:
            tx.peers.add(peer)
            tx.chats.add(chat)
            tx.chat_participants.add(participant)
            tx.messages.add(message)
            raise RuntimeError("boom")

        with pytest.raises(TransactionError):
            db.run_in_transaction(callback)

        assert db.peers.read("peer-1") is None
        assert db.chats.read("chat-1") is None
        assert db.chat_participants.read("chat-1", "peer-1") is None
        assert db.messages.read("msg-1") is None

    def test_run_in_transaction_wraps_storage_error_as_transaction_error(self, db: NodeDatabase) -> None:
        peer = make_peer("peer-1", b"Alice")

        def callback(tx: NodeDatabase) -> None:
            tx.peers.add(peer)
            tx.peers.add(peer)

        with pytest.raises(TransactionError) as exc_info:
            db.run_in_transaction(callback)

        assert isinstance(exc_info.value.__cause__, ConstraintError)
        assert db.peers.read("peer-1") is None

    def test_run_in_transaction_wraps_arbitrary_exception_as_transaction_error(self, db: NodeDatabase) -> None:
        def callback(tx: NodeDatabase) -> None:
            tx.peers.add(make_peer("peer-1", b"Alice"))
            raise ValueError("unexpected callback error")

        with pytest.raises(TransactionError) as exc_info:
            db.run_in_transaction(callback)

        assert isinstance(exc_info.value.__cause__, ValueError)
        assert db.peers.read("peer-1") is None

    def test_nested_run_in_transaction_fails_fast_and_rolls_back(self, db: NodeDatabase) -> None:
        def inner(tx: NodeDatabase) -> None:
            tx.peers.add(make_peer("peer-2", b"Bob"))

        def outer(tx: NodeDatabase) -> None:
            tx.peers.add(make_peer("peer-1", b"Alice"))
            tx.run_in_transaction(inner)

        with pytest.raises(TransactionError):
            db.run_in_transaction(outer)

        assert db.peers.read("peer-1") is None
        assert db.peers.read("peer-2") is None

    def test_run_in_transaction_requires_callable(self, db: NodeDatabase) -> None:
        with pytest.raises(TransactionError):
            db.run_in_transaction(None)

    def test_run_in_transaction_soft_delete_rolls_back_membership_removal_and_tombstone(
            self,
            db: NodeDatabase,
    ) -> None:
        peer = make_peer("peer-1", b"Alice", 100, 100)
        other_peer = make_peer("peer-2", b"Bob", 110, 110)
        chat = make_chat("chat-1", 200, 200)
        participant = make_participant("chat-1", "peer-1", 300)
        message = make_message("msg-1", "chat-1", "peer-1", 400, 400, b"hello")

        db.peers.add(peer)
        db.peers.add(other_peer)
        db.chats.add(chat)
        db.chat_participants.add(participant)
        db.messages.add(message)

        def callback(tx: NodeDatabase) -> None:
            tx.peers.soft_delete("peer-1", deleted_at = 500)
            raise RuntimeError("abort after tombstone")

        with pytest.raises(TransactionError):
            db.run_in_transaction(callback)

        restored_peer = db.peers.read("peer-1")
        restored_participant = db.chat_participants.read("chat-1", "peer-1")
        restored_message = db.messages.read("msg-1")

        assert restored_peer == peer
        assert restored_participant == participant
        assert restored_message == message

    def test_run_in_transaction_message_update_rolls_back_updated_at_and_content(
            self,
            db: NodeDatabase,
    ) -> None:
        peer = make_peer("peer-1", b"Alice")
        chat = make_chat("chat-1")
        message = make_message("msg-1", "chat-1", "peer-1", 400, 400, b"hello")

        db.peers.add(peer)
        db.chats.add(chat)
        db.messages.add(message)

        def callback(tx: NodeDatabase) -> None:
            tx.messages.update(
                make_message(
                    "msg-1",
                    "other-chat-ignored",
                    "other-peer-ignored",
                    created_at = 500,
                    updated_at = 700,
                    payload = b"updated",
                )
            )
            raise RuntimeError("abort after message update")

        with pytest.raises(TransactionError):
            db.run_in_transaction(callback)

        restored = db.messages.read("msg-1")
        assert restored == message

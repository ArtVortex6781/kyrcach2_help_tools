from __future__ import annotations

import time
from dataclasses import FrozenInstanceError

import pytest

from mesh_node_db import MessageRecord, NodeDB, NodeDBError


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "node.db"


@pytest.fixture
def opened_db(db_path):
    db = NodeDB(str(db_path))
    db.open()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def initialized_db(db_path):
    db = NodeDB(str(db_path))
    db.open()
    db.initialize()
    try:
        yield db
    finally:
        db.close()


def add_message(
        db: NodeDB,
        message_id: str,
        chat_id: str = "chat-1",
        sender_id: str = "user-1",
        payload: bytes = b"payload",
        created_at: int | None = None,
) -> None:
    db.add_message(
        message_id = message_id,
        chat_id = chat_id,
        sender_id = sender_id,
        payload = payload,
        created_at = created_at,
    )


class TestLifecycle:
    def test_open_creates_database_file_and_is_idempotent(self, db_path) -> None:
        db = NodeDB(str(db_path))

        assert not db_path.exists()

        db.open()
        assert db_path.exists()

        db.open()  # must be safe

        db.close()

    def test_close_is_idempotent(self, db_path) -> None:
        db = NodeDB(str(db_path))

        db.open()
        db.close()
        db.close()  # must be safe

    def test_reopen_initialize_again_preserves_data(self, db_path) -> None:
        db = NodeDB(str(db_path))
        db.open()
        db.initialize()

        add_message(
            db,
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 1_700_000_000,
        )

        db.close()

        db.open()
        db.initialize()

        assert db.get_schema_version() == NodeDB.SCHEMA_VERSION

        record = db.get_message("msg-1")
        assert record is not None
        assert record == MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 1_700_000_000,
        )

        db.close()


class TestSchemaBootstrap:
    def test_initialize_sets_schema_version_for_new_database(self, opened_db: NodeDB) -> None:
        opened_db.initialize()

        assert opened_db.get_schema_version() == NodeDB.SCHEMA_VERSION

    def test_initialize_is_idempotent_for_existing_database(self, opened_db: NodeDB) -> None:
        opened_db.initialize()
        first_version = opened_db.get_schema_version()

        opened_db.initialize()
        second_version = opened_db.get_schema_version()

        assert first_version == NodeDB.SCHEMA_VERSION
        assert second_version == NodeDB.SCHEMA_VERSION

    def test_get_schema_version_raises_if_schema_not_initialized(self, opened_db: NodeDB) -> None:
        with pytest.raises(NodeDBError):
            opened_db.get_schema_version()


class TestMessageRecord:
    def test_message_record_creation_and_fields(self) -> None:
        record = MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"abc",
            created_at = 123,
        )

        assert record.message_id == "msg-1"
        assert record.chat_id == "chat-1"
        assert record.sender_id == "alice"
        assert record.payload == b"abc"
        assert record.created_at == 123

    def test_message_record_is_frozen(self) -> None:
        record = MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"abc",
            created_at = 123,
        )

        with pytest.raises(FrozenInstanceError):
            record.message_id = "msg-2"


class TestAddMessage:
    def test_add_message_persists_and_get_message_returns_same_data(
            self,
            initialized_db: NodeDB,
    ) -> None:
        add_message(
            initialized_db,
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 1_700_000_000,
        )

        record = initialized_db.get_message("msg-1")

        assert record is not None
        assert record == MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 1_700_000_000,
        )

    def test_add_message_duplicate_message_id_raises(self, initialized_db: NodeDB) -> None:
        add_message(initialized_db, message_id = "msg-1")

        with pytest.raises(NodeDBError):
            add_message(initialized_db, message_id = "msg-1")

    def test_add_message_sets_created_at_automatically(self, initialized_db: NodeDB) -> None:
        before = int(time.time())
        add_message(
            initialized_db,
            message_id = "msg-auto-ts",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
        )
        after = int(time.time())

        record = initialized_db.get_message("msg-auto-ts")

        assert record is not None
        assert before <= record.created_at <= after

    def test_payload_roundtrip_is_bytes_and_unchanged(self, initialized_db: NodeDB) -> None:
        payload = b"\x00\x01\x02binary\xffdata"

        add_message(
            initialized_db,
            message_id = "msg-binary",
            payload = payload,
        )

        record = initialized_db.get_message("msg-binary")

        assert record is not None
        assert isinstance(record.payload, bytes)
        assert record.payload == payload


class TestGetMessage:
    def test_get_existing_message_returns_message_record(self, initialized_db: NodeDB) -> None:
        add_message(
            initialized_db,
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 42,
        )

        record = initialized_db.get_message("msg-1")

        assert record == MessageRecord(
            message_id = "msg-1",
            chat_id = "chat-1",
            sender_id = "alice",
            payload = b"hello",
            created_at = 42,
        )

    def test_get_missing_message_returns_none(self, initialized_db: NodeDB) -> None:
        assert initialized_db.get_message("missing") is None


class TestListChatMessages:
    def test_list_chat_messages_returns_only_requested_chat(self, initialized_db: NodeDB) -> None:
        add_message(initialized_db, message_id = "a1", chat_id = "chat-a", created_at = 10)
        add_message(initialized_db, message_id = "a2", chat_id = "chat-a", created_at = 20)
        add_message(initialized_db, message_id = "b1", chat_id = "chat-b", created_at = 30)

        records = initialized_db.list_chat_messages("chat-a")

        assert [record.message_id for record in records] == ["a2", "a1"]
        assert all(record.chat_id == "chat-a" for record in records)

    def test_list_chat_messages_orders_by_created_at_desc_then_message_id_desc(
            self,
            initialized_db: NodeDB,
    ) -> None:
        add_message(initialized_db, message_id = "a", chat_id = "chat-1", created_at = 100)
        add_message(initialized_db, message_id = "c", chat_id = "chat-1", created_at = 200)
        add_message(initialized_db, message_id = "b", chat_id = "chat-1", created_at = 200)
        add_message(initialized_db, message_id = "d", chat_id = "chat-1", created_at = 50)

        records = initialized_db.list_chat_messages("chat-1")

        assert [record.message_id for record in records] == ["c", "b", "a", "d"]

    def test_list_chat_messages_limit_restricts_result_size(self, initialized_db: NodeDB) -> None:
        add_message(initialized_db, message_id = "m1", created_at = 1)
        add_message(initialized_db, message_id = "m2", created_at = 2)
        add_message(initialized_db, message_id = "m3", created_at = 3)

        records = initialized_db.list_chat_messages("chat-1", limit = 2)

        assert len(records) == 2
        assert [record.message_id for record in records] == ["m3", "m2"]

    @pytest.mark.parametrize("bad_limit", [0, -1, -100, 1001])
    def test_list_chat_messages_invalid_limit_raises(
            self,
            initialized_db: NodeDB,
            bad_limit: int,
    ) -> None:
        with pytest.raises(NodeDBError):
            initialized_db.list_chat_messages("chat-1", limit = bad_limit)

    def test_list_chat_messages_pagination_returns_non_overlapping_pages(
            self,
            initialized_db: NodeDB,
    ) -> None:
        add_message(initialized_db, message_id = "a", chat_id = "chat-1", created_at = 198)
        add_message(initialized_db, message_id = "z", chat_id = "chat-1", created_at = 199)
        add_message(initialized_db, message_id = "b", chat_id = "chat-1", created_at = 200)
        add_message(initialized_db, message_id = "c", chat_id = "chat-1", created_at = 200)

        page_1 = initialized_db.list_chat_messages("chat-1", limit = 2)
        assert [record.message_id for record in page_1] == ["c", "b"]

        cursor = page_1[-1]
        page_2 = initialized_db.list_chat_messages(
            "chat-1",
            limit = 2,
            before_created_at = cursor.created_at,
            before_message_id = cursor.message_id,
        )

        assert [record.message_id for record in page_2] == ["z", "a"]

        page_1_ids = {record.message_id for record in page_1}
        page_2_ids = {record.message_id for record in page_2}
        assert page_1_ids.isdisjoint(page_2_ids)

    def test_list_chat_messages_requires_both_pagination_cursor_fields(
            self,
            initialized_db: NodeDB,
    ) -> None:
        with pytest.raises(NodeDBError):
            initialized_db.list_chat_messages(
                "chat-1",
                before_created_at = 123,
            )

        with pytest.raises(NodeDBError):
            initialized_db.list_chat_messages(
                "chat-1",
                before_message_id = "msg-1",
            )


class TestTransactions:
    def test_run_in_transaction_commits_successful_operation(self, initialized_db: NodeDB) -> None:
        initialized_db.run_in_transaction(
            lambda tx: tx.add_message(
                message_id = "msg-1",
                chat_id = "chat-1",
                sender_id = "alice",
                payload = b"hello",
                created_at = 123,
            )
        )

        record = initialized_db.get_message("msg-1")
        assert record is not None
        assert record.message_id == "msg-1"

    def test_run_in_transaction_rolls_back_on_error(self, initialized_db: NodeDB) -> None:
        def failing_operation(tx: NodeDB) -> None:
            tx.add_message(
                message_id = "msg-rollback",
                chat_id = "chat-1",
                sender_id = "alice",
                payload = b"hello",
                created_at = 123,
            )
            raise RuntimeError("boom")

        with pytest.raises(NodeDBError):
            initialized_db.run_in_transaction(failing_operation)

        assert initialized_db.get_message("msg-rollback") is None


class TestStateErrors:
    def test_operations_without_open_raise(self, db_path) -> None:
        db = NodeDB(str(db_path))

        with pytest.raises(NodeDBError):
            db.add_message(
                message_id = "msg-1",
                chat_id = "chat-1",
                sender_id = "alice",
                payload = b"hello",
            )

        with pytest.raises(NodeDBError):
            db.get_message("msg-1")

        with pytest.raises(NodeDBError):
            db.list_chat_messages("chat-1")

    def test_operations_without_initialize_raise(self, opened_db: NodeDB) -> None:
        with pytest.raises(NodeDBError):
            opened_db.add_message(
                message_id = "msg-1",
                chat_id = "chat-1",
                sender_id = "alice",
                payload = b"hello",
            )

        with pytest.raises(NodeDBError):
            opened_db.get_message("msg-1")

        with pytest.raises(NodeDBError):
            opened_db.list_chat_messages("chat-1")

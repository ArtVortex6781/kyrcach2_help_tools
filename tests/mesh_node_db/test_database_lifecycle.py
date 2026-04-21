from __future__ import annotations

import sqlite3

import pytest

from mesh_node_db import ChatRecord, NodeDatabase, PeerRecord, SchemaError


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "node.db"


@pytest.fixture
def opened_db(db_path) -> NodeDatabase:
    db = NodeDatabase(str(db_path))
    db.open()
    return db


@pytest.fixture
def initialized_db(db_path) -> NodeDatabase:
    db = NodeDatabase(str(db_path))
    db.open()
    db.initialize()
    return db


class TestOpenClose:
    def test_open_new_database_is_successful_and_wires_repositories(self, db_path) -> None:
        db = NodeDatabase(str(db_path))

        db.open()

        assert db.peers is not None
        assert db.chats is not None
        assert db.chat_participants is not None
        assert db.messages is not None
        assert db.attachments is not None

    def test_repeated_open_is_safe(self, db_path) -> None:
        db = NodeDatabase(str(db_path))

        db.open()
        first_peers = db.peers
        first_chats = db.chats

        db.open()

        assert db.peers is first_peers
        assert db.chats is first_chats

    def test_close_is_safe_and_resets_runtime_state(self, opened_db: NodeDatabase) -> None:
        opened_db.close()

        assert opened_db.peers is None
        assert opened_db.chats is None
        assert opened_db.chat_participants is None
        assert opened_db.messages is None
        assert opened_db.attachments is None

    def test_repeated_close_is_safe(self, opened_db: NodeDatabase) -> None:
        opened_db.close()
        opened_db.close()

        assert opened_db.peers is None
        assert opened_db.chats is None
        assert opened_db.chat_participants is None
        assert opened_db.messages is None
        assert opened_db.attachments is None


class TestInitialize:
    def test_initialize_new_database_bootstraps_schema_and_schema_version(
            self,
            opened_db: NodeDatabase,
    ) -> None:
        opened_db.initialize()

        assert opened_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

    def test_repeated_initialize_is_safe(self, initialized_db: NodeDatabase) -> None:
        initialized_db.initialize()

        assert initialized_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

    def test_reopen_existing_database_preserves_data_and_schema(self, db_path) -> None:
        writer = NodeDatabase(str(db_path))
        writer.open()
        writer.initialize()

        peer = PeerRecord(
            peer_id = "peer-1",
            display_name = b"Alice",
            public_key = b"alice-pk",
            created_at = 100,
            updated_at = 100,
        )
        chat = ChatRecord(
            chat_id = "chat-1",
            chat_type = "direct",
            chat_name = b"Direct chat",
            created_at = 101,
            updated_at = 101,
        )

        writer.peers.add(peer)
        writer.chats.add(chat)
        writer.close()

        reader = NodeDatabase(str(db_path))
        reader.open()
        reader.initialize()

        restored_peer = reader.peers.read("peer-1")
        restored_chat = reader.chats.read("chat-1")

        assert reader.get_schema_version() == NodeDatabase.SCHEMA_VERSION
        assert restored_peer == peer
        assert restored_chat == chat

    def test_initialize_on_incompatible_schema_version_raises_schema_error(self, db_path) -> None:
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            """
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO schema_version (id, version) VALUES (1, ?)",
            (NodeDatabase.SCHEMA_VERSION + 1,),
        )
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path))
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_broken_existing_schema_raises_schema_error(self, db_path) -> None:
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE schema_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)")
        conn.execute("INSERT INTO schema_version (id, version) VALUES (1, ?)", (NodeDatabase.SCHEMA_VERSION,))
        conn.execute("CREATE TABLE peers (peer_id TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path))
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

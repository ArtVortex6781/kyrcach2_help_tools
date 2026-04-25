from __future__ import annotations

import sqlite3

import pytest

from mesh_node_db import (
    ConfigurationError,
    NodeDBError,
    NodeDatabase,
    PeerRecord,
    SchemaError,
)


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


def create_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        """
        CREATE TABLE schema_version (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )
        """
    )
    conn.execute("INSERT INTO schema_version (id, version) VALUES (1, ?)", (version,))


class TestConfiguration:
    @pytest.mark.parametrize("journal_mode", [None, 123, "delete", " MEMORY "])
    def test_invalid_journal_mode_raises_configuration_error(self, db_path, journal_mode) -> None:
        with pytest.raises(ConfigurationError):
            NodeDatabase(str(db_path), journal_mode = journal_mode)

    @pytest.mark.parametrize("synchronous", [None, 123, "off", "extra"])
    def test_invalid_synchronous_raises_configuration_error(self, db_path, synchronous) -> None:
        with pytest.raises(ConfigurationError):
            NodeDatabase(str(db_path), synchronous = synchronous)


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
    def test_initialize_new_database_bootstraps_schema_version_and_peer_tombstone_columns(
            self,
            initialized_db: NodeDatabase,
            db_path,
    ) -> None:
        assert initialized_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

        conn = sqlite3.connect(str(db_path))
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(peers)").fetchall()
        }
        conn.close()

        assert {
            "peer_id",
            "display_name",
            "public_key",
            "created_at",
            "updated_at",
            "is_deleted",
            "deleted_at",
        }.issubset(columns)

    def test_repeated_initialize_is_safe(self, initialized_db: NodeDatabase) -> None:
        initialized_db.initialize()

        assert initialized_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

    def test_get_schema_version_before_initialize_raises_nodedb_error(
            self,
            opened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(NodeDBError):
            opened_db.get_schema_version()

    def test_get_schema_version_after_close_raises_nodedb_error(
            self,
            initialized_db: NodeDatabase,
    ) -> None:
        initialized_db.close()

        with pytest.raises(NodeDBError):
            initialized_db.get_schema_version()

    def test_reopen_existing_database_preserves_data_and_schema(self, db_path) -> None:
        writer = NodeDatabase(str(db_path))
        writer.open()
        writer.initialize()

        peer = make_peer("peer-1", b"Alice", b"alice-pk", 100, 100)
        writer.peers.add(peer)
        writer.close()

        reader = NodeDatabase(str(db_path))
        reader.open()
        reader.initialize()

        restored = reader.peers.read("peer-1")

        assert reader.get_schema_version() == NodeDatabase.SCHEMA_VERSION
        assert restored == peer

    def test_initialize_on_incompatible_schema_version_raises_schema_error(self, db_path) -> None:
        conn = sqlite3.connect(str(db_path))
        create_schema_version(conn, NodeDatabase.SCHEMA_VERSION + 1)
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path))
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_missing_required_peer_columns_raises_schema_error(self, db_path) -> None:
        conn = sqlite3.connect(str(db_path))
        create_schema_version(conn, NodeDatabase.SCHEMA_VERSION)
        conn.execute(
            """
            CREATE TABLE peers (
                peer_id TEXT PRIMARY KEY,
                display_name BLOB NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path))
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_missing_required_foreign_keys_raises_schema_error(self, db_path) -> None:
        conn = sqlite3.connect(str(db_path))
        create_schema_version(conn, NodeDatabase.SCHEMA_VERSION)

        conn.execute(
            """
            CREATE TABLE peers (
                peer_id TEXT PRIMARY KEY,
                display_name BLOB NOT NULL,
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                is_deleted INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE chats (
                chat_id TEXT PRIMARY KEY,
                chat_type TEXT NOT NULL,
                chat_name BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE chat_participants (
                chat_id TEXT NOT NULL,
                peer_id TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (chat_id, peer_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE attachments (
                attachment_hash TEXT PRIMARY KEY,
                file_path BLOB NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                payload BLOB NOT NULL,
                attachment_hash TEXT NULL
            )
            """
        )
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path))
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

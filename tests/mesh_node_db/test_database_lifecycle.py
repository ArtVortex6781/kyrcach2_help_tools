from __future__ import annotations

import sqlite3
import uuid

import pytest

from mesh_node_db import (
    DatabaseConfigurationError,
    DatabaseNotInitializedError,
    DatabaseNotOpenError,
    NodeDatabase,
    NodeDBCryptoAdapter,
    OperationalStorageError,
    PeerRecord,
    SchemaError,
)


class EchoStorageProvider:
    def encrypt_field(self, plaintext: bytes, *, aad: bytes, key_id) -> bytes:
        return b"encrypted:" + plaintext

    def decrypt_field(self, envelope: bytes, *, aad: bytes) -> bytes:
        prefix = b"encrypted:"
        if envelope.startswith(prefix):
            return envelope[len(prefix):]
        return envelope


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "node.db"


@pytest.fixture
def crypto_adapter() -> NodeDBCryptoAdapter:
    return NodeDBCryptoAdapter(
        provider = EchoStorageProvider(),
        active_storage_key_id = uuid.uuid4(),
    )


@pytest.fixture
def unopened_db(db_path, crypto_adapter: NodeDBCryptoAdapter) -> NodeDatabase:
    return NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)


@pytest.fixture
def opened_db(unopened_db: NodeDatabase) -> NodeDatabase:
    unopened_db.open()
    return unopened_db


@pytest.fixture
def initialized_db(opened_db: NodeDatabase) -> NodeDatabase:
    opened_db.initialize()
    return opened_db


def make_peer(
        peer_id: str,
        display_name: str = "Alice",
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


def column_info(db_path, table_name: str) -> dict[str, sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return {
            str(row["name"]): row
            for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
    finally:
        conn.close()


def index_names(db_path, table_name: str) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        return {
            str(row[1])
            for row in conn.execute(f"PRAGMA index_list({table_name})").fetchall()
        }
    finally:
        conn.close()


class TestConfiguration:
    @pytest.mark.parametrize("bad_path", [None, 123, b"node.db", ""])
    def test_invalid_path_raises_database_configuration_error(
            self,
            bad_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
        with pytest.raises(DatabaseConfigurationError):
            NodeDatabase(bad_path, crypto_adapter = crypto_adapter)

    def test_missing_crypto_adapter_raises_database_configuration_error(self, db_path) -> None:
        with pytest.raises(DatabaseConfigurationError):
            NodeDatabase(str(db_path), crypto_adapter = None)

    @pytest.mark.parametrize("bad_crypto_adapter", [object(), "adapter", 123])
    def test_invalid_crypto_adapter_raises_database_configuration_error(
            self,
            db_path,
            bad_crypto_adapter,
    ) -> None:
        with pytest.raises(DatabaseConfigurationError):
            NodeDatabase(str(db_path), crypto_adapter = bad_crypto_adapter)

    @pytest.mark.parametrize("journal_mode", [None, 123, "delete", " MEMORY ", "TRUNCATE"])
    def test_invalid_journal_mode_raises_database_configuration_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
            journal_mode,
    ) -> None:
        with pytest.raises(DatabaseConfigurationError):
            NodeDatabase(
                str(db_path),
                crypto_adapter = crypto_adapter,
                journal_mode = journal_mode,
            )

    @pytest.mark.parametrize("synchronous", [None, 123, "off", "extra", ""])
    def test_invalid_synchronous_raises_database_configuration_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
            synchronous,
    ) -> None:
        with pytest.raises(DatabaseConfigurationError):
            NodeDatabase(
                str(db_path),
                crypto_adapter = crypto_adapter,
                synchronous = synchronous,
            )

    @pytest.mark.parametrize(
        ("journal_mode", "synchronous"),
        [
            ("wal", "normal"),
            (" WAL ", " FULL "),
            ("WaL", "NoRmAl"),
        ],
    )
    def test_supported_pragma_config_is_normalized_and_database_opens(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
            journal_mode: str,
            synchronous: str,
    ) -> None:
        db = NodeDatabase(
            str(db_path),
            crypto_adapter = crypto_adapter,
            journal_mode = journal_mode,
            synchronous = synchronous,
        )

        db.open()
        db.initialize()

        assert db.get_schema_version() == NodeDatabase.SCHEMA_VERSION


class TestLifecycleStateErrors:
    def test_initialize_without_open_raises_database_not_open_error(
            self,
            unopened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(DatabaseNotOpenError):
            unopened_db.initialize()

    def test_get_schema_version_without_open_raises_database_not_open_error(
            self,
            unopened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(DatabaseNotOpenError):
            unopened_db.get_schema_version()

    def test_run_in_transaction_without_open_raises_database_not_open_error(
            self,
            unopened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(DatabaseNotOpenError):
            unopened_db.run_in_transaction(lambda tx: None)

    def test_get_schema_version_after_open_before_initialize_raises_database_not_initialized_error(
            self,
            opened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(DatabaseNotInitializedError):
            opened_db.get_schema_version()

    def test_run_in_transaction_after_open_before_initialize_raises_database_not_initialized_error(
            self,
            opened_db: NodeDatabase,
    ) -> None:
        with pytest.raises(DatabaseNotInitializedError):
            opened_db.run_in_transaction(lambda tx: None)

    def test_operations_after_close_raise_database_not_open_error(
            self,
            initialized_db: NodeDatabase,
    ) -> None:
        initialized_db.close()

        with pytest.raises(DatabaseNotOpenError):
            initialized_db.get_schema_version()

        with pytest.raises(DatabaseNotOpenError):
            initialized_db.initialize()

        with pytest.raises(DatabaseNotOpenError):
            initialized_db.run_in_transaction(lambda tx: None)


class TestOpenClose:
    def test_open_new_database_is_successful_and_wires_repositories(
            self,
            unopened_db: NodeDatabase,
    ) -> None:
        unopened_db.open()

        assert unopened_db.peers is not None
        assert unopened_db.chats is not None
        assert unopened_db.chat_participants is not None
        assert unopened_db.messages is not None
        assert unopened_db.attachments is not None

    def test_repeated_open_is_safe(self, unopened_db: NodeDatabase) -> None:
        unopened_db.open()
        first_peers = unopened_db.peers
        first_chats = unopened_db.chats
        first_messages = unopened_db.messages

        unopened_db.open()

        assert unopened_db.peers is first_peers
        assert unopened_db.chats is first_chats
        assert unopened_db.messages is first_messages

    def test_close_without_open_is_safe(self, unopened_db: NodeDatabase) -> None:
        unopened_db.close()

        assert unopened_db.peers is None
        assert unopened_db.chats is None
        assert unopened_db.chat_participants is None
        assert unopened_db.messages is None
        assert unopened_db.attachments is None

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

    def test_failed_open_resets_runtime_state(
            self,
            tmp_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
        db = NodeDatabase(str(tmp_path), crypto_adapter = crypto_adapter)

        with pytest.raises(OperationalStorageError):
            db.open()

        assert db.peers is None
        assert db.chats is None
        assert db.chat_participants is None
        assert db.messages is None
        assert db.attachments is None


class TestInitialize:
    def test_initialize_new_database_bootstraps_schema_version_and_peer_tombstone_columns(
            self,
            initialized_db: NodeDatabase,
            db_path,
    ) -> None:
        assert initialized_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

        peer_columns = column_info(db_path, "peers")

        assert {
            "peer_id",
            "display_name",
            "public_key",
            "created_at",
            "updated_at",
            "is_deleted",
            "deleted_at",
        }.issubset(peer_columns)

    def test_initialize_new_database_uses_encrypted_storage_column_types(
            self,
            initialized_db: NodeDatabase,
            db_path,
    ) -> None:
        peer_columns = column_info(db_path, "peers")
        chat_columns = column_info(db_path, "chats")
        message_columns = column_info(db_path, "messages")
        attachment_columns = column_info(db_path, "attachments")

        assert str(peer_columns["display_name"]["type"]).upper() == "BLOB"
        assert str(chat_columns["chat_name"]["type"]).upper() == "BLOB"
        assert int(chat_columns["chat_name"]["notnull"]) == 1
        assert str(message_columns["payload"]["type"]).upper() == "BLOB"
        assert str(attachment_columns["file_path"]["type"]).upper() == "TEXT"

    def test_initialize_new_database_creates_required_indexes(
            self,
            initialized_db: NodeDatabase,
            db_path,
    ) -> None:
        assert "idx_peers_is_deleted_created" in index_names(db_path, "peers")
        assert "idx_chats_chat_type" in index_names(db_path, "chats")
        assert "idx_chat_participants_peer" in index_names(db_path, "chat_participants")
        assert "idx_messages_chat_created_message" in index_names(db_path, "messages")
        assert "idx_messages_sender_created" in index_names(db_path, "messages")
        assert "idx_messages_attachment_hash" in index_names(db_path, "messages")

    def test_repeated_initialize_is_safe(self, initialized_db: NodeDatabase) -> None:
        initialized_db.initialize()

        assert initialized_db.get_schema_version() == NodeDatabase.SCHEMA_VERSION

    def test_reopen_existing_database_preserves_data_and_schema(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
        writer = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        writer.open()
        writer.initialize()

        peer = make_peer("peer-1", "Alice", b"alice-pk", 100, 100)
        writer.peers.add(peer)
        writer.close()

        reader = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        reader.open()
        reader.initialize()

        restored = reader.peers.read("peer-1")

        assert reader.get_schema_version() == NodeDatabase.SCHEMA_VERSION
        assert restored == peer

    def test_initialize_on_incompatible_schema_version_raises_schema_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
        conn = sqlite3.connect(str(db_path))
        create_schema_version(conn, NodeDatabase.SCHEMA_VERSION + 1)
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_missing_required_peer_columns_raises_schema_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
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

        db = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_missing_required_foreign_keys_raises_schema_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
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
                file_path TEXT NOT NULL
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
                updated_at INTEGER NOT NULL,
                payload BLOB NOT NULL,
                attachment_hash TEXT NULL
            )
            """
        )
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

    def test_initialize_on_wrong_foreign_key_delete_behavior_raises_schema_error(
            self,
            db_path,
            crypto_adapter: NodeDBCryptoAdapter,
    ) -> None:
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
                PRIMARY KEY (chat_id, peer_id),
                FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
                FOREIGN KEY (peer_id) REFERENCES peers(peer_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE attachments (
                attachment_hash TEXT PRIMARY KEY,
                file_path TEXT NOT NULL
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
                updated_at INTEGER NOT NULL,
                payload BLOB NOT NULL,
                attachment_hash TEXT NULL,
                FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES peers(peer_id) ON DELETE CASCADE,
                FOREIGN KEY (attachment_hash) REFERENCES attachments(attachment_hash) ON DELETE SET NULL
            )
            """
        )
        conn.commit()
        conn.close()

        db = NodeDatabase(str(db_path), crypto_adapter = crypto_adapter)
        db.open()

        with pytest.raises(SchemaError):
            db.initialize()

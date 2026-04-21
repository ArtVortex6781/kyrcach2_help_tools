from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Callable, Optional, TypeVar, Iterator, TYPE_CHECKING

from .errors import (
    ConstraintError,
    DatabaseExecutionError,
    NodeDBError,
    OperationalStorageError,
    SchemaError,
    TransactionError,
)

__all__ = ["NodeDatabase"]

T = TypeVar("T")

if TYPE_CHECKING:
    from .repositories import (
        AttachmentRepository,
        ChatParticipantRepository,
        ChatRepository,
        MessageRepository,
        PeerRepository,
    )


class _DatabaseExecutor:
    """
    Internal low-level SQL executor for mesh_node_db.

    Responsibilities:
    - execute SQL statements
    - fetch one row
    - fetch many rows
    - centralize sqlite3.Error -> mesh_node_db error conversion
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        """
        Initialize executor with an active sqlite connection.

        :param conn: active sqlite3 connection owned by the database engine
        """
        self._conn = conn

    @staticmethod
    def _raise_database_error(exc: sqlite3.Error, operation: str) -> None:
        """
        Convert sqlite3 exceptions into typed mesh_node_db errors.

        :param exc: original sqlite3 exception
        :param operation: logical low-level operation name for error messages
        :raises ConstraintError: if a database constraint is violated.
        :raises OperationalStorageError: if a low-level operational database error occurs.
        :raises DatabaseExecutionError: for other low-level database execution failures.
        """
        if isinstance(exc, sqlite3.IntegrityError):
            raise ConstraintError(f"Database constraint failed during {operation}: {exc}") from exc

        if isinstance(exc, sqlite3.OperationalError):
            raise OperationalStorageError(
                f"Database operational error during {operation}: {exc}"
            ) from exc

        raise DatabaseExecutionError(f"Database {operation} failed: {exc}") from exc

    def execute(self, sql: str,
                params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute one SQL statement and return the sqlite cursor.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: sqlite3.Cursor for the executed statement
        :raises ConstraintError: if a database constraint is violated.
        :raises OperationalStorageError: if a low-level operational database error occurs.
        :raises DatabaseExecutionError: for other low-level database execution failures.
        """
        try:
            return self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            self._raise_database_error(exc, "execute")

    def fetchone(self, sql: str,
                 params: tuple = ()) -> Optional[sqlite3.Row]:
        """
        Execute a SELECT statement and return one row or None.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: one sqlite3.Row or None
        :raises ConstraintError: if a database constraint is violated.
        :raises OperationalStorageError: if a low-level operational database error occurs.
        :raises DatabaseExecutionError: for other low-level database execution failures.
        """
        try:
            return self._conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            self._raise_database_error(exc, "fetchone")

    def fetchall(self, sql: str,
                 params: tuple = ()) -> list[sqlite3.Row]:
        """
        Execute a SELECT statement and return all matching rows.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: list of sqlite3.Row
        :raises ConstraintError: if a database constraint is violated.
        :raises OperationalStorageError: if a low-level operational database error occurs.
        :raises DatabaseExecutionError: for other low-level database execution failures.
        """
        try:
            return self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            self._raise_database_error(exc, "fetchall")


class NodeDatabase:
    """
    Typed storage database engine for mesh_node_db Phase 3.

    Responsibilities:
    - own SQLite connection lifecycle
    - configure SQLite connection
    - bootstrap schema and validate schema_version
    - define grouped transaction boundaries
    - expose repository objects
    - centralize low-level DB execution through _DatabaseExecutor

    Transaction model:
    - single write operations may be executed directly through repositories
      and rely on SQLite statement-level atomicity
    - grouped multi-step mutations that must succeed or fail as one unit
      must be executed through run_in_transaction(...)
    """

    SCHEMA_VERSION = 1

    _SCHEMA_STATEMENTS = (
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            display_name BLOB NOT NULL,
            public_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS chats (
            chat_id TEXT PRIMARY KEY,
            chat_type TEXT NOT NULL,
            chat_name BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS chat_participants (
            chat_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            joined_at INTEGER NOT NULL,
            PRIMARY KEY (chat_id, peer_id),
            FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
            FOREIGN KEY (peer_id) REFERENCES peers(peer_id) ON DELETE CASCADE
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS attachments (
            attachment_hash TEXT PRIMARY KEY,
            file_path BLOB NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            payload BLOB NOT NULL,
            attachment_hash TEXT NULL,
            FOREIGN KEY (chat_id) REFERENCES chats(chat_id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES peers(peer_id) ON DELETE CASCADE,
            FOREIGN KEY (attachment_hash) REFERENCES attachments(attachment_hash) ON DELETE SET NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_chats_chat_type
        ON chats(chat_type)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_chat_participants_peer
        ON chat_participants(peer_id)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_messages_chat_created_message
        ON messages(chat_id, created_at, message_id)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_messages_sender_created
        ON messages(sender_id, created_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_messages_attachment_hash
        ON messages(attachment_hash)
        """,
    )

    def __init__(self, path: str, journal_mode: str = "WAL",
                 synchronous: str = "NORMAL") -> None:
        """
        Initialize database engine configuration.

        :param path: SQLite file path
        :param journal_mode: PRAGMA journal_mode value
        :param synchronous: PRAGMA synchronous value
        """
        self._path = path
        self._journal_mode = journal_mode
        self._synchronous = synchronous

        self._conn: Optional[sqlite3.Connection] = None
        self._executor: Optional[_DatabaseExecutor] = None
        self._initialized: bool = False

        self.peers: Optional[PeerRepository] = None
        self.chats: Optional[ChatRepository] = None
        self.chat_participants: Optional[ChatParticipantRepository] = None
        self.messages: Optional[MessageRepository] = None
        self.attachments: Optional[AttachmentRepository] = None

    # -----------------------
    # connection management
    # -----------------------

    def open(self, timeout: float = 5.0) -> None:
        """
        Open SQLite connection, configure PRAGMAs and wire repositories.

        This method opens the database connection only. Schema bootstrap is
        explicit and is performed by initialize().

        Repeated calls are allowed and must remain stable.

        :param timeout: SQLite connection timeout in seconds
        :raises NodeDBError: if database open or connection configuration fails.
        """
        if self._conn is not None:
            return

        try:
            self._conn = sqlite3.connect(
                self._path,
                timeout = timeout,
                isolation_level = None,
            )
            self._conn.row_factory = sqlite3.Row
            self._configure_connection()

            self._executor = _DatabaseExecutor(self._conn)
            self._wire_repositories()
        except NodeDBError:
            self._reset_runtime_state()
            raise
        except sqlite3.Error as exc:
            self._reset_runtime_state()
            raise NodeDBError(f"Failed to open database: {exc}") from exc
        except Exception:
            self._reset_runtime_state()
            raise

    def close(self) -> None:
        """
        Close the SQLite connection and detach repositories.

        Repeated calls are allowed and must remain stable.

        :raises NodeDBError: if connection close fails.
        """
        if self._conn is None:
            return

        try:
            self._conn.close()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to close database: {exc}") from exc
        finally:
            self._reset_runtime_state()

    def initialize(self) -> None:
        """
        Bootstrap schema and validate schema version.

        For a new database:
        - creates all Phase 3 tables and indexes
        - inserts initial schema_version row

        For an existing database:
        - validates that schema_version matches SCHEMA_VERSION

        Repeated calls are allowed and must remain stable.

        :raises SchemaError: if schema bootstrap fails or schema version is unsupported.
        :raises NodeDBError: if the database is not open.
        """
        self._require_open()
        self._require_executor()

        try:
            with self._transaction():

                for statement in self._SCHEMA_STATEMENTS:
                    self._executor.execute(statement)

                row = self._executor.fetchone(
                    "SELECT version FROM schema_version WHERE id = 1"
                )

                if row is None:
                    self._executor.execute(
                        "INSERT INTO schema_version (id, version) VALUES (1, ?)",
                        (self.SCHEMA_VERSION,),
                    )
                    version = self.SCHEMA_VERSION
                else:
                    version = int(row["version"])
        except NodeDBError as exc:
            raise SchemaError(f"Failed to initialize database schema: {exc}") from exc
        except sqlite3.Error as exc:
            raise SchemaError(f"Failed to initialize database schema: {exc}") from exc

        if version != self.SCHEMA_VERSION:
            raise SchemaError(
                f"Unsupported schema version: {version}. Expected: {self.SCHEMA_VERSION}."
            )

        self._initialized = True

    def get_schema_version(self) -> int:
        """
        Return current schema version stored in the database.

        :return: current schema version
        :raises NodeDBError: if the database is not open or not initialized.
        :raises SchemaError: if schema_version row is missing.
        """
        self._require_initialized()

        row = self._executor.fetchone(
            "SELECT version FROM schema_version WHERE id = 1"
        )
        if row is None:
            raise SchemaError("Schema version is not initialized.")

        return int(row["version"])

    # -----------------------
    # transaction handling
    # -----------------------

    def run_in_transaction(self, fn: Callable[["NodeDatabase"], T]) -> T:
        """
        Execute a group of storage-level operations atomically.

        Single write operations may be executed directly through repositories.
        This method is intended for multi-step mutation sequences that must
        succeed or fail as one unit.

        The callback receives this NodeDatabase instance and may use the public
        repository objects exposed by it.

        :param fn: callback executed inside one SQL transaction
        :return: callback return value
        :raises TransactionError: if the grouped transaction fails.
        """
        self._require_initialized()

        try:
            with self._transaction():
                return fn(self)
        except TransactionError:
            raise
        except NodeDBError as exc:
            raise TransactionError("Transactional storage operation failed.") from exc
        except Exception as exc:
            raise TransactionError("Transactional callback failed.") from exc

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        """
        Execute one internal SQL transaction.

        This helper centralizes BEGIN / COMMIT / ROLLBACK policy and is not part
        of the public package API.

        :raises TransactionError: if SQL transaction handling fails.
        """
        self._require_open()

        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN;")
            yield
            cur.execute("COMMIT;")
        except sqlite3.Error as exc:
            try:
                cur.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise TransactionError(f"Database transaction failed: {exc}") from exc
        except Exception:
            try:
                cur.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise
        finally:
            cur.close()

    # -----------------------
    # internal helpers
    # -----------------------

    def _require_open(self) -> None:
        """
        Ensure that the SQLite connection is open.

        :raises NodeDBError: if the connection is not open.
        """
        if self._conn is None:
            raise NodeDBError("Database connection is not open.")

    def _require_executor(self) -> None:
        """
        Ensure that the internal database executor is available.

        :raises NodeDBError: if executor wiring has not been completed.
        """
        if self._executor is None:
            raise NodeDBError("Database executor is not available.")

    def _require_initialized(self) -> None:
        """
        Ensure that the database is open and schema has been initialized.

        :raises NodeDBError: if the database is not open or initialize() has not been called.
        """
        self._require_open()
        self._require_executor()

        if not self._initialized:
            raise NodeDBError("Database schema is not initialized. Call initialize() first.")

    def _configure_connection(self) -> None:
        """
        Configure SQLite connection PRAGMAs for mesh_node_db.

        :raises NodeDBError: if SQLite connection configuration fails.
        """
        self._require_open()

        try:
            self._conn.execute(f"PRAGMA journal_mode = {self._journal_mode};")
            self._conn.execute(f"PRAGMA synchronous = {self._synchronous};")
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA busy_timeout = 5000;")
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to configure database connection: {exc}") from exc

    def _wire_repositories(self) -> None:
        """
        Create repository objects bound to the internal database executor.

        :raises NodeDBError: if repository wiring cannot be completed.
        """
        self._require_executor()

        from .repositories import (
            AttachmentRepository,
            ChatParticipantRepository,
            ChatRepository,
            MessageRepository,
            PeerRepository,
        )

        self.peers = PeerRepository(self._executor)
        self.chats = ChatRepository(self._executor)
        self.chat_participants = ChatParticipantRepository(self._executor)
        self.messages = MessageRepository(self._executor)
        self.attachments = AttachmentRepository(self._executor)

    def _reset_runtime_state(self) -> None:
        """
        Reset runtime-only database state after close or failed open.
        """
        self._conn = None
        self._executor = None
        self._initialized = False

        self.peers = None
        self.chats = None
        self.chat_participants = None
        self.messages = None
        self.attachments = None

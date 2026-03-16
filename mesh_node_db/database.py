from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Optional, TypeVar

__all__ = ["NodeDB", "MessageRecord", "NodeDBError"]

T = TypeVar("T")


class NodeDBError(Exception):
    """Base error for NodeDB operations."""


@dataclass(frozen = True)
class MessageRecord:
    """In-memory representation returned by read/list methods."""

    message_id: str
    chat_id: str
    sender_id: str
    payload: bytes
    created_at: int


class NodeDB:
    """
    Minimal abstract local storage layer for Phase 1.

    Responsibilities:
    - open/close SQLite connection
    - initialize/bootstrap schema
    - expose a small storage-oriented public API
    - store and read minimal immutable message records
    - provide explicit transaction boundaries
    - prepare schema versioning for future migrations
    """

    SCHEMA_VERSION = 1

    _SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        payload BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_chat_created_message
    ON messages(chat_id, created_at, message_id);
    """

    def __init__(self, path: str, journal_mode: str = "WAL", synchronous: str = "NORMAL") -> None:
        """
        :param path: SQLite file path.
        :param journal_mode: PRAGMA journal_mode value.
        :param synchronous: PRAGMA synchronous value.
        """
        self._path = path
        self._journal_mode = journal_mode
        self._synchronous = synchronous
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized: bool = False

    # -----------------------
    # connection management
    # -----------------------

    def _require_open(self) -> None:
        """
        Ensure that the database connection is initialized and open.
        Raises NodeDBError if the database connection has not been opened.
        """
        if self._conn is None:
            raise NodeDBError("Database connection is not open.")

    def _require_initialized(self) -> None:
        """
        Ensure that the database connection is open and schema is initialized.
        Raises NodeDBError if initialize() has not been called yet.
        """
        self._require_open()
        if not self._initialized:
            raise NodeDBError("Database schema is not initialized. Call initialize() first.")

    def open(self, timeout: float = 5.0) -> None:
        """
        Open SQLite connection and configure connection-level PRAGMAs.
        This method opens the database connection only. Schema bootstrap is kept
        explicit and is performed by initialize().
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
        except sqlite3.Error as exc:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            raise NodeDBError(f"Failed to open database: {exc}") from exc

    def close(self) -> None:
        """
        Close the database connection if it is open.
        """
        if self._conn is None:
            return
        try:
            self._conn.close()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to close database: {exc}") from exc
        finally:
            self._conn = None
            self._initialized = False

    def initialize(self) -> None:
        """
        Bootstrap minimal Phase 1 schema and validate schema version.
        This method is explicit on purpose:
        - open() handles connection lifecycle
        - initialize() handles schema bootstrap and version checks
        Raises NodeDBError if schema bootstrap fails or an unsupported
        schema version is detected.
        """
        self._require_open()
        try:
            with self._transaction() as cur:
                cur.executescript(self._SCHEMA_SQL)
                row = cur.execute(
                    "SELECT version FROM schema_version WHERE id = 1"
                ).fetchone()
                if row is None:
                    cur.execute(
                        "INSERT INTO schema_version (id, version) VALUES (1, ?)",
                        (self.SCHEMA_VERSION,),
                    )
                    version = self.SCHEMA_VERSION
                else:
                    version = int(row["version"])
        except NodeDBError:
            raise
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to initialize database schema: {exc}") from exc
        if version != self.SCHEMA_VERSION:
            raise NodeDBError(
                f"Unsupported schema version: {version}. Expected: {self.SCHEMA_VERSION}."
            )
        self._initialized = True

    def get_schema_version(self) -> int:
        """
        Return current schema version stored in the database.
        Raises NodeDBError if the connection is not open or schema_version
        has not been initialized yet.
        """
        self._require_open()
        try:
            row = self._conn.execute(
                "SELECT version FROM schema_version WHERE id = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to read schema version: {exc}") from exc
        if row is None:
            raise NodeDBError("Schema version is not initialized.")
        return int(row["version"])

    # -----------------------
    # public grouped execution
    # -----------------------

    def run_in_transaction(self, fn: Callable[["NodeDB"], T]) -> T:
        """
        Execute a group of storage-level operations atomically.
        The callback receives this NodeDB instance and must use only the public
        storage API. SQLite's cursors and SQL details are not exposed.
        Example:
            db.run_in_transaction(lambda tx: tx.add_message(...))
        Raises NodeDBError on database-level transaction failure.
        """
        self._require_initialized()
        try:
            with self._transaction():
                return fn(self)
        except NodeDBError:
            raise
        except Exception as exc:
            raise NodeDBError(f"Transactional operation failed: {exc}") from exc

    # -----------------------
    # minimal storage API
    # -----------------------

    def add_message(self, message_id: str, chat_id: str, sender_id: str, payload: bytes,
                    created_at: Optional[int] = None, ) -> None:
        """
        Insert one immutable message record.

        :param message_id: stable logical identifier of the message
        :param chat_id: logical chat identifier
        :param sender_id: logical sender identifier
        :param payload: opaque message payload stored as BLOB
        :param created_at: unix timestamp; current time is used if omitted
        Raises NodeDBError on invalid input or database failure.
        """
        self._require_initialized()
        if not message_id:
            raise NodeDBError("message_id must not be empty.")
        if not chat_id:
            raise NodeDBError("chat_id must not be empty.")
        if not sender_id:
            raise NodeDBError("sender_id must not be empty.")
        if not isinstance(payload, (bytes, bytearray)):
            raise NodeDBError("payload must be bytes-like.")
        ts = int(time.time()) if created_at is None else int(created_at)
        try:
            self._conn.execute(
                """
                INSERT INTO messages (
                    message_id,
                    chat_id,
                    sender_id,
                    payload,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (message_id, chat_id, sender_id, bytes(payload), ts),
            )
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to add message: {exc}") from exc

    def get_message(self, message_id: str) -> Optional[MessageRecord]:
        """
        Read one message by message_id.

        :param message_id: stable logical identifier of the message
        :return: MessageRecord or None if not found
        Raises NodeDBError on invalid state or database failure.
        """
        self._require_initialized()
        if not message_id:
            raise NodeDBError("message_id must not be empty.")
        try:
            row = self._conn.execute(
                """
                SELECT message_id, chat_id, sender_id, payload, created_at
                FROM messages
                WHERE message_id = ?
                """,
                (message_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to read message: {exc}") from exc
        if row is None:
            return None
        return self._row_to_message(row)

    def list_chat_messages(self, chat_id: str, limit: int = 100, before_created_at: Optional[int] = None,
                           before_message_id: Optional[str] = None) -> list[MessageRecord]:
        """
        List messages for one chat ordered from newest to oldest.

        Pagination model:
        - first page: pass only chat_id and optional limit
        - next page: pass both before_created_at and before_message_id
          from the last record of the previous page

        :param chat_id: logical chat identifier
        :param limit: maximum number of records to return
        :param before_created_at: pagination cursor timestamp
        :param before_message_id: pagination cursor message id
        :return: list of MessageRecord
        Raises NodeDBError on invalid input or database failure.
        """
        self._require_initialized()
        if not chat_id:
            raise NodeDBError("chat_id must not be empty.")
        self._validate_limit(limit)
        try:
            if before_created_at is None and before_message_id is None:
                rows = self._conn.execute(
                    """
                    SELECT message_id, chat_id, sender_id, payload, created_at
                    FROM messages
                    WHERE chat_id = ?
                    ORDER BY created_at DESC, message_id DESC
                    LIMIT ?
                    """,
                    (chat_id, limit),
                ).fetchall()
            elif before_created_at is not None and before_message_id is not None:
                rows = self._conn.execute(
                    """
                    SELECT message_id, chat_id, sender_id, payload, created_at
                    FROM messages
                    WHERE chat_id = ?
                      AND (
                          created_at < ?
                          OR (created_at = ? AND message_id < ?)
                      )
                    ORDER BY created_at DESC, message_id DESC
                    LIMIT ?
                    """,
                    (
                        chat_id,
                        int(before_created_at),
                        int(before_created_at),
                        before_message_id,
                        limit,
                    ),
                ).fetchall()
            else:
                raise NodeDBError(
                    "Pagination requires both before_created_at and before_message_id, or neither."
                )
        except NodeDBError:
            raise
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to list chat messages: {exc}") from exc
        return [self._row_to_message(row) for row in rows]

    # -----------------------
    # internal helpers
    # -----------------------

    @contextmanager
    def _transaction(self):
        """
        Internal transaction context manager: BEGIN / COMMIT / ROLLBACK.

        This helper is intentionally private so SQLite transaction details do not
        leak through the public API.
        """
        self._require_open()
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN;")
            yield cur
            cur.execute("COMMIT;")
        except sqlite3.Error as exc:
            try:
                cur.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise NodeDBError(f"Database transaction failed: {exc}") from exc
        except Exception:
            try:
                cur.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise
        finally:
            cur.close()

    def _configure_connection(self) -> None:
        """
        Configure SQLite connection PRAGMAs for the minimal Phase 1 storage layer.
        """
        self._require_open()
        try:
            self._conn.execute(f"PRAGMA journal_mode = {self._journal_mode};")
            self._conn.execute(f"PRAGMA synchronous = {self._synchronous};")
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("PRAGMA busy_timeout = 5000;")
        except sqlite3.Error as exc:
            raise NodeDBError(f"Failed to configure database connection: {exc}") from exc

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> MessageRecord:
        """
        Convert one SQLite row into MessageRecord.
        """
        return MessageRecord(
            message_id = str(row["message_id"]),
            chat_id = str(row["chat_id"]),
            sender_id = str(row["sender_id"]),
            payload = bytes(row["payload"]),
            created_at = int(row["created_at"]),
        )

    @staticmethod
    def _validate_limit(limit: int) -> None:
        """
        Validate bounded fetch size for list operations.
        """
        if limit <= 0:
            raise NodeDBError("limit must be > 0.")
        if limit > 1000:
            raise NodeDBError("limit must be <= 1000.")

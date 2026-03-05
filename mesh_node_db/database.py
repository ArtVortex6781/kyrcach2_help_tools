from __future__ import annotations
import sqlite3
import json
import time
from typing import Any, Mapping, Optional, Sequence, Tuple, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import logging

logger = logging.getLogger("mesh_node_db")
logger.setLevel(logging.INFO)


class CryptoEngineProtocol:
    """Protocol/duck-typing for crypto engine used by NodeDB."""

    def encrypt(self, plaintext: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes) -> bytes: ...


class NodeDBError(Exception):
    """Base error for NodeDB operations."""


@dataclass
class Entity:
    """In-memory representation returned by read/iter methods."""
    id: str
    kind: Optional[str]
    data: dict
    created_at: int
    updated_at: int


class NodeDB:
    """
    Lightweight, self-contained storage layer.
    - Uses sqlite3.
    - Stores JSON-serializable 'data' per entity (in a BLOB/text column).
    - Optionally encrypts the stored blob via a provided crypto engine.
    Responsibilities:
    - open/close DB
    - create/read/update/delete entities
    - batch_write and iteration
    - simple migrations (manual SQL files in migrations/)
    """
    DEFAULT_SCHEMA = """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS entities (
        id TEXT PRIMARY KEY,
        kind TEXT,
        created_at INTEGER,
        updated_at INTEGER,
        data BLOB
    );
    CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind);
    CREATE TABLE IF NOT EXISTS errors (
        error_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER,
        op TEXT,
        entity_id TEXT,
        error_text TEXT
    );
    """

    def __init__(self, path: str, crypto: Optional[CryptoEngineProtocol] = None, journal_mode: str = "WAL") -> None:
        """
        :param path: sqlite file path
        :param crypto: optional object with encrypt/decrypt(bytes) -> bytes
        :param journal_mode: PRAGMA journal_mode value
        """
        self._path = path
        self._crypto = crypto
        self._conn: Optional[sqlite3.Connection] = None
        self._journal_mode = journal_mode
        self._foreign_keys: bool = False

    # -----------------------
    # connection management
    # -----------------------

    def _require_open(self) -> None:
        """
        Ensure that the database connection is initialized and open.
        Raises NodeDBError If the database connection has not been opened.
        """
        if not self._conn:
            raise NodeDBError("Database connection is not open.")

    def open(self, timeout: float = 5.0) -> None:
        """Open connection and ensure base schema / PRAGMAs."""
        if self._conn:
            return
        self._conn = sqlite3.connect(self._path, timeout = timeout, isolation_level = None)
        self._conn.execute(f"PRAGMA journal_mode = {self._journal_mode};")
        self._conn.execute("PRAGMA synchronous = NORMAL;")
        if self._foreign_keys:
            self._conn.execute("PRAGMA foreign_keys = ON;")
        self._ensure_schema()

    def close(self) -> None:
        if not self._conn:
            return
        self._conn.commit()
        self._conn.close()
        self._conn = None

    def _ensure_schema(self) -> None:
        """Create default tables if needed. Later, run migration scripts from migrations/."""
        self._require_open()
        cur = self._conn.cursor()
        cur.executescript(self.DEFAULT_SCHEMA)
        cur.close()

    # -----------------------
    # utility: transactions
    # -----------------------
    @contextmanager
    def transaction(self):
        """Simple transaction context manager: BEGIN / COMMIT / ROLLBACK and basic error logging."""
        self._require_open()
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN;")
            yield cur
            cur.execute("COMMIT;")
        except Exception as e:
            cur.execute("ROLLBACK;")
            try:
                ts = int(time.time())
                self._conn.execute(
                    "INSERT INTO errors (ts, op, entity_id, error_text) VALUES (?, ?, ?, ?)",
                    (ts, getattr(e, "op", "unknown"), None, repr(e)),
                    # TODO(#1): Чтобы передовалось имя операции (создать/обновить/удалить) в функцию transaction()
                    #  и записать его в errors.op вместо "unknown"
                )
                self._conn.commit()
            except Exception:
                pass
            raise

    # -----------------------
    # CRUD API
    # -----------------------

    def create(self, entity_id: str, data: Mapping[str, Any], kind: Optional[str] = None) -> None:
        """Create a new entity. Raises NodeDBError if exists."""
        self._require_open()
        now = int(time.time())
        payload = json.dumps(data, separators = (",", ":"), ensure_ascii = False).encode()
        if self._crypto:
            payload = self._crypto.encrypt(payload)
        with self.transaction() as cur:
            cur.execute(
                "INSERT INTO entities (id, kind, created_at, updated_at, data) VALUES (?, ?, ?, ?, ?)",
                (entity_id, kind, now, now, payload),
            )

    def read(self, entity_id: str) -> Optional[Entity]:
        """Read entity by id; returns Entity or None if not found."""
        self._require_open()
        cur = self._conn.cursor()
        cur.execute("SELECT id, kind, created_at, updated_at, data FROM entities WHERE id = ?", (entity_id,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return None
        raw = row[4]
        if self._crypto and raw is not None:
            raw = self._crypto.decrypt(raw)
        data = json.loads(raw.decode()) if raw is not None else {}
        return Entity(id = row[0], kind = row[1], created_at = row[2], updated_at = row[3], data = data)

    def update(self, entity_id: str, fields: Mapping[str, Any]) -> None:
        """Partial update: merges provided fields into existing dict. Raises if not found."""
        self._require_open()
        existing = self.read(entity_id)
        if existing is None:
            raise NodeDBError("Entity not found")
        merged = {**existing.data, **fields}
        now = int(time.time())
        payload = json.dumps(merged, separators = (",", ":"), ensure_ascii = False).encode()
        if self._crypto:
            payload = self._crypto.encrypt(payload)
        with self.transaction() as cur:
            cur.execute(
                "UPDATE entities SET data = ?, updated_at = ? WHERE id = ?",
                (payload, now, entity_id),
            )

    def delete(self, entity_id: str) -> None:
        self._require_open()
        with self.transaction() as cur:
            cur.execute("DELETE FROM entities WHERE id = ?", (entity_id,))

    # -----------------------
    # batch write and iteration
    # -----------------------

    def batch_write(self, items: Sequence[Tuple[str, Optional[str], Mapping[str, Any]]]) -> None:
        """
        :param items: sequence of (entity_id, kind, data)
        Performs one transaction with multiple inserts/updates (upsert).
        """
        self._require_open()
        now = int(time.time())
        with self.transaction() as cur:
            for entity_id, kind, data in items:
                payload = json.dumps(data, separators = (",", ":"), ensure_ascii = False).encode()
                if self._crypto:
                    payload = self._crypto.encrypt(payload)
                cur.execute(
                    """
                    INSERT INTO entities (id, kind, created_at, updated_at, data)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      kind=excluded.kind,
                      updated_at=excluded.updated_at,
                      data=excluded.data
                    """,
                    (entity_id, kind, now, now, payload),
                )

    def iter_all(self, strict: bool = True) -> Iterator[Entity]:
        """
        An iterator on all entities in the database.
        :param strict: if True, when corrupted data is detected, decryption error or invalid JSON)
        The function throws an exception. If False, such entries are skipped.

        :return Entity objects with the id, kind, data, created_at, updated_at fields.
        """
        self._require_open()
        cur = self._conn.execute("""SELECT id, kind, data, created_at, updated_at FROM entities ORDER BY created_at""")
        for entity_id, kind, raw, created_at, updated_at in cur:
            try:
                if self._crypto:
                    raw = self._crypto.decrypt(raw)
                data = json.loads(raw.decode("utf-8"))
            except Exception as e:
                logger.error(
                    "Corrupted entity detected: id = %s, error = %s",
                    entity_id,
                    str(e),
                )
                if strict:
                    raise
                continue
            yield Entity(
                id = entity_id,
                kind = kind,
                data = data,
                created_at = created_at,
                updated_at = updated_at,
            )

    # -----------------------
    # utilities
    # -----------------------

    def backup(self, dest_path: str) -> None:
        """Create a sqlite backup file (online backup)."""
        self._require_open()
        dest_conn = sqlite3.connect(dest_path)
        with dest_conn:
            self._conn.backup(dest_conn)
        dest_conn.close()

    def run_migration_script(self, sql: str) -> None:
        """Apply a manual migration SQL script (str)."""
        self._require_open()
        try:
            self._conn.executescript(sql)
        except Exception as e:
            try:
                ts = int(time.time())
                self._conn.execute(
                    "INSERT INTO errors (ts, op, entity_id, error_text) VALUES (?, ?, ?, ?)",
                    (ts, "migration", None, repr(e)),
                )
                self._conn.commit()
            except Exception:
                pass
            raise

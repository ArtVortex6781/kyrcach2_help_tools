from __future__ import annotations

import sqlite3
from typing import Optional

from .errors import NodeDBError

__all__: list[str] = []


class _DatabaseExecutor:
    """
    Internal low-level SQL executor for mesh_node_db.

    Responsibilities:
    - execute SQL statements
    - fetch one row
    - fetch many rows
    - centralize sqlite3.Error -> NodeDBError conversion
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        """
        Initialize executor with an active sqlite connection.

        :param conn: active sqlite3 connection owned by the database engine
        """
        self._conn = conn

    def execute(self, sql: str,
                params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute one SQL statement and return the sqlite cursor.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: sqlite3.Cursor for the executed statement
        :raises NodeDBError: if SQLite execution fails.
        """
        try:
            return self._conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise NodeDBError(f"Database execute failed: {exc}") from exc

    def fetchone(self, sql: str,
                 params: tuple = ()) -> Optional[sqlite3.Row]:
        """
        Execute a SELECT statement and return one row or None.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: one sqlite3.Row or None
        :raises NodeDBError: if SQLite execution fails.
        """
        try:
            return self._conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Database fetchone failed: {exc}") from exc

    def fetchall(self, sql: str,
                 params: tuple = ()) -> list[sqlite3.Row]:
        """
        Execute a SELECT statement and return all matching rows.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: list of sqlite3.Row
        :raises NodeDBError: if SQLite execution fails.
        """
        try:
            return self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise NodeDBError(f"Database fetchall failed: {exc}") from exc

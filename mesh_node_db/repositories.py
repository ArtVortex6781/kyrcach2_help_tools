from __future__ import annotations

import sqlite3
from typing import Optional

from ._validation import (
    require_limit,
    require_non_empty_str,
    require_offset,
    require_non_negative_int
)
from .database import _DatabaseExecutor
from .errors import InvalidRecordError, RecordNotFoundError
from .tables import (
    AttachmentRecord,
    ChatMessageWithSenderRecord,
    ChatParticipantRecord,
    ChatRecord,
    ChatWithParticipantCountRecord,
    MessageRecord,
    PeerRecord,
)

__all__ = [
    "BaseRepository",
    "PeerRepository",
    "ChatRepository",
    "ChatParticipantRepository",
    "MessageRepository",
    "AttachmentRepository",
]


class BaseRepository:
    """Thin infrastructure base class for typed repositories."""

    def __init__(self, executor: _DatabaseExecutor) -> None:
        """
        Initialize repository with a database executor.

        :param executor: internal database executor used for SQL operations
        """
        self._executor = executor

    def _execute(self, sql: str,
                 params: tuple = ()) -> sqlite3.Cursor:
        """
        Execute one SQL statement.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: sqlite3.Cursor for the executed statement
        :raises NodeDBError: if SQLite execution fails.
        """
        return self._executor.execute(sql, params)

    def _fetchone(self, sql: str,
                  params: tuple = ()) -> Optional[sqlite3.Row]:
        """
        Execute a SELECT statement and return one row or None.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: one sqlite3.Row or None
        :raises NodeDBError: if SQLite execution fails.
        """
        return self._executor.fetchone(sql, params)

    def _fetchall(self, sql: str,
                  params: tuple = ()) -> list[sqlite3.Row]:
        """
        Execute a SELECT statement and return all matching rows.

        :param sql: SQL statement text
        :param params: positional SQL parameters
        :return: list of sqlite3.Row
        :raises NodeDBError: if SQLite execution fails.
        """
        return self._executor.fetchall(sql, params)

    @staticmethod
    def _require_row_affected(rowcount: int, *,
                              operation: str, entity_name: str,
                              key_value: str) -> None:
        """
        Ensure that an UPDATE or DELETE statement affected at least one row.

        :param rowcount: cursor.rowcount value
        :param operation: logical operation name
        :param entity_name: logical entity name
        :param key_value: entity key value for error messages
        :raises RecordNotFoundError: if no rows were affected.
        """
        if rowcount == 0:
            raise RecordNotFoundError(
                f"{entity_name} not found for {operation}: {key_value}"
            )


class PeerRepository(BaseRepository):
    """Repository for peer records."""

    def add(self, record: PeerRecord) -> None:
        """
        Insert one peer record.

        :param record: peer record to insert
        """
        self._execute(
            """
            INSERT INTO peers (
                peer_id,
                display_name,
                public_key,
                created_at,
                updated_at,
                is_deleted,
                deleted_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            self._params_from_record(record),
        )

    def read(self, peer_id: str) -> Optional[PeerRecord]:
        """
        Read one peer by peer_id.

        :param peer_id: logical peer identifier
        :return: PeerRecord or None
        :raises InvalidRecordError: if peer_id is invalid.
        """
        require_non_empty_str(peer_id, field_name = "peer_id")

        row = self._fetchone(
            """
            SELECT
                peer_id,
                display_name,
                public_key,
                created_at,
                updated_at,
                is_deleted,
                deleted_at
            FROM peers
            WHERE peer_id = ?
            """,
            (peer_id,),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def update(self, record: PeerRecord) -> None:
        """
        Update mutable peer fields.

        :param record: peer record with updated values
        :raises RecordNotFoundError: if the peer does not exist.
        """
        cur = self._execute(
            """
            UPDATE peers
            SET display_name = ?,
                public_key = ?,
                updated_at = ?
            WHERE peer_id = ?
            """,
            (
                record.display_name,
                record.public_key,
                record.updated_at,
                record.peer_id,
            ),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "update",
            entity_name = "peer",
            key_value = record.peer_id,
        )

    def soft_delete(self, peer_id: str, deleted_at: int) -> None:
        """
        Mark one peer as deleted using tombstone semantics.

        This operation does not physically remove the peer row. Historical
        metadata remains available for message history. Existing chat
        memberships of this peer are removed separately.

        This method must be called only inside NodeDatabase.run_in_transaction(...)
        when used as part of peer removal workflow.

        :param peer_id: logical peer identifier
        :param deleted_at: tombstone timestamp
        :raises InvalidRecordError: if input values are invalid.
        :raises RecordNotFoundError: if the peer does not exist.
        """
        require_non_empty_str(peer_id, field_name = "peer_id")
        require_non_negative_int(deleted_at, field_name = "deleted_at")

        cur = self._execute(
            """
            UPDATE peers
            SET is_deleted = ?,
                deleted_at = ?,
                updated_at = ?
            WHERE peer_id = ?
            """,
            (
                1,
                deleted_at,
                deleted_at,
                peer_id,
            ),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "soft_delete",
            entity_name = "peer",
            key_value = peer_id,
        )

        self._execute(
            """
            DELETE FROM chat_participants
            WHERE peer_id = ?
            """,
            (peer_id,),
        )

    def list_active(self, limit: int = 100,
                    offset: int = 0) -> list[PeerRecord]:
        """
        List active peers ordered by created_at and peer_id.

        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of PeerRecord
        :raises InvalidRecordError: if limit or offset is invalid.
        """
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT
                peer_id,
                display_name,
                public_key,
                created_at,
                updated_at,
                is_deleted,
                deleted_at
            FROM peers
            WHERE is_deleted = 0
            ORDER BY created_at ASC, peer_id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [self._row_to_record(row) for row in rows]

    def list_deleted(self, limit: int = 100,
                     offset: int = 0) -> list[PeerRecord]:
        """
        List tombstoned peers ordered by deleted_at and peer_id.

        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of PeerRecord
        :raises InvalidRecordError: if limit or offset is invalid.
        """
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT
                peer_id,
                display_name,
                public_key,
                created_at,
                updated_at,
                is_deleted,
                deleted_at
            FROM peers
            WHERE is_deleted = 1
            ORDER BY deleted_at ASC, peer_id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _params_from_record(record: PeerRecord) -> tuple:
        """
        Build SQL parameters from PeerRecord.

        :param record: peer record to serialize
        :return: positional SQL parameters tuple
        """
        return (
            record.peer_id,
            record.display_name,
            record.public_key,
            record.created_at,
            record.updated_at,
            int(record.is_deleted),
            record.deleted_at,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> PeerRecord:
        """
        Convert one SQLite row into PeerRecord.

        :param row: sqlite row to convert
        :return: PeerRecord
        """
        return PeerRecord(
            peer_id = str(row["peer_id"]),
            display_name = bytes(row["display_name"]),
            public_key = bytes(row["public_key"]),
            created_at = int(row["created_at"]),
            updated_at = int(row["updated_at"]),
            is_deleted = bool(row["is_deleted"]),
            deleted_at = (
                None if row["deleted_at"] is None else int(row["deleted_at"])
            ),
        )


class ChatRepository(BaseRepository):
    """Repository for chat records."""

    def add(self, record: ChatRecord) -> None:
        """
        Insert one chat record.

        :param record: chat record to insert
        """
        self._execute(
            """
            INSERT INTO chats (
                chat_id,
                chat_type,
                chat_name,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            self._params_from_record(record),
        )

    def read(self, chat_id: str) -> Optional[ChatRecord]:
        """
        Read one chat by chat_id.

        :param chat_id: logical chat identifier
        :return: ChatRecord or None
        :raises InvalidRecordError: if chat_id is invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")

        row = self._fetchone(
            """
            SELECT chat_id, chat_type, chat_name, created_at, updated_at
            FROM chats
            WHERE chat_id = ?
            """,
            (chat_id,),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def update(self, record: ChatRecord) -> None:
        """
        Update one chat record.

        :param record: chat record with updated values
        :raises RecordNotFoundError: if the chat does not exist.
        """
        cur = self._execute(
            """
            UPDATE chats
            SET chat_name = ?,
                updated_at = ?
            WHERE chat_id = ?
            """,
            (
                record.chat_name,
                record.updated_at,
                record.chat_id,
            ),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "update",
            entity_name = "chat",
            key_value = record.chat_id,
        )

    def delete(self, chat_id: str) -> None:
        """
       Cascade deletion of a chat with the corresponding ID,
       i.e., all messages in it and all its participants are deleted

        :param chat_id: logical chat identifier
        :raises InvalidRecordError: if chat_id is invalid.
        :raises RecordNotFoundError: if the chat does not exist.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")

        cur = self._execute(
            "DELETE FROM chats WHERE chat_id = ?",
            (chat_id,),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "delete",
            entity_name = "chat",
            key_value = chat_id,
        )

    def list_all(self, limit: int = 100,
                 offset: int = 0) -> list[ChatRecord]:
        """
        List chats ordered by created_at and chat_id.

        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of ChatRecord
        :raises InvalidRecordError: if limit or offset is invalid.
        """
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT chat_id, chat_type, chat_name, created_at, updated_at
            FROM chats
            ORDER BY created_at ASC, chat_id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [self._row_to_record(row) for row in rows]

    def list_by_type(self, chat_type: str,
                     limit: int = 100, offset: int = 0) -> list[ChatRecord]:
        """
        List chats filtered by chat_type.

        :param chat_type: logical chat type value
        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of ChatRecord
        :raises InvalidRecordError: if chat_type, limit or offset is invalid.
        """
        require_non_empty_str(chat_type, field_name = "chat_type")
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT chat_id, chat_type, chat_name, created_at, updated_at
            FROM chats
            WHERE chat_type = ?
            ORDER BY created_at ASC, chat_id ASC
            LIMIT ? OFFSET ?
            """,
            (chat_type, limit, offset),
        )
        return [self._row_to_record(row) for row in rows]

    def list_with_participant_count(self, limit: int = 100,
                                    offset: int = 0) -> list[ChatWithParticipantCountRecord]:
        """
        List chats together with participant count.

        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of ChatWithParticipantCountRecord
        :raises InvalidRecordError: if limit or offset is invalid.
        """
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT
                c.chat_id,
                c.chat_type,
                c.chat_name,
                c.created_at,
                c.updated_at,
                COUNT(cp.peer_id) AS participant_count
            FROM chats AS c
            LEFT JOIN chat_participants AS cp
                ON c.chat_id = cp.chat_id
            GROUP BY
                c.chat_id,
                c.chat_type,
                c.chat_name,
                c.created_at,
                c.updated_at
            ORDER BY c.created_at ASC, c.chat_id ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [self._row_to_count_record(row) for row in rows]

    @staticmethod
    def _params_from_record(record: ChatRecord) -> tuple:
        """
        Build SQL parameters from ChatRecord.

        :param record: chat record to serialize
        :return: positional SQL parameters tuple
        """
        return (
            record.chat_id,
            record.chat_type,
            record.chat_name,
            record.created_at,
            record.updated_at,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ChatRecord:
        """
        Convert one SQLite row into ChatRecord.

        :param row: sqlite row to convert
        :return: ChatRecord
        """
        return ChatRecord(
            chat_id = str(row["chat_id"]),
            chat_type = str(row["chat_type"]),
            chat_name = bytes(row["chat_name"]),
            created_at = int(row["created_at"]),
            updated_at = int(row["updated_at"]),
        )

    @staticmethod
    def _row_to_count_record(row: sqlite3.Row) -> ChatWithParticipantCountRecord:
        """
        Convert one SQLite row into ChatWithParticipantCountRecord.

        :param row: sqlite row to convert
        :return: ChatWithParticipantCountRecord
        """
        return ChatWithParticipantCountRecord(
            chat_id = str(row["chat_id"]),
            chat_type = str(row["chat_type"]),
            chat_name = bytes(row["chat_name"]),
            created_at = int(row["created_at"]),
            updated_at = int(row["updated_at"]),
            participant_count = int(row["participant_count"]),
        )


class ChatParticipantRepository(BaseRepository):
    """Repository for chat participant records."""

    def add(self, record: ChatParticipantRecord) -> None:
        """
        Insert one chat participant record.

        :param record: chat participant record to insert
        """
        self._execute(
            """
            INSERT INTO chat_participants (
                chat_id,
                peer_id,
                joined_at
            )
            VALUES (?, ?, ?)
            """,
            self._params_from_record(record),
        )

    def read(self, chat_id: str,
             peer_id: str) -> Optional[ChatParticipantRecord]:
        """
        Read one chat participant by composite key.

        :param chat_id: logical chat identifier
        :param peer_id: logical peer identifier
        :return: ChatParticipantRecord or None
        :raises InvalidRecordError: if chat_id or peer_id is invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_non_empty_str(peer_id, field_name = "peer_id")

        row = self._fetchone(
            """
            SELECT chat_id, peer_id, joined_at
            FROM chat_participants
            WHERE chat_id = ? AND peer_id = ?
            """,
            (chat_id, peer_id),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def delete(self, chat_id: str,
               peer_id: str) -> None:
        """
        Delete one chat participant by composite key.

        :param chat_id: logical chat identifier
        :param peer_id: logical peer identifier
        :raises InvalidRecordError: if chat_id or peer_id is invalid.
        :raises RecordNotFoundError: if the record does not exist.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_non_empty_str(peer_id, field_name = "peer_id")

        cur = self._execute(
            """
            DELETE FROM chat_participants
            WHERE chat_id = ? AND peer_id = ?
            """,
            (chat_id, peer_id),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "delete",
            entity_name = "chat_participant",
            key_value = f"{chat_id}:{peer_id}",
        )

    def list_by_chat(self, chat_id: str) -> list[ChatParticipantRecord]:
        """
        List participants of one chat.

        :param chat_id: logical chat identifier
        :return: list of ChatParticipantRecord
        :raises InvalidRecordError: if chat_id is invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")

        rows = self._fetchall(
            """
            SELECT chat_id, peer_id, joined_at
            FROM chat_participants
            WHERE chat_id = ?
            ORDER BY joined_at ASC, peer_id ASC
            """,
            (chat_id,),
        )
        return [self._row_to_record(row) for row in rows]

    def list_by_peer(self, peer_id: str) -> list[ChatParticipantRecord]:
        """
        List chat memberships of one peer.

        :param peer_id: logical peer identifier
        :return: list of ChatParticipantRecord
        :raises InvalidRecordError: if peer_id is invalid.
        """
        require_non_empty_str(peer_id, field_name = "peer_id")

        rows = self._fetchall(
            """
            SELECT chat_id, peer_id, joined_at
            FROM chat_participants
            WHERE peer_id = ?
            ORDER BY joined_at ASC, chat_id ASC
            """,
            (peer_id,),
        )
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _params_from_record(record: ChatParticipantRecord) -> tuple:
        """
        Build SQL parameters from ChatParticipantRecord.

        :param record: chat participant record to serialize
        :return: positional SQL parameters tuple
        """
        return (
            record.chat_id,
            record.peer_id,
            record.joined_at,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ChatParticipantRecord:
        """
        Convert one SQLite row into ChatParticipantRecord.

        :param row: sqlite row to convert
        :return: ChatParticipantRecord
        """
        return ChatParticipantRecord(
            chat_id = str(row["chat_id"]),
            peer_id = str(row["peer_id"]),
            joined_at = int(row["joined_at"]),
        )


class MessageRepository(BaseRepository):
    """Repository for message records."""

    def add(self, record: MessageRecord) -> None:
        """
        Insert one message record.

        :param record: message record to insert
        """
        self._execute(
            """
            INSERT INTO messages (
                message_id,
                chat_id,
                sender_id,
                created_at,
                updated_at,
                payload,
                attachment_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            self._params_from_record(record),
        )

    def read(self, message_id: str) -> Optional[MessageRecord]:
        """
        Read one message by message_id.

        :param message_id: logical message identifier
        :return: MessageRecord or None
        :raises InvalidRecordError: if message_id is invalid.
        """
        require_non_empty_str(message_id, field_name = "message_id")

        row = self._fetchone(
            """
            SELECT
                message_id,
                chat_id,
                sender_id,
                created_at,
                updated_at,
                payload,
                attachment_hash
            FROM messages
            WHERE message_id = ?
            """,
            (message_id,),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def update(self, record: MessageRecord) -> None:
        """
        Update mutable content fields of one message record.

        :param record: message record with updated content values
        :raises RecordNotFoundError: if the message does not exist.
        """
        cur = self._execute(
            """
            UPDATE messages
            SET updated_at = ?,
                payload = ?,
                attachment_hash = ?
            WHERE message_id = ?
            """,
            (
                record.updated_at,
                record.payload,
                record.attachment_hash,
                record.message_id,
            ),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "update",
            entity_name = "message",
            key_value = record.message_id,
        )

    def delete(self, message_id: str) -> None:
        """
        Delete one message by message_id.

        :param message_id: logical message identifier
        :raises InvalidRecordError: if message_id is invalid.
        :raises RecordNotFoundError: if the message does not exist.
        """
        require_non_empty_str(message_id, field_name = "message_id")

        cur = self._execute(
            "DELETE FROM messages WHERE message_id = ?",
            (message_id,),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "delete",
            entity_name = "message",
            key_value = message_id,
        )

    def list_by_chat(self, chat_id: str, limit: int = 100, before_created_at: Optional[int] = None,
                     before_message_id: Optional[str] = None) -> list[MessageRecord]:
        """
        List messages of one chat ordered from newest to oldest.

        Pagination model:
        - first page: pass only chat_id and limit
        - next page: pass both before_created_at and before_message_id

        :param chat_id: logical chat identifier
        :param limit: maximum number of rows to return
        :param before_created_at: pagination cursor timestamp
        :param before_message_id: pagination cursor message id
        :return: list of MessageRecord
        :raises InvalidRecordError: if input values are invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_limit(limit, max_value = 1000)

        if before_created_at is None and before_message_id is None:
            rows = self._fetchall(
                """
                SELECT
                    message_id,
                    chat_id,
                    sender_id,
                    created_at,
                    updated_at,
                    payload,
                    attachment_hash
                FROM messages
                WHERE chat_id = ?
                ORDER BY created_at DESC, message_id DESC
                LIMIT ?
                """,
                (chat_id, limit),
            )
            return [self._row_to_record(row) for row in rows]

        if before_created_at is not None and before_message_id is not None:
            require_non_negative_int(
                before_created_at,
                field_name = "before_created_at",
            )
            require_non_empty_str(
                before_message_id,
                field_name = "before_message_id",
            )

            rows = self._fetchall(
                """
                SELECT
                    message_id,
                    chat_id,
                    sender_id,
                    created_at,
                    updated_at,
                    payload,
                    attachment_hash
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
                    before_created_at,
                    before_created_at,
                    before_message_id,
                    limit,
                ),
            )
            return [self._row_to_record(row) for row in rows]

        raise InvalidRecordError(
            "Pagination requires both before_created_at and before_message_id, or neither."
        )

    def list_by_sender(self, sender_id: str, limit: int = 100,
                       offset: int = 0) -> list[MessageRecord]:
        """
        List messages sent by one peer.

        :param sender_id: logical sender identifier
        :param limit: maximum number of rows to return
        :param offset: number of rows to skip
        :return: list of MessageRecord
        :raises InvalidRecordError: if sender_id, limit or offset is invalid.
        """
        require_non_empty_str(sender_id, field_name = "sender_id")
        require_limit(limit, max_value = 1000)
        require_offset(offset)

        rows = self._fetchall(
            """
            SELECT
                message_id,
                chat_id,
                sender_id,
                created_at,
                updated_at,
                payload,
                attachment_hash
            FROM messages
            WHERE sender_id = ?
            ORDER BY created_at DESC, message_id DESC
            LIMIT ? OFFSET ?
            """,
            (sender_id, limit, offset),
        )
        return [self._row_to_record(row) for row in rows]

    def list_by_chat_and_time_range(self, chat_id: str, start_created_at: int,
                                    end_created_at: int, limit: int = 100) -> list[MessageRecord]:
        """
        List messages of one chat within an inclusive time range.

        :param chat_id: logical chat identifier
        :param start_created_at: inclusive lower bound timestamp
        :param end_created_at: inclusive upper bound timestamp
        :param limit: maximum number of rows to return
        :return: list of MessageRecord
        :raises InvalidRecordError: if input values are invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_non_negative_int(
            start_created_at,
            field_name = "start_created_at",
        )
        require_non_negative_int(
            end_created_at,
            field_name = "end_created_at",
        )
        require_limit(limit, max_value = 1000)

        if start_created_at > end_created_at:
            raise InvalidRecordError(
                "start_created_at must be <= end_created_at"
            )

        rows = self._fetchall(
            """
            SELECT
                message_id,
                chat_id,
                sender_id,
                created_at,
                updated_at,
                payload,
                attachment_hash
            FROM messages
            WHERE chat_id = ?
              AND created_at >= ?
              AND created_at <= ?
            ORDER BY created_at ASC, message_id ASC
            LIMIT ?
            """,
            (chat_id, start_created_at, end_created_at, limit),
        )
        return [self._row_to_record(row) for row in rows]

    def list_by_chat_with_sender_display_name(self, chat_id: str, limit: int = 100,
                                              before_created_at: Optional[int] = None,
                                              before_message_id: Optional[str] = None) -> (
            list)[ChatMessageWithSenderRecord]:
        """
        List chat messages together with sender display name.

        Pagination model:
        - first page: pass only chat_id and limit
        - next page: pass both before_created_at and before_message_id

        :param chat_id: logical chat identifier
        :param limit: maximum number of rows to return
        :param before_created_at: pagination cursor timestamp
        :param before_message_id: pagination cursor message id
        :return: list of ChatMessageWithSenderRecord
        :raises InvalidRecordError: if input values are invalid.
        """
        require_non_empty_str(chat_id, field_name = "chat_id")
        require_limit(limit, max_value = 1000)

        if before_created_at is None and before_message_id is None:
            rows = self._fetchall(
                """
                SELECT
                    m.message_id,
                    m.chat_id,
                    m.sender_id,
                    p.display_name AS sender_display_name,
                    m.created_at,
                    m.updated_at,
                    m.payload,
                    m.attachment_hash
                FROM messages AS m
                JOIN peers AS p
                    ON m.sender_id = p.peer_id
                WHERE m.chat_id = ?
                ORDER BY m.created_at DESC, m.message_id DESC
                LIMIT ?
                """,
                (chat_id, limit),
            )
            return [self._row_to_sender_record(row) for row in rows]

        if before_created_at is not None and before_message_id is not None:
            require_non_negative_int(
                before_created_at,
                field_name = "before_created_at",
            )
            require_non_empty_str(
                before_message_id,
                field_name = "before_message_id",
            )

            rows = self._fetchall(
                """
                SELECT
                    m.message_id,
                    m.chat_id,
                    m.sender_id,
                    p.display_name AS sender_display_name,
                    m.created_at,
                    m.updated_at,
                    m.payload,
                    m.attachment_hash
                FROM messages AS m
                JOIN peers AS p
                    ON m.sender_id = p.peer_id
                WHERE m.chat_id = ?
                  AND (
                      m.created_at < ?
                      OR (m.created_at = ? AND m.message_id < ?)
                  )
                ORDER BY m.created_at DESC, m.message_id DESC
                LIMIT ?
                """,
                (
                    chat_id,
                    before_created_at,
                    before_created_at,
                    before_message_id,
                    limit,
                ),
            )
            return [self._row_to_sender_record(row) for row in rows]

        raise InvalidRecordError(
            "Pagination requires both before_created_at and before_message_id, or neither."
        )

    @staticmethod
    def _params_from_record(record: MessageRecord) -> tuple:
        """
        Build SQL parameters from MessageRecord.

        :param record: message record to serialize
        :return: positional SQL parameters tuple
        """
        return (
            record.message_id,
            record.chat_id,
            record.sender_id,
            record.created_at,
            record.updated_at,
            record.payload,
            record.attachment_hash,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> MessageRecord:
        """
        Convert one SQLite row into MessageRecord.

        :param row: sqlite row to convert
        :return: MessageRecord
        """
        return MessageRecord(
            message_id = str(row["message_id"]),
            chat_id = str(row["chat_id"]),
            sender_id = str(row["sender_id"]),
            created_at = int(row["created_at"]),
            updated_at = int(row["updated_at"]),
            payload = bytes(row["payload"]),
            attachment_hash = (
                None if row["attachment_hash"] is None else str(row["attachment_hash"])
            ),
        )

    @staticmethod
    def _row_to_sender_record(row: sqlite3.Row) -> ChatMessageWithSenderRecord:
        """
        Convert one SQLite row into ChatMessageWithSenderRecord.

        :param row: sqlite row to convert
        :return: ChatMessageWithSenderRecord
        """
        return ChatMessageWithSenderRecord(
            message_id = str(row["message_id"]),
            chat_id = str(row["chat_id"]),
            sender_id = str(row["sender_id"]),
            sender_display_name = bytes(row["sender_display_name"]),
            created_at = int(row["created_at"]),
            updated_at = int(row["updated_at"]),
            payload = bytes(row["payload"]),
            attachment_hash = (
                None if row["attachment_hash"] is None else str(row["attachment_hash"])
            ),
        )


class AttachmentRepository(BaseRepository):
    """Repository for attachment records."""

    def add(self, record: AttachmentRecord) -> None:
        """
        Insert one attachment record.

        :param record: attachment record to insert
        """
        self._execute(
            """
            INSERT INTO attachments (
                attachment_hash,
                file_path
            )
            VALUES (?, ?)
            """,
            self._params_from_record(record),
        )

    def read(self, attachment_hash: str) -> Optional[AttachmentRecord]:
        """
        Read one attachment by attachment_hash.

        :param attachment_hash: logical attachment identifier
        :return: AttachmentRecord or None
        :raises InvalidRecordError: if attachment_hash is invalid.
        """
        require_non_empty_str(attachment_hash, field_name = "attachment_hash")

        row = self._fetchone(
            """
            SELECT attachment_hash, file_path
            FROM attachments
            WHERE attachment_hash = ?
            """,
            (attachment_hash,),
        )
        if row is None:
            return None
        return self._row_to_record(row)

    def delete(self, attachment_hash: str) -> None:
        """
        Delete one attachment by attachment_hash.

        :param attachment_hash: logical attachment identifier
        :raises InvalidRecordError: if attachment_hash is invalid.
        :raises RecordNotFoundError: if the attachment does not exist.
        """
        require_non_empty_str(attachment_hash, field_name = "attachment_hash")

        cur = self._execute(
            "DELETE FROM attachments WHERE attachment_hash = ?",
            (attachment_hash,),
        )
        self._require_row_affected(
            cur.rowcount,
            operation = "delete",
            entity_name = "attachment",
            key_value = attachment_hash,
        )

    @staticmethod
    def _params_from_record(record: AttachmentRecord) -> tuple:
        """
        Build SQL parameters from AttachmentRecord.

        :param record: attachment record to serialize
        :return: positional SQL parameters tuple
        """
        return (
            record.attachment_hash,
            record.file_path,
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> AttachmentRecord:
        """
        Convert one SQLite row into AttachmentRecord.

        :param row: sqlite row to convert
        :return: AttachmentRecord
        """
        return AttachmentRecord(
            attachment_hash = str(row["attachment_hash"]),
            file_path = bytes(row["file_path"]),
        )

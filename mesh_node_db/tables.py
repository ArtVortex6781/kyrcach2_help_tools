from __future__ import annotations

from dataclasses import dataclass

from ._validation import (
    require_bytes,
    require_non_negative_int,
    require_non_empty_str,
    require_optional_str,
    require_optional_non_negative_int,
    require_instance
)
from .errors import InvalidRecordError

__all__ = [
    "PeerRecord",
    "ChatRecord",
    "ChatParticipantRecord",
    "MessageRecord",
    "AttachmentRecord",
    "ChatMessageWithSenderRecord",
    "ChatWithParticipantCountRecord",
]


def _validate_created_updated_timestamps(*, created_at: int, updated_at: int) -> None:
    """
    Validate paired created/updated timestamps.

    :param created_at: creation timestamp
    :param updated_at: last update timestamp
    :raises InvalidRecordError: if timestamp invariants are violated
    """
    require_non_negative_int(created_at, field_name = "created_at")
    require_non_negative_int(updated_at, field_name = "updated_at")

    if updated_at < created_at:
        raise InvalidRecordError("updated_at must be >= created_at")


def _validate_chat_like_fields(*, chat_id: str, chat_type: str, chat_name: bytes,
                               created_at: int, updated_at: int) -> None:
    """
    Validate structural invariants shared by chat-like records.

    :param chat_id: chat identifier
    :param chat_type: chat type string
    :param chat_name: chat display name bytes
    :param created_at: creation timestamp
    :param updated_at: last update timestamp
    :raises InvalidRecordError: if any invariant is violated
    """
    require_non_empty_str(chat_id, field_name = "chat_id")
    require_non_empty_str(chat_type, field_name = "chat_type")
    require_bytes(chat_name, field_name = "chat_name")
    _validate_created_updated_timestamps(
        created_at = created_at,
        updated_at = updated_at,
    )


@dataclass(frozen = True)
class PeerRecord:
    """In-memory representation of one peer record."""

    peer_id: str
    display_name: bytes
    public_key: bytes
    created_at: int
    updated_at: int
    is_deleted: bool
    deleted_at: int | None

    def __post_init__(self) -> None:
        """
        Validate structural invariants of PeerRecord.
        """
        require_non_empty_str(self.peer_id, field_name = "peer_id")
        require_bytes(self.display_name, field_name = "display_name")
        require_bytes(self.public_key, field_name = "public_key")
        _validate_created_updated_timestamps(
            created_at = self.created_at,
            updated_at = self.updated_at,
        )
        require_instance(self.is_deleted, bool, field_name = "is_deleted")
        require_optional_non_negative_int(self.deleted_at, field_name = "deleted_at")

        if not self.is_deleted and self.deleted_at is not None:
            raise InvalidRecordError(
                "deleted_at must be None when is_deleted = 0"
            )

        if self.is_deleted and self.deleted_at is None:
            raise InvalidRecordError(
                "deleted_at must be set when is_deleted = 1"
            )


@dataclass(frozen = True)
class ChatRecord:
    """In-memory representation of one chat record."""

    chat_id: str
    chat_type: str
    chat_name: bytes
    created_at: int
    updated_at: int

    def __post_init__(self) -> None:
        """
        Validate structural invariants of ChatRecord.
        """
        _validate_chat_like_fields(
            chat_id = self.chat_id,
            chat_type = self.chat_type,
            chat_name = self.chat_name,
            created_at = self.created_at,
            updated_at = self.updated_at,
        )


@dataclass(frozen = True)
class ChatParticipantRecord:
    """In-memory representation of one chat participant record."""

    chat_id: str
    peer_id: str
    joined_at: int

    def __post_init__(self) -> None:
        """
        Validate structural invariants of ChatParticipantRecord.
        """
        require_non_empty_str(self.chat_id, field_name = "chat_id")
        require_non_empty_str(self.peer_id, field_name = "peer_id")
        require_non_negative_int(self.joined_at, field_name = "joined_at")


@dataclass(frozen = True)
class MessageRecord:
    """In-memory representation of one message record."""

    message_id: str
    chat_id: str
    sender_id: str
    created_at: int
    updated_at: int
    payload: bytes
    attachment_hash: str | None

    def __post_init__(self) -> None:
        """
        Validate structural invariants of MessageRecord.
        """
        require_non_empty_str(self.message_id, field_name = "message_id")
        require_non_empty_str(self.chat_id, field_name = "chat_id")
        require_non_empty_str(self.sender_id, field_name = "sender_id")
        _validate_created_updated_timestamps(
            created_at = self.created_at,
            updated_at = self.updated_at,
        )
        require_bytes(self.payload, field_name = "payload")
        require_optional_str(self.attachment_hash, field_name = "attachment_hash")


@dataclass(frozen = True)
class AttachmentRecord:
    """In-memory representation of one attachment record."""

    attachment_hash: str
    file_path: bytes

    def __post_init__(self) -> None:
        """
        Validate structural invariants of AttachmentRecord.
        """
        require_non_empty_str(self.attachment_hash, field_name = "attachment_hash")
        require_bytes(self.file_path, field_name = "file_path")


@dataclass(frozen = True)
class ChatMessageWithSenderRecord:
    """In-memory representation of a chat message with sender display name."""

    message_id: str
    chat_id: str
    sender_id: str
    sender_display_name: bytes
    created_at: int
    payload: bytes
    attachment_hash: str | None

    def __post_init__(self) -> None:
        """
        Validate structural invariants of ChatMessageWithSenderRecord.
        """
        require_non_empty_str(self.message_id, field_name = "message_id")
        require_non_empty_str(self.chat_id, field_name = "chat_id")
        require_non_empty_str(self.sender_id, field_name = "sender_id")
        require_bytes(self.sender_display_name, field_name = "sender_display_name")
        require_non_negative_int(self.created_at, field_name = "created_at")
        require_bytes(self.payload, field_name = "payload")
        require_optional_str(self.attachment_hash, field_name = "attachment_hash")


@dataclass(frozen = True)
class ChatWithParticipantCountRecord:
    """In-memory representation of a chat record with participant count."""

    chat_id: str
    chat_type: str
    chat_name: bytes
    created_at: int
    updated_at: int
    participant_count: int

    def __post_init__(self) -> None:
        """
        Validate structural invariants of ChatWithParticipantCountRecord.
        """
        _validate_chat_like_fields(
            chat_id = self.chat_id,
            chat_type = self.chat_type,
            chat_name = self.chat_name,
            created_at = self.created_at,
            updated_at = self.updated_at,
        )
        require_non_negative_int(self.participant_count, field_name = "participant_count")

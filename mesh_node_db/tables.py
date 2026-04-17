from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "PeerRecord",
    "ChatRecord",
    "ChatParticipantRecord",
    "MessageRecord",
    "AttachmentRecord",
]


@dataclass(frozen = True)
class PeerRecord:
    """In-memory representation of one peer record."""

    peer_id: str
    display_name: bytes
    public_key: bytes
    created_at: int
    updated_at: int


@dataclass(frozen = True)
class ChatRecord:
    """In-memory representation of one chat record."""

    chat_id: str
    chat_type: str
    chat_name: bytes
    created_at: int
    updated_at: int


@dataclass(frozen = True)
class ChatParticipantRecord:
    """In-memory representation of one chat participant record."""

    chat_id: str
    peer_id: str
    joined_at: int


@dataclass(frozen = True)
class MessageRecord:
    """In-memory representation of one message record."""

    message_id: str
    chat_id: str
    sender_id: str
    created_at: int
    payload: bytes
    attachment_hash: str | None


@dataclass(frozen = True)
class AttachmentRecord:
    """In-memory representation of one attachment record."""

    attachment_hash: str
    file_path: bytes

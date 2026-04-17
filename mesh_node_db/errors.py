from __future__ import annotations

__all__ = [
    "NodeDBError",
    "InvalidRecordError",
    "RecordNotFoundError",
    "SchemaError",
    "MigrationError",
    "TransactionError",
]


class NodeDBError(Exception):
    """Base error for mesh_node_db operations."""


class InvalidRecordError(NodeDBError):
    """Raised when a typed record or record input is invalid."""


class RecordNotFoundError(NodeDBError):
    """Raised when a requested record does not exist."""


class SchemaError(NodeDBError):
    """Raised when schema bootstrap or schema validation fails."""


class MigrationError(NodeDBError):
    """Raised when a schema migration fails."""


class TransactionError(NodeDBError):
    """Raised when a database transaction fails."""

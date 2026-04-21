from __future__ import annotations

__all__ = [
    "NodeDBError",
    "InvalidRecordError",
    "RecordNotFoundError",
    "SchemaError",
    "MigrationError",
    "TransactionError",
    "DatabaseExecutionError",
    "ConstraintError",
    "OperationalStorageError",
]


class NodeDBError(Exception):
    """Base error for mesh_node_db operations."""


class InvalidRecordError(NodeDBError):
    """Raised when a typed record or storage input is invalid."""


class RecordNotFoundError(NodeDBError):
    """Raised when a requested record does not exist."""


class SchemaError(NodeDBError):
    """Raised when schema bootstrap or schema validation fails."""


class MigrationError(SchemaError):
    """Raised when a schema migration fails."""


class TransactionError(NodeDBError):
    """Raised when a grouped database transaction fails."""


class DatabaseExecutionError(NodeDBError):
    """Raised when a low-level database execution step fails."""


class ConstraintError(DatabaseExecutionError):
    """Raised when a database constraint is violated."""


class OperationalStorageError(DatabaseExecutionError):
    """Raised when a low-level operational database error occurs."""

from __future__ import annotations

__all__ = [
    "NodeDBError",
    "ConfigurationError",
    "DatabaseConfigurationError",
    "StorageCryptoConfigurationError",
    "EncryptedFieldConfigurationError",
    "InvalidRecordError",
    "RecordNotFoundError",
    "SchemaError",
    "MigrationError",
    "TransactionError",
    "DatabaseExecutionError",
    "ConstraintError",
    "OperationalStorageError",
    "StorageCryptoProviderError",
    "EncryptedFieldError",
]


class NodeDBError(Exception):
    """Base error for mesh_node_db operations."""


class ConfigurationError(NodeDBError):
    """Raised when database configuration input is invalid."""


class DatabaseConfigurationError(ConfigurationError):
    """Raised when NodeDatabase configuration is invalid."""


class StorageCryptoConfigurationError(ConfigurationError):
    """Raised when storage crypto adapter or provider configuration is invalid."""


class EncryptedFieldConfigurationError(ConfigurationError):
    """Raised when encrypted field configuration or AAD policy is invalid."""


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


class StorageCryptoProviderError(NodeDBError):
    """Raised when a configured storage crypto provider fails."""

    def __init__(self, message: str, *,
                 operation: str, cause_type: str) -> None:
        """
        Initialize storage crypto provider error.

        :param message: error message
        :param operation: provider operation name
        :param cause_type: original provider exception type name
        """
        super().__init__(message)
        self.operation = operation
        self.cause_type = cause_type


class EncryptedFieldError(NodeDBError):
    """Raised when an encrypted database field cannot be processed safely."""

    def __init__(self, message: str, *, field_name: str,
                 operation: str, cause_type: str) -> None:
        """
        Initialize encrypted field error.

        :param message: error message
        :param field_name: logical encrypted field name
        :param operation: encrypted field operation name
        :param cause_type: original cause exception type name
        """
        super().__init__(message)
        self.field_name = field_name
        self.operation = operation
        self.cause_type = cause_type

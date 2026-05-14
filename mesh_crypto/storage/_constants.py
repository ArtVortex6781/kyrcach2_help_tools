from __future__ import annotations

__all__ = [
    "STORAGE_FIELD_VERSION",
    "STORAGE_FIELD_TYPE",
    "STORAGE_FIELD_ALGORITHM",
    "STORAGE_KEY_LENGTH",
    "STORAGE_AAD_CONTEXT",
    "STORAGE_FIELD_KEYS"
]

STORAGE_FIELD_VERSION = 1
STORAGE_FIELD_TYPE = "storage_field"
STORAGE_FIELD_ALGORITHM = "mesh-storage-v1"
STORAGE_KEY_LENGTH = 32
STORAGE_AAD_CONTEXT = b"mesh_crypto:storage_field_aad:v1"

STORAGE_FIELD_KEYS = {
    "version",
    "type",
    "algorithm",
    "key_id",
    "aead",
}

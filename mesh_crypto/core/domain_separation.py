from __future__ import annotations

__all__ = [
    "HKDF_INFO_SESSION_KEY",
    "HKDF_INFO_WRAP_KEY",
    "HKDF_INFO_STORAGE_KEY",
    "HKDF_INFO_HANDSHAKE_BINDING",
    "SIGNING_CONTEXT_IDENTITY",
    "SIGNING_CONTEXT_PREKEY",
    "SIGNING_CONTEXT_HANDSHAKE",
    "SIGNING_CONTEXT_METADATA",
    "AAD_PURPOSE_STORAGE",
    "AAD_PURPOSE_WRAPPED_KEY",
]

# HKDF info labels
HKDF_INFO_SESSION_KEY = b"mesh_crypto:hkdf:session_key:v1"
HKDF_INFO_WRAP_KEY = b"mesh_crypto:hkdf:wrap_key:v1"
HKDF_INFO_STORAGE_KEY = b"mesh_crypto:hkdf:storage_key:v1"
HKDF_INFO_HANDSHAKE_BINDING = b"mesh_crypto:hkdf:handshake_binding:v1"

# Ed25519 signing context labels
SIGNING_CONTEXT_IDENTITY = b"mesh_crypto:sign:identity:v1"
SIGNING_CONTEXT_PREKEY = b"mesh_crypto:sign:prekey:v1"
SIGNING_CONTEXT_HANDSHAKE = b"mesh_crypto:sign:handshake:v1"
SIGNING_CONTEXT_METADATA = b"mesh_crypto:sign:metadata:v1"

# AEAD/AAD purpose labels
AAD_PURPOSE_STORAGE = b"mesh_crypto:aad:storage:v1"
AAD_PURPOSE_WRAPPED_KEY = b"mesh_crypto:aad:wrapped_key:v1"

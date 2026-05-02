from __future__ import annotations

__all__ = [
    "HKDF_INFO_SESSION_KEY",
    "HKDF_INFO_WRAP_KEY",
    "HKDF_INFO_STORAGE_KEY",
    "HKDF_INFO_HANDSHAKE_BINDING",
    "HKDF_INFO_STORAGE_FIELD_KEY",
    "HKDF_INFO_DIRECT_SESSION_ID",
    "HKDF_INFO_DIRECT_ROOT_KEY",
    "HKDF_INFO_DIRECT_CHAIN_I2R",
    "HKDF_INFO_DIRECT_CHAIN_R2I",
    "HKDF_INFO_DIRECT_MESSAGE_KEY",
    "HKDF_INFO_DIRECT_NEXT_CHAIN_KEY",
    "HKDF_INFO_DIRECT_RATCHET_ROOT",
    "HKDF_INFO_DIRECT_RATCHET_CHAIN",
    "HKDF_INFO_DIRECT_SKIPPED_KEY",
    "SIGNING_CONTEXT_IDENTITY",
    "SIGNING_CONTEXT_PREKEY",
    "SIGNING_CONTEXT_HANDSHAKE",
    "SIGNING_CONTEXT_DIRECT_HANDSHAKE",
    "SIGNING_CONTEXT_METADATA",
    "AAD_PURPOSE_STORAGE",
    "AAD_PURPOSE_STORAGE_FIELD",
    "AAD_PURPOSE_WRAPPED_KEY",
    "AAD_PURPOSE_KEY_BLOB",
    "AAD_PURPOSE_DIRECT_MESSAGE",
]

# ==============================
# HKDF info labels
# ==============================

HKDF_INFO_SESSION_KEY = b"mesh_crypto:hkdf:session_key:v1"
HKDF_INFO_WRAP_KEY = b"mesh_crypto:hkdf:wrap_key:v1"
HKDF_INFO_STORAGE_KEY = b"mesh_crypto:hkdf:storage_key:v1"
HKDF_INFO_HANDSHAKE_BINDING = b"mesh_crypto:hkdf:handshake_binding:v1"

# Storage crypto labels
HKDF_INFO_STORAGE_FIELD_KEY = b"mesh_crypto:hkdf:storage_field_key:v1"

# Direct E2EE session labels
HKDF_INFO_DIRECT_SESSION_ID = b"mesh_crypto:hkdf:direct_session_id:v1"
HKDF_INFO_DIRECT_ROOT_KEY = b"mesh_crypto:hkdf:direct_root_key:v1"

# Directional chain labels:
# - I2R = initiator -> responder
# - R2I = responder -> initiator
HKDF_INFO_DIRECT_CHAIN_I2R = b"mesh_crypto:hkdf:direct_chain_i2r:v1"
HKDF_INFO_DIRECT_CHAIN_R2I = b"mesh_crypto:hkdf:direct_chain_r2i:v1"

# Symmetric chain/message-key labels
HKDF_INFO_DIRECT_MESSAGE_KEY = b"mesh_crypto:hkdf:direct_message_key:v1"
HKDF_INFO_DIRECT_NEXT_CHAIN_KEY = b"mesh_crypto:hkdf:direct_next_chain_key:v1"

# DH ratchet labels
HKDF_INFO_DIRECT_RATCHET_ROOT = b"mesh_crypto:hkdf:direct_ratchet_root:v1"
HKDF_INFO_DIRECT_RATCHET_CHAIN = b"mesh_crypto:hkdf:direct_ratchet_chain:v1"

# Skipped-key cache label
HKDF_INFO_DIRECT_SKIPPED_KEY = b"mesh_crypto:hkdf:direct_skipped_key:v1"

# ==============================
# Ed25519 signing context labels
# ==============================

SIGNING_CONTEXT_IDENTITY = b"mesh_crypto:sign:identity:v1"
SIGNING_CONTEXT_PREKEY = b"mesh_crypto:sign:prekey:v1"
SIGNING_CONTEXT_HANDSHAKE = b"mesh_crypto:sign:handshake:v1"
SIGNING_CONTEXT_DIRECT_HANDSHAKE = b"mesh_crypto:sign:direct_handshake:v1"
SIGNING_CONTEXT_METADATA = b"mesh_crypto:sign:metadata:v1"

# ==============================
# AEAD/AAD purpose labels
# ==============================

AAD_PURPOSE_STORAGE = b"mesh_crypto:aad:storage:v1"
AAD_PURPOSE_STORAGE_FIELD = b"mesh_crypto:aad:storage_field:v1"
AAD_PURPOSE_WRAPPED_KEY = b"mesh_crypto:aad:wrapped_key:v1"
AAD_PURPOSE_KEY_BLOB = b"mesh_crypto:aad:key_blob:v1"
AAD_PURPOSE_DIRECT_MESSAGE = b"mesh_crypto:aad:direct_message:v1"

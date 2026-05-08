from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ..core.domain_separation import (
    HKDF_INFO_DIRECT_CHAIN_I2R,
    HKDF_INFO_DIRECT_CHAIN_R2I,
    HKDF_INFO_DIRECT_RATCHET_CHAIN,
    HKDF_INFO_DIRECT_RATCHET_ROOT,
)
from ..core.keys import EncryptionKeyPair
from ..core.serialization import EncryptionKeySerializer
from ..errors import MeshCryptoError, RatchetError
from ..primitives.dh import derive_session_key
from ..primitives.kdf import derive_key_hkdf
from .state import (
    SessionRole,
    SessionState,
    SkippedMessageKey,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

__all__ = [
    "ratchet_public_key_bytes",
    "should_receive_ratchet",
    "apply_outgoing_ratchet",
    "apply_receive_ratchet",
]

_ROOT_KEY_LENGTH = 32
_CHAIN_KEY_LENGTH = 32

_RATCHET_CHAIN_INFO_CONTEXT = b"mesh_crypto:direct_ratchet_chain_info:v1"


def _frame_bytes(value: bytes) -> bytes:
    """
    Encode bytes as a length-prefixed frame.

    :param value: Bytes to frame.
    :return: 4-byte big-endian length followed by value.
    """
    return len(value).to_bytes(4, "big") + value


def _frame_labeled_bytes(label: bytes, value: bytes) -> bytes:
    """
    Encode a labeled byte field as length-prefixed label and value.

    :param label: Field label.
    :param value: Field value.
    :return: Canonically framed labeled field.
    """
    return _frame_bytes(label) + _frame_bytes(value)


def _build_ratchet_chain_info(direction_label: bytes) -> bytes:
    """
    Build canonical HKDF info for DH ratchet chain derivation.

    :param direction_label: Directional chain label.
    :return: Framed HKDF info.
    """
    return (
            _frame_labeled_bytes(b"context", _RATCHET_CHAIN_INFO_CONTEXT)
            + _frame_labeled_bytes(b"purpose", HKDF_INFO_DIRECT_RATCHET_CHAIN)
            + _frame_labeled_bytes(b"direction", direction_label)
    )


def _x25519_public_key_from_bytes(ratchet_pub: bytes) -> "X25519PublicKey":
    """
    Parse raw X25519 public key bytes.

    :param ratchet_pub: Raw X25519 public key bytes.
    :return: X25519 public key object.
    :raises RatchetError: If public key import fails.
    """
    try:
        return EncryptionKeySerializer.import_public_key_raw(ratchet_pub)
    except MeshCryptoError as exc:
        raise RatchetError("invalid X25519 ratchet public key") from exc


def _send_direction_label(role: SessionRole) -> bytes:
    """
    Return directional chain label for local outgoing messages.

    :param role: Local session role.
    :return: Directional HKDF label.
    """
    if role == SessionRole.INITIATOR:
        return HKDF_INFO_DIRECT_CHAIN_I2R
    return HKDF_INFO_DIRECT_CHAIN_R2I


def _recv_direction_label(role: SessionRole) -> bytes:
    """
    Return directional chain label for local incoming messages.

    :param role: Local session role.
    :return: Directional HKDF label.
    """
    if role == SessionRole.INITIATOR:
        return HKDF_INFO_DIRECT_CHAIN_R2I
    return HKDF_INFO_DIRECT_CHAIN_I2R


def _derive_ratchet_root_key(local_key_pair: EncryptionKeyPair, remote_public_key: "X25519PublicKey",
                             *, current_root_key: bytes) -> bytes:
    """
    Derive a refreshed root key from a DH ratchet step.

    :param local_key_pair: Local X25519 ratchet key pair.
    :param remote_public_key: Remote X25519 ratchet public key.
    :param current_root_key: Current root key used as HKDF salt.
    :return: Refreshed 32-byte root key.
    :raises RatchetError: If DH or HKDF derivation fails.
    """
    try:
        return derive_session_key(
            local_key_pair.sk,
            remote_public_key,
            salt = current_root_key,
            info = HKDF_INFO_DIRECT_RATCHET_ROOT,
            length = _ROOT_KEY_LENGTH,
        )
    except MeshCryptoError as exc:
        raise RatchetError("failed to derive DH ratchet root key") from exc


def _derive_ratchet_chain_key(root_key: bytes, direction_label: bytes) -> bytes:
    """
    Derive a chain key from refreshed ratchet root material.

    :param root_key: Refreshed root key.
    :param direction_label: Directional chain label.
    :return: New chain key.
    :raises RatchetError: If HKDF derivation fails.
    """
    try:
        return derive_key_hkdf(
            root_key,
            salt = None,
            info = _build_ratchet_chain_info(direction_label),
            length = _CHAIN_KEY_LENGTH,
        )
    except MeshCryptoError as exc:
        raise RatchetError("failed to derive DH ratchet chain key") from exc


def ratchet_public_key_bytes(key_pair: EncryptionKeyPair) -> bytes:
    """
    Export raw public bytes from an X25519 ratchet key pair.

    :param key_pair: X25519 ratchet key pair.
    :return: Raw public key bytes.
    :raises RatchetError: If public key export fails.
    """
    try:
        return EncryptionKeySerializer.export_public_key_raw(key_pair.pk)
    except MeshCryptoError as exc:
        raise RatchetError("invalid X25519 ratchet key pair") from exc


def should_receive_ratchet(state: SessionState, ratchet_pub: bytes) -> bool:
    """
    Check whether an incoming envelope starts a new remote ratchet chain.

    :param state: Current session state.
    :param ratchet_pub: Incoming envelope ratchet public key bytes.
    :return: True if receive ratchet is required.
    """
    return ratchet_pub != state.remote_ratchet_public_key


def apply_outgoing_ratchet(state: SessionState) -> SessionState:
    """
    Apply an outgoing DH ratchet transition.

    This helper is used by encrypt_direct_message(..., force_ratchet=True).
    It generates a new local X25519 ratchet key pair, refreshes root_key with
    X25519(new local private, current remote public), derives a new send chain,
    records previous_send_chain_length, and resets send_counter to zero.

    :param state: Current session state.
    :return: Candidate state after outgoing ratchet transition.
    :raises RatchetError: If ratchet transition fails.
    """
    try:
        new_local_key_pair = EncryptionKeyPair.generate()
        remote_public_key = _x25519_public_key_from_bytes(state.remote_ratchet_public_key)

        new_root_key = _derive_ratchet_root_key(
            new_local_key_pair,
            remote_public_key,
            current_root_key = state.root_key,
        )
        new_send_chain_key = _derive_ratchet_chain_key(
            new_root_key,
            _send_direction_label(state.role),
        )

        return replace(
            state,
            root_key = new_root_key,
            send_chain_key = new_send_chain_key,
            send_counter = 0,
            previous_send_chain_length = state.send_counter,
            local_ratchet_key_pair = new_local_key_pair,
        )
    except MeshCryptoError as exc:
        if isinstance(exc, RatchetError):
            raise
        raise RatchetError("failed to apply outgoing DH ratchet") from exc


def apply_receive_ratchet(state: SessionState, *, new_remote_ratchet_public_key: bytes,
                          skipped_message_keys: tuple[SkippedMessageKey, ...] | None = None) -> SessionState:
    """
    Apply a receive DH ratchet transition.

    This performs the two-step receive ratchet policy:

    1. Refresh root and derive the new receiving chain using:
       X25519(current local private, new remote public).

    2. Generate a new local ratchet key pair, refresh root again, and derive the
       next sending chain using:
       X25519(new local private, new remote public).

    The returned state is a candidate state. decrypt_direct_message() must only
    expose/commit it after successful AEAD authentication of the current message.

    :param state: Current session state.
    :param new_remote_ratchet_public_key: New remote X25519 ratchet public key bytes.
    :param skipped_message_keys: Optional skipped-key cache already updated for the old chain.
    :return: Candidate state after receive ratchet transition.
    :raises RatchetError: If ratchet transition fails.
    """
    try:
        remote_public_key = _x25519_public_key_from_bytes(new_remote_ratchet_public_key)

        recv_root_key = _derive_ratchet_root_key(
            state.local_ratchet_key_pair,
            remote_public_key,
            current_root_key = state.root_key,
        )
        new_recv_chain_key = _derive_ratchet_chain_key(
            recv_root_key,
            _recv_direction_label(state.role),
        )

        new_local_key_pair = EncryptionKeyPair.generate()

        send_root_key = _derive_ratchet_root_key(
            new_local_key_pair,
            remote_public_key,
            current_root_key = recv_root_key,
        )
        new_send_chain_key = _derive_ratchet_chain_key(
            send_root_key,
            _send_direction_label(state.role),
        )

        next_skipped_keys = (
            state.skipped_message_keys
            if skipped_message_keys is None
            else skipped_message_keys
        )

        return replace(
            state,
            root_key = send_root_key,
            send_chain_key = new_send_chain_key,
            recv_chain_key = new_recv_chain_key,
            send_counter = 0,
            recv_counter = 0,
            previous_send_chain_length = state.send_counter,
            local_ratchet_key_pair = new_local_key_pair,
            remote_ratchet_public_key = new_remote_ratchet_public_key,
            skipped_message_keys = next_skipped_keys,
        )
    except MeshCryptoError as exc:
        if isinstance(exc, RatchetError):
            raise
        raise RatchetError("failed to apply receive DH ratchet") from exc

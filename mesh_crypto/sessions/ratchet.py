from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from .._internal import (
    frame_labeled_bytes,
    remap_crypto_error,
)
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


def _build_ratchet_chain_info(direction_label: bytes) -> bytes:
    """
    Build canonical HKDF info for DH ratchet chain derivation.

    :param direction_label: Directional chain label.
    :return: Framed HKDF info.
    """
    return (
            frame_labeled_bytes(b"context", _RATCHET_CHAIN_INFO_CONTEXT)
            + frame_labeled_bytes(b"purpose", HKDF_INFO_DIRECT_RATCHET_CHAIN)
            + frame_labeled_bytes(b"direction", direction_label)
    )


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


def ratchet_public_key_bytes(key_pair: EncryptionKeyPair) -> bytes:
    """
    Export raw public bytes from an X25519 ratchet key pair.

    :param key_pair: X25519 ratchet key pair.
    :return: Raw public key bytes.
    :raises RatchetError: If public key export fails.
    """
    return remap_crypto_error(
        lambda: EncryptionKeySerializer.export_public_key_raw(key_pair.pk),
        error_cls = RatchetError,
        message = "invalid X25519 ratchet key pair",
    )


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

        remote_public_key: X25519PublicKey = remap_crypto_error(
            lambda: EncryptionKeySerializer.import_public_key_raw(
                state.remote_ratchet_public_key
            ),
            error_cls = RatchetError,
            message = "invalid X25519 ratchet public key",
        )

        new_root_key = remap_crypto_error(
            lambda: derive_session_key(
                new_local_key_pair.sk,
                remote_public_key,
                salt = state.root_key,
                info = HKDF_INFO_DIRECT_RATCHET_ROOT,
                length = _ROOT_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet root key",
        )

        new_send_chain_key = remap_crypto_error(
            lambda: derive_key_hkdf(
                new_root_key,
                salt = None,
                info = _build_ratchet_chain_info(_send_direction_label(state.role)),
                length = _CHAIN_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet send chain key",
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
        remote_public_key: X25519PublicKey = remap_crypto_error(
            lambda: EncryptionKeySerializer.import_public_key_raw(
                new_remote_ratchet_public_key
            ),
            error_cls = RatchetError,
            message = "invalid X25519 ratchet public key",
        )

        recv_root_key = remap_crypto_error(
            lambda: derive_session_key(
                state.local_ratchet_key_pair.sk,
                remote_public_key,
                salt = state.root_key,
                info = HKDF_INFO_DIRECT_RATCHET_ROOT,
                length = _ROOT_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet receive root key",
        )

        new_recv_chain_key = remap_crypto_error(
            lambda: derive_key_hkdf(
                recv_root_key,
                salt = None,
                info = _build_ratchet_chain_info(_recv_direction_label(state.role)),
                length = _CHAIN_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet receive chain key",
        )

        new_local_key_pair = EncryptionKeyPair.generate()

        send_root_key = remap_crypto_error(
            lambda: derive_session_key(
                new_local_key_pair.sk,
                remote_public_key,
                salt = recv_root_key,
                info = HKDF_INFO_DIRECT_RATCHET_ROOT,
                length = _ROOT_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet send root key",
        )

        new_send_chain_key = remap_crypto_error(
            lambda: derive_key_hkdf(
                send_root_key,
                salt = None,
                info = _build_ratchet_chain_info(_send_direction_label(state.role)),
                length = _CHAIN_KEY_LENGTH,
            ),
            error_cls = RatchetError,
            message = "failed to derive DH ratchet send chain key",
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

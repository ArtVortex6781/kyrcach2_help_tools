from __future__ import annotations

from dataclasses import replace

from .._internal import (
    frame_labeled_bytes,
    frame_str,
    frame_uint32,
    frame_uint64,
    require_instance,
    require_optional_instance,
)
from ..core.domain_separation import AAD_PURPOSE_DIRECT_MESSAGE
from ..errors import (
    InvalidSessionStateError,
    OutOfOrderMessageError,
    ReplayDetectedError,
    SkippedKeyLimitError,
)
from ..primitives.aead import decrypt, encrypt
from .chains import advance_chain
from .envelopes import DirectMessageEnvelope
from .ratchet import (
    apply_outgoing_ratchet,
    apply_receive_ratchet,
    ratchet_public_key_bytes,
    should_receive_ratchet,
)
from .state import SessionState, SkippedMessageKey

__all__ = [
    "encrypt_direct_message",
    "decrypt_direct_message",
]

_DIRECT_MESSAGE_VERSION = 1
_DIRECT_MESSAGE_TYPE = "direct_message"
_DIRECT_MESSAGE_ALGORITHM = "mesh-direct-v1"

_DEFAULT_MAX_SKIP = 600


def _build_direct_message_aad(*, session_id: object, counter: int,
                              previous_chain_length: int, ratchet_pub: bytes,
                              aad: bytes | None) -> bytes:
    """
    Build protocol-level AAD for direct message encryption.

    The AAD binds ciphertext to direct message metadata. The caller-provided
    aad is optional application-level context and is framed separately from
    protocol metadata.

    :param session_id: Direct session identifier.
    :param counter: Message counter in the current sending chain.
    :param previous_chain_length: Length of previous sending chain before ratchet transition.
    :param ratchet_pub: Sender current X25519 ratchet public key bytes.
    :param aad: Optional caller-provided application AAD.
    :return: Framed protocol AAD bytes.
    """
    external_aad_present = aad is not None
    external_aad = b"" if aad is None else aad

    return (
            frame_labeled_bytes(b"context", AAD_PURPOSE_DIRECT_MESSAGE)
            + frame_labeled_bytes(b"version", frame_uint32(_DIRECT_MESSAGE_VERSION))
            + frame_labeled_bytes(b"type", frame_str(_DIRECT_MESSAGE_TYPE))
            + frame_labeled_bytes(b"algorithm", frame_str(_DIRECT_MESSAGE_ALGORITHM))
            + frame_labeled_bytes(b"session_id", frame_str(str(session_id)))
            + frame_labeled_bytes(b"counter", frame_uint64(counter))
            + frame_labeled_bytes(b"previous_chain_length", frame_uint64(previous_chain_length))
            + frame_labeled_bytes(b"ratchet_pub", ratchet_pub)
            + frame_labeled_bytes(b"external_aad_present", frame_uint32(1 if external_aad_present else 0))
            + frame_labeled_bytes(b"external_aad", external_aad)
    )


def _find_skipped_message_key(skipped_message_keys: tuple[SkippedMessageKey, ...], *,
                              ratchet_pub: bytes, counter: int) -> SkippedMessageKey | None:
    """
    Find a skipped message key by `(ratchet_pub, counter)`.

    :param skipped_message_keys: Current skipped key cache.
    :param ratchet_pub: Remote ratchet public key bytes.
    :param counter: Message counter.
    :return: Matching skipped key entry or None.
    """
    for skipped in skipped_message_keys:
        if skipped.ratchet_pub == ratchet_pub and skipped.counter == counter:
            return skipped
    return None


def _remove_skipped_message_key(skipped_message_keys: tuple[SkippedMessageKey, ...], *,
                                ratchet_pub: bytes, counter: int) -> tuple[SkippedMessageKey, ...]:
    """
    Remove a consumed skipped message key from cache.

    :param skipped_message_keys: Current skipped key cache.
    :param ratchet_pub: Remote ratchet public key bytes.
    :param counter: Message counter.
    :return: Updated skipped key cache.
    """
    return tuple(
        skipped
        for skipped in skipped_message_keys
        if not (skipped.ratchet_pub == ratchet_pub and skipped.counter == counter)
    )


def _ensure_skipped_capacity(skipped_message_keys: tuple[SkippedMessageKey, ...], *,
                             additional_count: int) -> None:
    """
    Ensure skipped key cache can store additional entries.

    :param skipped_message_keys: Current skipped key cache.
    :param additional_count: Number of keys that would be added.
    :raises SkippedKeyLimitError: If the cache would exceed DEFAULT_MAX_SKIP.
    """
    if additional_count < 0:
        raise OutOfOrderMessageError("cannot derive skipped keys for a stale counter")

    if additional_count > _DEFAULT_MAX_SKIP:
        raise SkippedKeyLimitError("message counter gap exceeds skipped-key limit")

    if len(skipped_message_keys) + additional_count > _DEFAULT_MAX_SKIP:
        raise SkippedKeyLimitError("skipped message key cache limit exceeded")


def _save_skipped_message_keys_until(state: SessionState, *,
                                     until_counter: int) -> SessionState:
    """
    Derive and cache skipped message keys up to, but not including, until_counter.

    This advances the receiving chain to until_counter and stores derived keys
    for counters that may arrive later out of order.

    :param state: Current candidate session state.
    :param until_counter: Counter boundary, exclusive.
    :return: Candidate state with updated skipped cache and receiving chain.
    :raises OutOfOrderMessageError: If until_counter is stale.
    :raises SkippedKeyLimitError: If skipped key limit would be exceeded.
    """
    if until_counter < state.recv_counter:
        raise OutOfOrderMessageError("cannot skip backwards in receiving chain")

    missing_count = until_counter - state.recv_counter
    _ensure_skipped_capacity(
        state.skipped_message_keys,
        additional_count = missing_count,
    )

    recv_chain_key = state.recv_chain_key
    recv_counter = state.recv_counter
    skipped_entries = list(state.skipped_message_keys)

    while recv_counter < until_counter:
        if _find_skipped_message_key(
                tuple(skipped_entries),
                ratchet_pub = state.remote_ratchet_public_key,
                counter = recv_counter,
        ) is not None:
            raise InvalidSessionStateError("duplicate skipped message key entry")

        message_key, recv_chain_key, next_counter = advance_chain(
            recv_chain_key,
            recv_counter,
        )
        skipped_entries.append(
            SkippedMessageKey(
                ratchet_pub = state.remote_ratchet_public_key,
                counter = recv_counter,
                message_key = message_key,
            )
        )
        recv_counter = next_counter

    return replace(
        state,
        recv_chain_key = recv_chain_key,
        recv_counter = recv_counter,
        skipped_message_keys = tuple(skipped_entries),
    )


def _decrypt_with_skipped_key(state: SessionState, envelope: DirectMessageEnvelope,
                              *, aad: bytes | None,
                              skipped: SkippedMessageKey) -> tuple[SessionState, bytes]:
    """
    Decrypt a stale/out-of-order message using a cached skipped key.

    The skipped key is removed only after successful AEAD authentication.

    :param state: Current session state.
    :param envelope: Direct message envelope.
    :param aad: Optional caller-provided application AAD.
    :param skipped: Matching skipped key entry.
    :return: Tuple of updated state and plaintext.
    :raises AuthenticationError: If AEAD authentication fails.
    """
    protocol_aad = _build_direct_message_aad(
        session_id = envelope.session_id,
        counter = envelope.counter,
        previous_chain_length = envelope.previous_chain_length,
        ratchet_pub = envelope.ratchet_pub,
        aad = aad,
    )

    plaintext = decrypt(
        skipped.message_key,
        envelope.aead,
        aad = protocol_aad,
    )

    return (
        replace(
            state,
            skipped_message_keys = _remove_skipped_message_key(
                state.skipped_message_keys,
                ratchet_pub = envelope.ratchet_pub,
                counter = envelope.counter,
            ),
        ),
        plaintext,
    )


def _decrypt_current_or_future_message(state: SessionState, envelope: DirectMessageEnvelope,
                                       *, aad: bytes | None) -> tuple[SessionState, bytes]:
    """
    Decrypt a current or future message in the active receiving chain.

    If the message counter is ahead, skipped keys are derived and cached first.
    State is returned only after successful AEAD authentication.

    :param state: Candidate session state.
    :param envelope: Direct message envelope.
    :param aad: Optional caller-provided application AAD.
    :return: Tuple of updated state and plaintext.
    :raises SkippedKeyLimitError: If counter gap exceeds supported limit.
    :raises AuthenticationError: If AEAD authentication fails.
    """
    candidate_state = _save_skipped_message_keys_until(
        state,
        until_counter = envelope.counter,
    )

    message_key, next_recv_chain_key, next_recv_counter = advance_chain(
        candidate_state.recv_chain_key,
        candidate_state.recv_counter,
    )

    protocol_aad = _build_direct_message_aad(
        session_id = envelope.session_id,
        counter = envelope.counter,
        previous_chain_length = envelope.previous_chain_length,
        ratchet_pub = envelope.ratchet_pub,
        aad = aad,
    )

    plaintext = decrypt(
        message_key,
        envelope.aead,
        aad = protocol_aad,
    )

    return (
        replace(
            candidate_state,
            recv_chain_key = next_recv_chain_key,
            recv_counter = next_recv_counter,
        ),
        plaintext,
    )


def encrypt_direct_message(state: SessionState, plaintext: bytes,
                           *, aad: bytes | None = None,
                           force_ratchet: bool = False) -> tuple[SessionState, DirectMessageEnvelope]:
    """
    Encrypt a direct one-to-one message and advance sending state.

    If force_ratchet is true, an outgoing DH ratchet transition is applied
    atomically before deriving the message key for this message.

    :param state: Current direct session state.
    :param plaintext: Message plaintext bytes.
    :param aad: Optional caller-provided application AAD.
    :param force_ratchet: Whether to initiate an outgoing DH ratchet transition.
    :return: Tuple of updated SessionState and DirectMessageEnvelope.
    :raises InvalidInputError: If plaintext or aad has invalid type.
    :raises RatchetError: If forced outgoing ratchet fails.
    :raises SessionCounterError: If sending counter cannot advance.
    :raises InvalidSessionStateError: If state is malformed.
    """
    require_instance(state, SessionState, field_name = "state", error_cls = InvalidSessionStateError)
    require_instance(plaintext, bytes, field_name = "plaintext")
    require_optional_instance(aad, bytes, field_name = "aad")
    require_instance(force_ratchet, bool, field_name = "force_ratchet")

    candidate_state = apply_outgoing_ratchet(state) if force_ratchet else state

    message_key, next_send_chain_key, next_send_counter = advance_chain(
        candidate_state.send_chain_key,
        candidate_state.send_counter,
    )
    ratchet_pub = ratchet_public_key_bytes(candidate_state.local_ratchet_key_pair)

    protocol_aad = _build_direct_message_aad(
        session_id = candidate_state.session_id,
        counter = candidate_state.send_counter,
        previous_chain_length = candidate_state.previous_send_chain_length,
        ratchet_pub = ratchet_pub,
        aad = aad,
    )

    aead = encrypt(
        message_key,
        plaintext,
        aad = protocol_aad,
    )

    envelope = DirectMessageEnvelope(
        version = _DIRECT_MESSAGE_VERSION,
        type = _DIRECT_MESSAGE_TYPE,
        session_id = candidate_state.session_id,
        counter = candidate_state.send_counter,
        previous_chain_length = candidate_state.previous_send_chain_length,
        algorithm = _DIRECT_MESSAGE_ALGORITHM,
        ratchet_pub = ratchet_pub,
        aead = aead,
    )

    return (
        replace(
            candidate_state,
            send_chain_key = next_send_chain_key,
            send_counter = next_send_counter,
        ),
        envelope,
    )


def decrypt_direct_message(state: SessionState, envelope: DirectMessageEnvelope,
                           *, aad: bytes | None = None) -> tuple[SessionState, bytes]:
    """
    Decrypt a direct one-to-one message and advance receiving state.

    The function supports bounded out-of-order delivery through skipped message
    keys. If the envelope contains a new ratchet public key, receive-ratchet is
    applied to a candidate state first. The candidate state is returned only
    after successful AEAD authentication.

    :param state: Current direct session state.
    :param envelope: Direct message envelope.
    :param aad: Optional caller-provided application AAD.
    :return: Tuple of updated SessionState and plaintext bytes.
    :raises InvalidSessionStateError: If state/envelope do not belong together.
    :raises ReplayDetectedError: If a stale message has no skipped key.
    :raises OutOfOrderMessageError: If message ordering cannot be handled.
    :raises SkippedKeyLimitError: If skipped-key cache limit would be exceeded.
    :raises AuthenticationError: If AEAD authentication fails.
    :raises RatchetError: If receive ratchet fails.
    """
    require_instance(state, SessionState, field_name = "state", error_cls = InvalidSessionStateError)
    require_instance(
        envelope,
        DirectMessageEnvelope,
        field_name = "envelope",
        error_cls = InvalidSessionStateError,
    )
    require_optional_instance(aad, bytes, field_name = "aad")

    if envelope.session_id != state.session_id:
        raise InvalidSessionStateError("direct message session_id mismatch")

    if should_receive_ratchet(state, envelope.ratchet_pub):
        old_chain_state = _save_skipped_message_keys_until(
            state,
            until_counter = envelope.previous_chain_length,
        )
        candidate_state = apply_receive_ratchet(
            old_chain_state,
            new_remote_ratchet_public_key = envelope.ratchet_pub,
            skipped_message_keys = old_chain_state.skipped_message_keys,
        )
    else:
        candidate_state = state

    if envelope.counter < candidate_state.recv_counter:
        skipped = _find_skipped_message_key(
            candidate_state.skipped_message_keys,
            ratchet_pub = envelope.ratchet_pub,
            counter = envelope.counter,
        )

        if skipped is None:
            raise ReplayDetectedError("direct message replay detected")

        return _decrypt_with_skipped_key(
            candidate_state,
            envelope,
            aad = aad,
            skipped = skipped,
        )

    return _decrypt_current_or_future_message(
        candidate_state,
        envelope,
        aad = aad,
    )

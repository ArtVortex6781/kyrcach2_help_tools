from __future__ import annotations

import pytest

from mesh_crypto.core import EncryptionKeyPair, EncryptionKeySerializer, KeyIdHelpers
from mesh_crypto.errors import RatchetError
from mesh_crypto.sessions.ratchet import (
    apply_outgoing_ratchet,
    apply_receive_ratchet,
    ratchet_public_key_bytes,
    should_receive_ratchet,
)
from mesh_crypto.sessions import SessionRole, SessionState, SkippedMessageKey


def make_ratchet_key_pair() -> EncryptionKeyPair:
    return EncryptionKeyPair.generate()


def export_ratchet_public_key(key_pair: EncryptionKeyPair) -> bytes:
    return EncryptionKeySerializer.export_public_key_raw(key_pair.pk)


def make_session_state(
        *,
        role: SessionRole = SessionRole.INITIATOR,
        root_key: bytes = b"r" * 32,
        send_chain_key: bytes = b"s" * 32,
        recv_chain_key: bytes = b"v" * 32,
        send_counter: int = 0,
        recv_counter: int = 0,
        previous_send_chain_length: int = 0,
        local_ratchet_key_pair: EncryptionKeyPair | None = None,
        remote_ratchet_public_key: bytes | None = None,
        skipped_message_keys: tuple[SkippedMessageKey, ...] = (),
) -> SessionState:
    if local_ratchet_key_pair is None:
        local_ratchet_key_pair = make_ratchet_key_pair()
    if remote_ratchet_public_key is None:
        remote_ratchet_public_key = export_ratchet_public_key(make_ratchet_key_pair())

    return SessionState(
        version = 1,
        algorithm = "mesh-direct-v1",
        session_id = KeyIdHelpers.new_key_id(),
        role = role,
        local_identity_key_id = KeyIdHelpers.new_key_id(),
        remote_identity_key_id = KeyIdHelpers.new_key_id(),
        local_identity_public_key = b"l" * 32,
        remote_identity_public_key = b"p" * 32,
        root_key = root_key,
        send_chain_key = send_chain_key,
        recv_chain_key = recv_chain_key,
        send_counter = send_counter,
        recv_counter = recv_counter,
        previous_send_chain_length = previous_send_chain_length,
        local_ratchet_key_pair = local_ratchet_key_pair,
        remote_ratchet_public_key = remote_ratchet_public_key,
        skipped_message_keys = skipped_message_keys,
    )


def make_skipped_message_key(
        *,
        ratchet_pub: bytes,
        counter: int = 0,
        message_key: bytes = b"m" * 32,
) -> SkippedMessageKey:
    return SkippedMessageKey(
        ratchet_pub = ratchet_pub,
        counter = counter,
        message_key = message_key,
    )


class TestShouldReceiveRatchet:
    def test_should_receive_ratchet_returns_false_for_current_remote_ratchet_pub(self) -> None:
        state = make_session_state()

        assert should_receive_ratchet(state, state.remote_ratchet_public_key) is False

    def test_should_receive_ratchet_returns_true_for_new_remote_ratchet_pub(self) -> None:
        state = make_session_state()
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        assert new_remote_ratchet_pub != state.remote_ratchet_public_key
        assert should_receive_ratchet(state, new_remote_ratchet_pub) is True


class TestApplyOutgoingRatchet:
    def test_apply_outgoing_ratchet_updates_send_ratchet_state(self) -> None:
        state = make_session_state(
            root_key = b"r" * 32,
            send_chain_key = b"s" * 32,
            recv_chain_key = b"v" * 32,
            send_counter = 7,
            recv_counter = 3,
            previous_send_chain_length = 2,
        )
        old_local_ratchet_public_key = ratchet_public_key_bytes(state.local_ratchet_key_pair)

        updated = apply_outgoing_ratchet(state)

        assert updated is not state
        assert ratchet_public_key_bytes(updated.local_ratchet_key_pair) != old_local_ratchet_public_key
        assert updated.root_key != state.root_key
        assert updated.send_chain_key != state.send_chain_key
        assert updated.recv_chain_key == state.recv_chain_key
        assert updated.send_counter == 0
        assert updated.recv_counter == state.recv_counter
        assert updated.previous_send_chain_length == state.send_counter
        assert updated.remote_ratchet_public_key == state.remote_ratchet_public_key
        assert updated.skipped_message_keys == state.skipped_message_keys

    def test_apply_outgoing_ratchet_does_not_mutate_original_state(self) -> None:
        state = make_session_state(send_counter = 5)
        old_root_key = state.root_key
        old_send_chain_key = state.send_chain_key
        old_local_ratchet_key_pair = state.local_ratchet_key_pair

        updated = apply_outgoing_ratchet(state)

        assert updated != state
        assert state.root_key == old_root_key
        assert state.send_chain_key == old_send_chain_key
        assert state.send_counter == 5
        assert state.local_ratchet_key_pair == old_local_ratchet_key_pair

    def test_apply_outgoing_ratchet_for_responder_updates_send_chain(self) -> None:
        state = make_session_state(role = SessionRole.RESPONDER, send_counter = 4)

        updated = apply_outgoing_ratchet(state)

        assert updated.role == SessionRole.RESPONDER
        assert updated.root_key != state.root_key
        assert updated.send_chain_key != state.send_chain_key
        assert updated.send_counter == 0
        assert updated.previous_send_chain_length == 4


class TestApplyReceiveRatchet:
    def test_apply_receive_ratchet_updates_receive_and_next_send_ratchet_state(self) -> None:
        state = make_session_state(
            root_key = b"r" * 32,
            send_chain_key = b"s" * 32,
            recv_chain_key = b"v" * 32,
            send_counter = 8,
            recv_counter = 5,
            previous_send_chain_length = 2,
        )
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())
        old_local_ratchet_public_key = ratchet_public_key_bytes(state.local_ratchet_key_pair)
        skipped = (
            make_skipped_message_key(
                ratchet_pub = state.remote_ratchet_public_key,
                counter = 1,
                message_key = b"a" * 32,
            ),
        )

        updated = apply_receive_ratchet(
            state,
            new_remote_ratchet_public_key = new_remote_ratchet_pub,
            skipped_message_keys = skipped,
        )

        assert updated is not state
        assert updated.remote_ratchet_public_key == new_remote_ratchet_pub
        assert updated.root_key != state.root_key
        assert updated.recv_chain_key != state.recv_chain_key
        assert updated.send_chain_key != state.send_chain_key
        assert updated.send_counter == 0
        assert updated.recv_counter == 0
        assert updated.previous_send_chain_length == state.send_counter
        assert ratchet_public_key_bytes(updated.local_ratchet_key_pair) != old_local_ratchet_public_key
        assert updated.skipped_message_keys == skipped

    def test_apply_receive_ratchet_uses_existing_skipped_cache_when_not_provided(self) -> None:
        skipped = (
            make_skipped_message_key(
                ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair()),
                counter = 1,
                message_key = b"a" * 32,
            ),
        )
        state = make_session_state(skipped_message_keys = skipped)
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        updated = apply_receive_ratchet(
            state,
            new_remote_ratchet_public_key = new_remote_ratchet_pub,
        )

        assert updated.skipped_message_keys == skipped

    def test_apply_receive_ratchet_accepts_empty_updated_skipped_cache(self) -> None:
        skipped = (
            make_skipped_message_key(
                ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair()),
                counter = 1,
                message_key = b"a" * 32,
            ),
        )
        state = make_session_state(skipped_message_keys = skipped)
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        updated = apply_receive_ratchet(
            state,
            new_remote_ratchet_public_key = new_remote_ratchet_pub,
            skipped_message_keys = (),
        )

        assert updated.skipped_message_keys == ()

    def test_apply_receive_ratchet_does_not_mutate_original_state(self) -> None:
        state = make_session_state(send_counter = 9, recv_counter = 6)
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        updated = apply_receive_ratchet(
            state,
            new_remote_ratchet_public_key = new_remote_ratchet_pub,
        )

        assert updated != state
        assert state.send_counter == 9
        assert state.recv_counter == 6
        assert state.remote_ratchet_public_key != new_remote_ratchet_pub

    def test_apply_receive_ratchet_for_responder_updates_receive_and_send_chains(self) -> None:
        state = make_session_state(role = SessionRole.RESPONDER, send_counter = 4, recv_counter = 2)
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        updated = apply_receive_ratchet(
            state,
            new_remote_ratchet_public_key = new_remote_ratchet_pub,
        )

        assert updated.role == SessionRole.RESPONDER
        assert updated.remote_ratchet_public_key == new_remote_ratchet_pub
        assert updated.root_key != state.root_key
        assert updated.recv_chain_key != state.recv_chain_key
        assert updated.send_chain_key != state.send_chain_key
        assert updated.send_counter == 0
        assert updated.recv_counter == 0
        assert updated.previous_send_chain_length == 4

    @pytest.mark.parametrize(
        "bad_remote_ratchet_pub",
        [
            b"",
            b"x" * 31,
            b"x" * 33,
            "x" * 32,
            None,
        ],
    )
    def test_apply_receive_ratchet_invalid_remote_public_key_raises_ratchet_error(
            self,
            bad_remote_ratchet_pub,
    ) -> None:
        state = make_session_state()

        with pytest.raises(RatchetError):
            apply_receive_ratchet(
                state,
                new_remote_ratchet_public_key = bad_remote_ratchet_pub,
            )

    def test_apply_receive_ratchet_invalid_skipped_cache_raises_ratchet_error(self) -> None:
        state = make_session_state()
        new_remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        with pytest.raises(RatchetError):
            apply_receive_ratchet(
                state,
                new_remote_ratchet_public_key = new_remote_ratchet_pub,
                skipped_message_keys = (object(),),
            )

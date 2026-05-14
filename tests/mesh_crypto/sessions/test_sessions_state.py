from __future__ import annotations

import pytest

from mesh_crypto.core import EncryptionKeyPair, EncryptionKeySerializer, KeyIdHelpers
from mesh_crypto.errors import (
    InvalidSessionStateError,
    SessionCounterError,
    SkippedKeyLimitError,
)
from mesh_crypto.sessions import (
    SessionRole,
    SessionState,
    SkippedMessageKey,
)

_MISSING = object()


def make_ratchet_key_pair() -> EncryptionKeyPair:
    return EncryptionKeyPair.generate()


def export_ratchet_public_key(key_pair: EncryptionKeyPair) -> bytes:
    return EncryptionKeySerializer.export_public_key_raw(key_pair.pk)


def make_skipped_message_key(
        *,
        ratchet_pub = _MISSING,
        counter: int = 0,
        message_key: bytes = b"m" * 32,
) -> SkippedMessageKey:
    if ratchet_pub is _MISSING:
        ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

    return SkippedMessageKey(
        ratchet_pub = ratchet_pub,
        counter = counter,
        message_key = message_key,
    )


def make_session_state(
        *,
        version: int = 1,
        algorithm: str = "mesh-direct-v1",
        session_id = _MISSING,
        role: SessionRole | str = SessionRole.INITIATOR,
        local_identity_key_id = _MISSING,
        remote_identity_key_id = _MISSING,
        local_identity_public_key: bytes = b"l" * 32,
        remote_identity_public_key: bytes = b"r" * 32,
        root_key: bytes = b"a" * 32,
        send_chain_key: bytes = b"b" * 32,
        recv_chain_key: bytes = b"c" * 32,
        send_counter: int = 0,
        recv_counter: int = 0,
        previous_send_chain_length: int = 0,
        local_ratchet_key_pair = _MISSING,
        remote_ratchet_public_key = _MISSING,
        skipped_message_keys: tuple[SkippedMessageKey, ...] = (),
) -> SessionState:
    if session_id is _MISSING:
        session_id = KeyIdHelpers.new_key_id()
    if local_identity_key_id is _MISSING:
        local_identity_key_id = KeyIdHelpers.new_key_id()
    if remote_identity_key_id is _MISSING:
        remote_identity_key_id = KeyIdHelpers.new_key_id()
    if local_ratchet_key_pair is _MISSING:
        local_ratchet_key_pair = make_ratchet_key_pair()
    if remote_ratchet_public_key is _MISSING:
        remote_ratchet_public_key = export_ratchet_public_key(make_ratchet_key_pair())

    return SessionState(
        version = version,
        algorithm = algorithm,
        session_id = session_id,
        role = role,
        local_identity_key_id = local_identity_key_id,
        remote_identity_key_id = remote_identity_key_id,
        local_identity_public_key = local_identity_public_key,
        remote_identity_public_key = remote_identity_public_key,
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


class TestSessionRole:
    def test_session_role_normalizes_from_string(self) -> None:
        state = make_session_state(role = "responder")

        assert state.role == SessionRole.RESPONDER

    @pytest.mark.parametrize("bad_role", ["", "sender", "receiver", 123, None])
    def test_invalid_session_role_raises_invalid_session_state_error(self, bad_role) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(role = bad_role)


class TestSessionStateHappyPath:
    def test_valid_session_state_can_be_created(self) -> None:
        session_id = KeyIdHelpers.new_key_id()
        local_identity_key_id = KeyIdHelpers.new_key_id()
        remote_identity_key_id = KeyIdHelpers.new_key_id()
        local_ratchet = make_ratchet_key_pair()
        remote_ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())

        state = make_session_state(
            session_id = session_id,
            role = SessionRole.INITIATOR,
            local_identity_key_id = local_identity_key_id,
            remote_identity_key_id = remote_identity_key_id,
            local_ratchet_key_pair = local_ratchet,
            remote_ratchet_public_key = remote_ratchet_pub,
        )

        assert state.version == 1
        assert state.algorithm == "mesh-direct-v1"
        assert state.session_id == session_id
        assert state.role == SessionRole.INITIATOR
        assert state.local_identity_key_id == local_identity_key_id
        assert state.remote_identity_key_id == remote_identity_key_id
        assert state.local_identity_public_key == b"l" * 32
        assert state.remote_identity_public_key == b"r" * 32
        assert state.root_key == b"a" * 32
        assert state.send_chain_key == b"b" * 32
        assert state.recv_chain_key == b"c" * 32
        assert state.send_counter == 0
        assert state.recv_counter == 0
        assert state.previous_send_chain_length == 0
        assert state.local_ratchet_key_pair == local_ratchet
        assert state.remote_ratchet_public_key == remote_ratchet_pub
        assert state.skipped_message_keys == ()

    def test_session_state_normalizes_key_ids_from_string_and_bytes(self) -> None:
        session_id = KeyIdHelpers.new_key_id()
        local_identity_key_id = KeyIdHelpers.new_key_id()
        remote_identity_key_id = KeyIdHelpers.new_key_id()

        state = make_session_state(
            session_id = str(session_id),
            local_identity_key_id = KeyIdHelpers.key_id_to_bytes(local_identity_key_id),
            remote_identity_key_id = str(remote_identity_key_id),
        )

        assert state.session_id == session_id
        assert state.local_identity_key_id == local_identity_key_id
        assert state.remote_identity_key_id == remote_identity_key_id


class TestSessionStateVersionAndAlgorithm:
    @pytest.mark.parametrize("bad_version", [0, 2, 999])
    def test_unsupported_version_raises_invalid_session_state_error(self, bad_version: int) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(version = bad_version)

    @pytest.mark.parametrize("bad_version", [True, False, "1", None])
    def test_invalid_version_type_raises_invalid_session_state_error(self, bad_version) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(version = bad_version)

    @pytest.mark.parametrize("bad_algorithm", ["", "mesh-direct-v2", "aesgcm", "unknown"])
    def test_unsupported_algorithm_raises_invalid_session_state_error(self, bad_algorithm: str) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(algorithm = bad_algorithm)

    @pytest.mark.parametrize("bad_algorithm", [123, None, b"mesh-direct-v1"])
    def test_invalid_algorithm_type_raises_invalid_session_state_error(self, bad_algorithm) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(algorithm = bad_algorithm)


class TestSessionStateIdentityValidation:
    @pytest.mark.parametrize("bad_session_id", ["", "not-a-uuid", b"short", b"x" * 15, b"x" * 17, 123, None])
    def test_invalid_session_id_raises_invalid_session_state_error(self, bad_session_id) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(session_id = bad_session_id)

    @pytest.mark.parametrize("bad_key_id", ["", "not-a-uuid", b"short", b"x" * 15, b"x" * 17, 123, None])
    def test_invalid_local_identity_key_id_raises_invalid_session_state_error(self, bad_key_id) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(local_identity_key_id = bad_key_id)

    @pytest.mark.parametrize("bad_key_id", ["", "not-a-uuid", b"short", b"x" * 15, b"x" * 17, 123, None])
    def test_invalid_remote_identity_key_id_raises_invalid_session_state_error(self, bad_key_id) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(remote_identity_key_id = bad_key_id)

    @pytest.mark.parametrize("bad_public_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_local_identity_public_key_raises_invalid_session_state_error(self, bad_public_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(local_identity_public_key = bad_public_key)

    @pytest.mark.parametrize("bad_public_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_remote_identity_public_key_raises_invalid_session_state_error(self, bad_public_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(remote_identity_public_key = bad_public_key)


class TestSessionStateKeyMaterialValidation:
    @pytest.mark.parametrize("bad_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_root_key_raises_invalid_session_state_error(self, bad_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(root_key = bad_key)

    @pytest.mark.parametrize("bad_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_send_chain_key_raises_invalid_session_state_error(self, bad_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(send_chain_key = bad_key)

    @pytest.mark.parametrize("bad_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_recv_chain_key_raises_invalid_session_state_error(self, bad_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(recv_chain_key = bad_key)


class TestSessionStateCounterValidation:
    @pytest.mark.parametrize("bad_counter", [-1, 2 ** 64, "0", None, True, False])
    def test_invalid_send_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            make_session_state(send_counter = bad_counter)

    @pytest.mark.parametrize("bad_counter", [-1, 2 ** 64, "0", None, True, False])
    def test_invalid_recv_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            make_session_state(recv_counter = bad_counter)

    @pytest.mark.parametrize("bad_counter", [-1, 2 ** 64, "0", None, True, False])
    def test_invalid_previous_send_chain_length_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            make_session_state(previous_send_chain_length = bad_counter)


class TestSessionStateRatchetValidation:
    @pytest.mark.parametrize("bad_ratchet_key_pair", [object(), None, b"x" * 32])
    def test_invalid_local_ratchet_key_pair_raises_invalid_session_state_error(
            self,
            bad_ratchet_key_pair,
    ) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(local_ratchet_key_pair = bad_ratchet_key_pair)

    @pytest.mark.parametrize("bad_ratchet_pub", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_remote_ratchet_public_key_raises_invalid_session_state_error(
            self,
            bad_ratchet_pub,
    ) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(remote_ratchet_public_key = bad_ratchet_pub)


class TestSkippedMessageKey:
    def test_valid_skipped_message_key_can_be_created(self) -> None:
        ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())
        skipped = SkippedMessageKey(
            ratchet_pub = ratchet_pub,
            counter = 7,
            message_key = b"k" * 32,
        )

        assert skipped.ratchet_pub == ratchet_pub
        assert skipped.counter == 7
        assert skipped.message_key == b"k" * 32

    @pytest.mark.parametrize("bad_ratchet_pub", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_skipped_ratchet_pub_raises_invalid_session_state_error(self, bad_ratchet_pub) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_skipped_message_key(ratchet_pub = bad_ratchet_pub)

    @pytest.mark.parametrize("bad_counter", [-1, 2 ** 64, "0", None, True, False])
    def test_invalid_skipped_counter_raises_session_counter_error(self, bad_counter) -> None:
        with pytest.raises(SessionCounterError):
            make_skipped_message_key(counter = bad_counter)

    @pytest.mark.parametrize("bad_message_key", [b"", b"x" * 31, b"x" * 33, "x" * 32, None])
    def test_invalid_skipped_message_key_raises_invalid_session_state_error(self, bad_message_key) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_skipped_message_key(message_key = bad_message_key)

    def test_session_state_accepts_valid_skipped_message_keys(self) -> None:
        first = make_skipped_message_key(counter = 1)
        second = make_skipped_message_key(counter = 2)

        state = make_session_state(skipped_message_keys = (first, second))

        assert state.skipped_message_keys == (first, second)

    def test_skipped_message_keys_must_be_tuple(self) -> None:
        skipped = make_skipped_message_key()

        with pytest.raises(InvalidSessionStateError):
            make_session_state(skipped_message_keys = [skipped])

    def test_skipped_message_keys_must_contain_skipped_message_key_objects(self) -> None:
        with pytest.raises(InvalidSessionStateError):
            make_session_state(skipped_message_keys = (object(),))

    def test_duplicate_skipped_message_keys_raise_invalid_session_state_error(self) -> None:
        ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())
        first = make_skipped_message_key(ratchet_pub = ratchet_pub, counter = 10, message_key = b"a" * 32)
        duplicate = make_skipped_message_key(ratchet_pub = ratchet_pub, counter = 10, message_key = b"b" * 32)

        with pytest.raises(InvalidSessionStateError):
            make_session_state(skipped_message_keys = (first, duplicate))

    def test_skipped_key_cache_over_default_max_skip_raises_skipped_key_limit_error(self) -> None:
        ratchet_pub = export_ratchet_public_key(make_ratchet_key_pair())
        skipped = tuple(
            make_skipped_message_key(
                ratchet_pub = ratchet_pub,
                counter = counter,
                message_key = counter.to_bytes(8, "big") + b"k" * 24,
            )
            for counter in range(601)
        )

        with pytest.raises(SkippedKeyLimitError):
            make_session_state(skipped_message_keys = skipped)

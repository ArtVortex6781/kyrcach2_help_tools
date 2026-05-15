from __future__ import annotations

from dataclasses import replace

import pytest

from mesh_crypto.core import (
    EncryptionKeyPair,
    EncryptionKeySerializer,
    KeyKind,
    SigningKeySerializer,
)
from mesh_crypto.errors import (
    AuthenticationError,
    InvalidSessionStateError,
    ReplayDetectedError,
    SkippedKeyLimitError,
)
from mesh_crypto.keystore import FileKeyStore, PasswordProtector
from mesh_crypto.sessions import (
    DirectMessageEnvelope,
    SessionState,
    accept_direct_handshake_init,
    complete_direct_handshake,
    create_direct_handshake_init,
    decrypt_direct_message,
    encrypt_direct_message,
)
from mesh_crypto.sessions.ratchet import ratchet_public_key_bytes


@pytest.fixture
def alice_keystore(tmp_path) -> FileKeyStore:
    store = FileKeyStore(
        tmp_path / "alice",
        PasswordProtector(password = "alice password"),
    )
    store.create_new()
    return store


@pytest.fixture
def bob_keystore(tmp_path) -> FileKeyStore:
    store = FileKeyStore(
        tmp_path / "bob",
        PasswordProtector(password = "bob password"),
    )
    store.create_new()
    return store


def generate_identity(store: FileKeyStore):
    key_id = store.generate_key(KeyKind.ED25519)
    key_bytes, _meta = store.get_key(key_id)
    key_pair = SigningKeySerializer.restore_pair_from_private_bytes(key_bytes)
    public_key = SigningKeySerializer.export_pair_public_key_raw(key_pair)
    return key_id, public_key


@pytest.fixture
def session_pair(
        alice_keystore: FileKeyStore,
        bob_keystore: FileKeyStore,
) -> tuple[SessionState, SessionState]:
    alice_identity_key_id, alice_public_key = generate_identity(alice_keystore)
    bob_identity_key_id, bob_public_key = generate_identity(bob_keystore)

    pending, init = create_direct_handshake_init(
        alice_keystore,
        alice_identity_key_id,
        alice_public_key,
        expected_peer_identity_public_key = bob_public_key,
    )

    bob_state, response = accept_direct_handshake_init(
        bob_keystore,
        bob_identity_key_id,
        bob_public_key,
        expected_peer_identity_public_key = alice_public_key,
        init = init,
    )

    alice_state = complete_direct_handshake(
        pending,
        init,
        response,
        expected_peer_identity_public_key = bob_public_key,
    )

    return alice_state, bob_state


def fresh_ratchet_public_key() -> bytes:
    pair = EncryptionKeyPair.generate()
    return EncryptionKeySerializer.export_pair_public_key_raw(pair)


class TestBasicEncryptDecrypt:
    def test_alice_encrypts_and_bob_decrypts_one_message(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"hello bob",
        )
        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
        )

        assert isinstance(envelope, DirectMessageEnvelope)
        assert plaintext == b"hello bob"

        assert next_alice_state is not alice_state
        assert next_bob_state is not bob_state

        assert next_alice_state.send_counter == alice_state.send_counter + 1
        assert next_alice_state.send_chain_key != alice_state.send_chain_key

        assert next_bob_state.recv_counter == bob_state.recv_counter + 1
        assert next_bob_state.recv_chain_key != bob_state.recv_chain_key

        assert alice_state.send_counter == 0
        assert bob_state.recv_counter == 0

    def test_encrypt_direct_message_does_not_mutate_old_state(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, _bob_state = session_pair

        old_send_chain_key = alice_state.send_chain_key
        old_send_counter = alice_state.send_counter

        next_alice_state, _envelope = encrypt_direct_message(
            alice_state,
            b"immutable state check",
        )

        assert next_alice_state != alice_state
        assert alice_state.send_chain_key == old_send_chain_key
        assert alice_state.send_counter == old_send_counter

    def test_decrypt_direct_message_does_not_mutate_old_state(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair
        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"immutable decrypt state check",
        )

        old_recv_chain_key = bob_state.recv_chain_key
        old_recv_counter = bob_state.recv_counter

        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
        )

        assert plaintext == b"immutable decrypt state check"
        assert next_bob_state != bob_state
        assert bob_state.recv_chain_key == old_recv_chain_key
        assert bob_state.recv_counter == old_recv_counter


class TestMultipleInOrderMessages:
    def test_multiple_messages_decrypt_in_order_and_advance_counters(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair
        plaintexts = [b"message-0", b"message-1", b"message-2"]
        envelopes: list[DirectMessageEnvelope] = []

        for plaintext in plaintexts:
            alice_state, envelope = encrypt_direct_message(alice_state, plaintext)
            envelopes.append(envelope)

        assert [envelope.counter for envelope in envelopes] == [0, 1, 2]
        assert alice_state.send_counter == 3

        decrypted: list[bytes] = []
        for envelope in envelopes:
            bob_state, plaintext = decrypt_direct_message(bob_state, envelope)
            decrypted.append(plaintext)

        assert decrypted == plaintexts
        assert bob_state.recv_counter == 3
        assert bob_state.skipped_message_keys == ()


class TestDirectMessageAad:
    def test_encrypt_decrypt_with_aad(self, session_pair: tuple[SessionState, SessionState]) -> None:
        alice_state, bob_state = session_pair

        next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"payload with aad",
            aad = b"chat:1|msg:1",
        )
        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
            aad = b"chat:1|msg:1",
        )

        assert plaintext == b"payload with aad"
        assert next_alice_state.send_counter == 1
        assert next_bob_state.recv_counter == 1

    def test_decrypt_with_different_aad_raises_authentication_error_and_state_remains_usable(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"aad protected payload",
            aad = b"chat:1|msg:1",
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                envelope,
                aad = b"chat:1|msg:2",
            )

        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
            aad = b"chat:1|msg:1",
        )

        assert plaintext == b"aad protected payload"
        assert next_bob_state.recv_counter == 1

    def test_decrypt_without_aad_fails_when_message_was_encrypted_with_aad(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"requires aad",
            aad = b"chat:1",
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(bob_state, envelope)

    def test_decrypt_with_aad_fails_when_message_was_encrypted_without_aad(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"no aad",
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                envelope,
                aad = b"unexpected aad",
            )


class TestReplayDetection:
    def test_replaying_same_envelope_after_successful_decrypt_raises_replay_detected_error(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"replay protected",
        )

        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
        )

        assert plaintext == b"replay protected"

        with pytest.raises(ReplayDetectedError):
            decrypt_direct_message(
                next_bob_state,
                envelope,
            )


class TestOutOfOrderMessages:
    def test_out_of_order_messages_within_limit_use_and_remove_skipped_keys(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        alice_state, envelope_0 = encrypt_direct_message(alice_state, b"zero")
        alice_state, envelope_1 = encrypt_direct_message(alice_state, b"one")
        alice_state, envelope_2 = encrypt_direct_message(alice_state, b"two")

        bob_state_after_2, plaintext_2 = decrypt_direct_message(
            bob_state,
            envelope_2,
        )

        assert plaintext_2 == b"two"
        assert bob_state_after_2.recv_counter == 3
        assert len(bob_state_after_2.skipped_message_keys) == 2
        assert {(entry.ratchet_pub, entry.counter) for entry in bob_state_after_2.skipped_message_keys} == {
            (envelope_0.ratchet_pub, 0),
            (envelope_1.ratchet_pub, 1),
        }

        bob_state_after_0, plaintext_0 = decrypt_direct_message(
            bob_state_after_2,
            envelope_0,
        )

        assert plaintext_0 == b"zero"
        assert len(bob_state_after_0.skipped_message_keys) == 1
        assert {(entry.ratchet_pub, entry.counter) for entry in bob_state_after_0.skipped_message_keys} == {
            (envelope_1.ratchet_pub, 1),
        }

        bob_state_after_1, plaintext_1 = decrypt_direct_message(
            bob_state_after_0,
            envelope_1,
        )

        assert plaintext_1 == b"one"
        assert bob_state_after_1.skipped_message_keys == ()

        with pytest.raises(ReplayDetectedError):
            decrypt_direct_message(
                bob_state_after_1,
                envelope_0,
            )

    def test_out_of_order_gap_beyond_limit_raises_skipped_key_limit_error(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"base envelope",
        )
        far_future_envelope = replace(envelope, counter = 601)

        with pytest.raises(SkippedKeyLimitError):
            decrypt_direct_message(
                bob_state,
                far_future_envelope,
            )


class TestForceRatchetMessages:
    def test_force_ratchet_message_updates_receiver_and_allows_response_ratchet(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        initial_alice_ratchet_pub = ratchet_public_key_bytes(alice_state.local_ratchet_key_pair)
        initial_bob_ratchet_pub = ratchet_public_key_bytes(bob_state.local_ratchet_key_pair)

        alice_after_ratchet, envelope_to_bob = encrypt_direct_message(
            alice_state,
            b"ratcheted hello",
            force_ratchet = True,
        )

        assert envelope_to_bob.ratchet_pub == ratchet_public_key_bytes(
            alice_after_ratchet.local_ratchet_key_pair
        )
        assert envelope_to_bob.ratchet_pub != initial_alice_ratchet_pub
        assert alice_after_ratchet.send_counter == 1
        assert alice_after_ratchet.previous_send_chain_length == alice_state.send_counter

        bob_after_receive, plaintext = decrypt_direct_message(
            bob_state,
            envelope_to_bob,
        )

        assert plaintext == b"ratcheted hello"
        assert bob_after_receive.remote_ratchet_public_key == envelope_to_bob.ratchet_pub
        assert bob_after_receive.root_key != bob_state.root_key
        assert bob_after_receive.recv_chain_key != bob_state.recv_chain_key
        assert bob_after_receive.send_chain_key != bob_state.send_chain_key
        assert bob_after_receive.recv_counter == 1
        assert bob_after_receive.send_counter == 0
        assert ratchet_public_key_bytes(bob_after_receive.local_ratchet_key_pair) != initial_bob_ratchet_pub

        bob_after_reply, envelope_to_alice = encrypt_direct_message(
            bob_after_receive,
            b"ratcheted reply",
        )

        assert envelope_to_alice.ratchet_pub == ratchet_public_key_bytes(
            bob_after_reply.local_ratchet_key_pair
        )
        assert envelope_to_alice.ratchet_pub != alice_after_ratchet.remote_ratchet_public_key

        alice_after_receive, reply_plaintext = decrypt_direct_message(
            alice_after_ratchet,
            envelope_to_alice,
        )

        assert reply_plaintext == b"ratcheted reply"
        assert alice_after_receive.remote_ratchet_public_key == envelope_to_alice.ratchet_pub
        assert alice_after_receive.root_key != alice_after_ratchet.root_key
        assert alice_after_receive.recv_chain_key != alice_after_ratchet.recv_chain_key


class TestInvalidEnvelopeAndBinding:
    def test_envelope_with_different_session_id_raises_invalid_session_state_error(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"payload",
        )
        wrong_session_envelope = replace(
            envelope,
            session_id = SigningKeySerializerFallback.new_session_id(),
        )

        with pytest.raises(InvalidSessionStateError):
            decrypt_direct_message(
                bob_state,
                wrong_session_envelope,
            )

    def test_tampered_counter_breaks_authentication(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"counter-bound",
        )
        tampered = replace(envelope, counter = envelope.counter + 1)

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                tampered,
            )

    def test_tampered_previous_chain_length_breaks_authentication(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"previous-chain-length-bound",
        )
        tampered = replace(
            envelope,
            previous_chain_length = envelope.previous_chain_length + 1,
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                tampered,
            )

    def test_tampered_ratchet_pub_breaks_authentication(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"ratchet-pub-bound",
        )
        tampered = replace(
            envelope,
            ratchet_pub = fresh_ratchet_public_key(),
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                tampered,
            )

    def test_invalid_envelope_object_raises_invalid_session_state_error(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        _alice_state, bob_state = session_pair

        with pytest.raises(InvalidSessionStateError):
            decrypt_direct_message(
                bob_state,
                object(),
            )

    def test_authentication_failure_does_not_consume_receiver_state(
            self,
            session_pair: tuple[SessionState, SessionState],
    ) -> None:
        alice_state, bob_state = session_pair

        _next_alice_state, envelope = encrypt_direct_message(
            alice_state,
            b"state remains usable after failure",
            aad = b"correct aad",
        )

        with pytest.raises(AuthenticationError):
            decrypt_direct_message(
                bob_state,
                envelope,
                aad = b"wrong aad",
            )

        next_bob_state, plaintext = decrypt_direct_message(
            bob_state,
            envelope,
            aad = b"correct aad",
        )

        assert plaintext == b"state remains usable after failure"
        assert next_bob_state.recv_counter == 1


class SigningKeySerializerFallback:
    @staticmethod
    def new_session_id():
        from mesh_crypto.core import KeyIdHelpers

        return KeyIdHelpers.new_key_id()

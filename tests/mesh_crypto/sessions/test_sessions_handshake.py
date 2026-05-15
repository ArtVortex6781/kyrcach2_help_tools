from __future__ import annotations

import pytest

from mesh_crypto.core import (
    KeyIdHelpers,
    KeyKind,
    SigningKeySerializer,
)
from mesh_crypto.errors import (
    HandshakeError,
    KeystoreNotLoadedError,
    SignatureVerificationError,
)
from mesh_crypto.keystore import FileKeyStore, PasswordProtector
from mesh_crypto.sessions import (
    DirectHandshakeInit,
    DirectHandshakeResponse,
    PendingDirectHandshake,
    SessionRole,
    SessionState,
    accept_direct_handshake_init,
    complete_direct_handshake,
    create_direct_handshake_init,
)
from mesh_crypto.sessions.ratchet import ratchet_public_key_bytes


def make_keystore(tmp_path, name: str) -> FileKeyStore:
    store = FileKeyStore(
        tmp_path / name,
        PasswordProtector(password = f"{name} password"),
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
def alice_keystore(tmp_path) -> FileKeyStore:
    return make_keystore(tmp_path, "alice")


@pytest.fixture
def bob_keystore(tmp_path) -> FileKeyStore:
    return make_keystore(tmp_path, "bob")


@pytest.fixture
def alice_identity(alice_keystore: FileKeyStore):
    return generate_identity(alice_keystore)


@pytest.fixture
def bob_identity(bob_keystore: FileKeyStore):
    return generate_identity(bob_keystore)


def run_handshake(
        *,
        alice_keystore: FileKeyStore,
        bob_keystore: FileKeyStore,
        alice_identity,
        bob_identity,
) -> tuple[
    PendingDirectHandshake,
    DirectHandshakeInit,
    SessionState,
    DirectHandshakeResponse,
    SessionState,
]:
    alice_identity_key_id, alice_public_key = alice_identity
    bob_identity_key_id, bob_public_key = bob_identity

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

    return pending, init, bob_state, response, alice_state


class TestDirectHandshakeHappyPath:
    def test_full_direct_handshake_creates_compatible_session_states(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        bob_identity_key_id, bob_public_key = bob_identity

        pending, init, bob_state, response, alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        assert isinstance(pending, PendingDirectHandshake)
        assert isinstance(init, DirectHandshakeInit)
        assert isinstance(response, DirectHandshakeResponse)
        assert isinstance(alice_state, SessionState)
        assert isinstance(bob_state, SessionState)

        assert alice_state.session_id == bob_state.session_id
        assert alice_state.session_id == init.session_id
        assert response.session_id == init.session_id

        assert alice_state.role == SessionRole.INITIATOR
        assert bob_state.role == SessionRole.RESPONDER

        assert alice_state.send_chain_key == bob_state.recv_chain_key
        assert bob_state.send_chain_key == alice_state.recv_chain_key

        assert alice_state.local_identity_key_id == alice_identity_key_id
        assert alice_state.remote_identity_key_id == bob_identity_key_id
        assert bob_state.local_identity_key_id == bob_identity_key_id
        assert bob_state.remote_identity_key_id == alice_identity_key_id

        assert alice_state.local_identity_public_key == alice_public_key
        assert alice_state.remote_identity_public_key == bob_public_key
        assert bob_state.local_identity_public_key == bob_public_key
        assert bob_state.remote_identity_public_key == alice_public_key

        assert ratchet_public_key_bytes(alice_state.local_ratchet_key_pair) == init.initiator_ratchet_public_key
        assert alice_state.remote_ratchet_public_key == response.responder_ratchet_public_key
        assert ratchet_public_key_bytes(bob_state.local_ratchet_key_pair) == response.responder_ratchet_public_key
        assert bob_state.remote_ratchet_public_key == init.initiator_ratchet_public_key

        assert alice_state.root_key == bob_state.root_key
        assert alice_state.send_counter == 0
        assert alice_state.recv_counter == 0
        assert bob_state.send_counter == 0
        assert bob_state.recv_counter == 0
        assert alice_state.skipped_message_keys == ()
        assert bob_state.skipped_message_keys == ()


class TestDirectHandshakeLocalIdentityConsistency:
    def test_create_init_rejects_identity_public_key_that_does_not_match_local_keystore_key(
            self,
            alice_keystore: FileKeyStore,
            bob_identity,
    ) -> None:
        alice_key_id, _alice_public_key = generate_identity(alice_keystore)
        _other_key_id, other_alice_public_key = generate_identity(alice_keystore)
        _bob_key_id, bob_public_key = bob_identity

        with pytest.raises(HandshakeError):
            create_direct_handshake_init(
                alice_keystore,
                alice_key_id,
                other_alice_public_key,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_accept_init_rejects_identity_public_key_that_does_not_match_local_keystore_key(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init = create_direct_handshake_init(
            alice_keystore,
            alice_identity_key_id,
            alice_public_key,
            expected_peer_identity_public_key = bob_public_key,
        )
        assert isinstance(pending, PendingDirectHandshake)

        bob_key_id, _matching_bob_public_key = generate_identity(bob_keystore)
        _other_bob_key_id, other_bob_public_key = generate_identity(bob_keystore)

        with pytest.raises(HandshakeError):
            accept_direct_handshake_init(
                bob_keystore,
                bob_key_id,
                other_bob_public_key,
                expected_peer_identity_public_key = alice_public_key,
                init = init,
            )

    def test_create_init_with_non_ed25519_identity_key_raises_handshake_error(
            self,
            alice_keystore: FileKeyStore,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity
        wrong_key_id = alice_keystore.generate_key(KeyKind.X25519)

        with pytest.raises(HandshakeError):
            create_direct_handshake_init(
                alice_keystore,
                wrong_key_id,
                b"a" * 32,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_accept_init_with_non_ed25519_identity_key_raises_handshake_error(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        _bob_identity_key_id, bob_public_key = bob_identity

        _pending, init = create_direct_handshake_init(
            alice_keystore,
            alice_identity_key_id,
            alice_public_key,
            expected_peer_identity_public_key = bob_public_key,
        )

        wrong_key_id = bob_keystore.generate_key(KeyKind.SYMMETRIC)

        with pytest.raises(HandshakeError):
            accept_direct_handshake_init(
                bob_keystore,
                wrong_key_id,
                b"b" * 32,
                expected_peer_identity_public_key = alice_public_key,
                init = init,
            )


class TestDirectHandshakeInitFailures:
    def test_tampered_init_transcript_field_fails_signature_verification(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        bob_identity_key_id, bob_public_key = bob_identity

        _pending, init = create_direct_handshake_init(
            alice_keystore,
            alice_identity_key_id,
            alice_public_key,
            expected_peer_identity_public_key = bob_public_key,
        )

        tampered_init = DirectHandshakeInit(
            version = init.version,
            type = init.type,
            algorithm = init.algorithm,
            session_id = init.session_id,
            initiator_identity_key_id = init.initiator_identity_key_id,
            initiator_identity_public_key = init.initiator_identity_public_key,
            initiator_ratchet_public_key = b"x" * 32,
            signature = init.signature,
        )

        with pytest.raises(SignatureVerificationError):
            accept_direct_handshake_init(
                bob_keystore,
                bob_identity_key_id,
                bob_public_key,
                expected_peer_identity_public_key = alice_public_key,
                init = tampered_init,
            )

    def test_wrong_expected_peer_identity_public_key_fails_on_accept(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        bob_identity_key_id, bob_public_key = bob_identity

        _pending, init = create_direct_handshake_init(
            alice_keystore,
            alice_identity_key_id,
            alice_public_key,
            expected_peer_identity_public_key = bob_public_key,
        )

        with pytest.raises(HandshakeError):
            accept_direct_handshake_init(
                bob_keystore,
                bob_identity_key_id,
                bob_public_key,
                expected_peer_identity_public_key = b"w" * 32,
                init = init,
            )

    def test_wrong_init_signature_fails_on_accept(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        alice_identity_key_id, alice_public_key = alice_identity
        bob_identity_key_id, bob_public_key = bob_identity

        _pending, init = create_direct_handshake_init(
            alice_keystore,
            alice_identity_key_id,
            alice_public_key,
            expected_peer_identity_public_key = bob_public_key,
        )

        tampered_signature = bytes([init.signature[0] ^ 0x01]) + init.signature[1:]
        tampered_init = DirectHandshakeInit(
            version = init.version,
            type = init.type,
            algorithm = init.algorithm,
            session_id = init.session_id,
            initiator_identity_key_id = init.initiator_identity_key_id,
            initiator_identity_public_key = init.initiator_identity_public_key,
            initiator_ratchet_public_key = init.initiator_ratchet_public_key,
            signature = tampered_signature,
        )

        with pytest.raises(SignatureVerificationError):
            accept_direct_handshake_init(
                bob_keystore,
                bob_identity_key_id,
                bob_public_key,
                expected_peer_identity_public_key = alice_public_key,
                init = tampered_init,
            )


class TestDirectHandshakeResponseFailures:
    def test_tampered_response_transcript_field_fails_signature_verification(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = bob_identity_key_id,
            responder_identity_public_key = bob_public_key,
            responder_ratchet_public_key = b"z" * 32,
            signature = response.signature,
        )

        with pytest.raises(SignatureVerificationError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_wrong_expected_responder_identity_public_key_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                response,
                expected_peer_identity_public_key = b"w" * 32,
            )

    def test_wrong_response_signature_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_signature = bytes([response.signature[0] ^ 0x01]) + response.signature[1:]
        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = tampered_signature,
        )

        with pytest.raises(SignatureVerificationError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_response_with_different_session_id_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = KeyIdHelpers.new_key_id(),
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = response.signature,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_response_with_wrong_init_transcript_hash_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_hash = bytes([response.init_transcript_hash[0] ^ 0x01]) + response.init_transcript_hash[1:]
        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = tampered_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = response.signature,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_response_that_changes_initiator_identity_key_id_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = KeyIdHelpers.new_key_id(),
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = response.signature,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_response_that_changes_initiator_identity_public_key_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = b"q" * 32,
            initiator_ratchet_public_key = response.initiator_ratchet_public_key,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = response.signature,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )

    def test_response_that_changes_initiator_ratchet_field_fails_on_complete(
            self,
            alice_keystore: FileKeyStore,
            bob_keystore: FileKeyStore,
            alice_identity,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity

        pending, init, _bob_state, response, _alice_state = run_handshake(
            alice_keystore = alice_keystore,
            bob_keystore = bob_keystore,
            alice_identity = alice_identity,
            bob_identity = bob_identity,
        )

        tampered_response = DirectHandshakeResponse(
            version = response.version,
            type = response.type,
            algorithm = response.algorithm,
            session_id = response.session_id,
            init_transcript_hash = response.init_transcript_hash,
            initiator_identity_key_id = response.initiator_identity_key_id,
            initiator_identity_public_key = response.initiator_identity_public_key,
            initiator_ratchet_public_key = b"q" * 32,
            responder_identity_key_id = response.responder_identity_key_id,
            responder_identity_public_key = response.responder_identity_public_key,
            responder_ratchet_public_key = response.responder_ratchet_public_key,
            signature = response.signature,
        )

        with pytest.raises(HandshakeError):
            complete_direct_handshake(
                pending,
                init,
                tampered_response,
                expected_peer_identity_public_key = bob_public_key,
            )


class TestDirectHandshakeSigningFailures:
    def test_create_init_with_unloaded_keystore_raises_keystore_not_loaded_error(
            self,
            tmp_path,
            bob_identity,
    ) -> None:
        _bob_identity_key_id, bob_public_key = bob_identity
        unloaded = FileKeyStore(
            tmp_path / "unloaded-alice",
            PasswordProtector(password = "unloaded password"),
        )
        identity_key_id = KeyIdHelpers.new_key_id()

        with pytest.raises(HandshakeError):
            create_direct_handshake_init(
                unloaded,
                identity_key_id,
                b"a" * 32,
                expected_peer_identity_public_key = bob_public_key,
            )

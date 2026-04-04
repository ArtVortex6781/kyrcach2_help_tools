from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mesh_crypto.core import EncryptionKeyPair, HKDF_INFO_HANDSHAKE_BINDING, HKDF_INFO_SESSION_KEY
from mesh_crypto.errors import InvalidInputError, InvalidKeyError, WrongKeyTypeError
from mesh_crypto.primitives import derive_raw_shared_secret, derive_session_key


class TestRawSharedSecret:
    def test_raw_shared_secret_matches_for_both_sides(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        alice_secret = derive_raw_shared_secret(alice.sk, bob.pk)
        bob_secret = derive_raw_shared_secret(bob.sk, alice.pk)

        assert alice_secret == bob_secret

    def test_raw_shared_secret_is_bytes_of_expected_length(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        secret = derive_raw_shared_secret(alice.sk, bob.pk)

        assert isinstance(secret, bytes)
        assert len(secret) == 32

    @pytest.mark.parametrize(
        "bad_sk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            EncryptionKeyPair.generate().pk,
        ],
    )
    def test_raw_shared_secret_rejects_wrong_private_key_type(self, bad_sk) -> None:
        peer = EncryptionKeyPair.generate()

        with pytest.raises(WrongKeyTypeError):
            derive_raw_shared_secret(bad_sk, peer.pk)

    @pytest.mark.parametrize(
        "bad_peer_pk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            EncryptionKeyPair.generate().sk,
        ],
    )
    def test_raw_shared_secret_rejects_wrong_public_key_type(self, bad_peer_pk) -> None:
        local = EncryptionKeyPair.generate()

        with pytest.raises(WrongKeyTypeError):
            derive_raw_shared_secret(local.sk, bad_peer_pk)


class TestSessionKeyDerivation:
    def test_session_key_derivation_returns_bytes_of_requested_length(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        session_key = derive_session_key(
            alice.sk,
            bob.pk,
            salt = None,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )

        assert isinstance(session_key, bytes)
        assert len(session_key) == 32

    def test_both_sides_derive_same_session_key(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        salt = b"0123456789abcdef"

        alice_key = derive_session_key(
            alice.sk,
            bob.pk,
            salt = salt,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )
        bob_key = derive_session_key(
            bob.sk,
            alice.pk,
            salt = salt,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )

        assert alice_key == bob_key

    def test_same_shared_secret_but_different_info_produces_different_session_keys(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        salt = b"0123456789abcdef"

        session_key_1 = derive_session_key(
            alice.sk,
            bob.pk,
            salt = salt,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )
        session_key_2 = derive_session_key(
            alice.sk,
            bob.pk,
            salt = salt,
            info = HKDF_INFO_HANDSHAKE_BINDING,
            length = 32,
        )

        assert session_key_1 != session_key_2

    def test_same_info_but_different_salt_produces_different_session_keys(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        session_key_1 = derive_session_key(
            alice.sk,
            bob.pk,
            salt = b"0123456789abcdef",
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )
        session_key_2 = derive_session_key(
            alice.sk,
            bob.pk,
            salt = b"fedcba9876543210",
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )

        assert session_key_1 != session_key_2

    @pytest.mark.parametrize(
        "bad_info",
        [
            None,
            "",
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_session_key_rejects_non_bytes_info(self, bad_info) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        with pytest.raises(InvalidInputError):
            derive_session_key(
                alice.sk,
                bob.pk,
                salt = None,
                info = bad_info,
                length = 32,
            )

    def test_session_key_rejects_empty_info(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        with pytest.raises(InvalidInputError):
            derive_session_key(
                alice.sk,
                bob.pk,
                salt = None,
                info = b"",
                length = 32,
            )

    @pytest.mark.parametrize("bad_length", [0, -1, "32", None])
    def test_session_key_rejects_invalid_length(self, bad_length) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        with pytest.raises(InvalidInputError):
            derive_session_key(
                alice.sk,
                bob.pk,
                salt = None,
                info = HKDF_INFO_SESSION_KEY,
                length = bad_length,
            )

    @pytest.mark.parametrize(
        "bad_salt",
        [
            "",
            "not-bytes",
            123,
            object(),
        ],
    )
    def test_session_key_rejects_invalid_salt_type(self, bad_salt) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        with pytest.raises(InvalidInputError):
            derive_session_key(
                alice.sk,
                bob.pk,
                salt = bad_salt,
                info = HKDF_INFO_SESSION_KEY,
                length = 32,
            )

    @pytest.mark.parametrize(
        "bad_sk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            EncryptionKeyPair.generate().pk,
        ],
    )
    def test_session_key_rejects_wrong_private_key_type(self, bad_sk) -> None:
        peer = EncryptionKeyPair.generate()

        with pytest.raises(WrongKeyTypeError):
            derive_session_key(
                bad_sk,
                peer.pk,
                salt = None,
                info = HKDF_INFO_SESSION_KEY,
                length = 32,
            )

    @pytest.mark.parametrize(
        "bad_peer_pk",
        [
            None,
            object(),
            "not-a-key",
            b"not-a-key",
            123,
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate().public_key(),
            EncryptionKeyPair.generate().sk,
        ],
    )
    def test_session_key_rejects_wrong_public_key_type(self, bad_peer_pk) -> None:
        local = EncryptionKeyPair.generate()

        with pytest.raises(WrongKeyTypeError):
            derive_session_key(
                local.sk,
                bad_peer_pk,
                salt = None,
                info = HKDF_INFO_SESSION_KEY,
                length = 32,
            )

    def test_raw_helper_and_safe_api_are_consistent(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        salt = b"0123456789abcdef"

        raw_secret = derive_raw_shared_secret(alice.sk, bob.pk)
        assert isinstance(raw_secret, bytes)
        assert len(raw_secret) == 32

        session_key = derive_session_key(
            alice.sk,
            bob.pk,
            salt = salt,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )

        assert isinstance(session_key, bytes)
        assert len(session_key) == 32
        assert session_key != raw_secret

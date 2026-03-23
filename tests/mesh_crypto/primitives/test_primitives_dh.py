from __future__ import annotations

import pytest

from mesh_crypto.core import EncryptionKeyPair
from mesh_crypto.errors import InvalidKeyError
from mesh_crypto.primitives.dh import derive_shared_secret


class TestDiffieHellman:
    def test_shared_secret_matches_for_both_sides(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        alice_secret = derive_shared_secret(alice.sk, bob.pk)
        bob_secret = derive_shared_secret(bob.sk, alice.pk)

        assert alice_secret == bob_secret

    def test_shared_secret_is_bytes(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        secret = derive_shared_secret(alice.sk, bob.pk)

        assert isinstance(secret, bytes)

    def test_shared_secret_has_expected_length(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()

        secret = derive_shared_secret(alice.sk, bob.pk)

        assert len(secret) == 32

    @pytest.mark.parametrize(
        "bad_private_key",
        [
            None,
            object(),
            b"not-a-private-key",
            "not-a-private-key",
            123,
        ],
    )
    def test_derive_shared_secret_rejects_invalid_private_key(self, bad_private_key) -> None:
        bob = EncryptionKeyPair.generate()

        with pytest.raises(InvalidKeyError):
            derive_shared_secret(bad_private_key, bob.pk)

    @pytest.mark.parametrize(
        "bad_public_key",
        [
            None,
            object(),
            b"not-a-public-key",
            "not-a-public-key",
            123,
        ],
    )
    def test_derive_shared_secret_rejects_invalid_public_key(self, bad_public_key) -> None:
        alice = EncryptionKeyPair.generate()

        with pytest.raises(InvalidKeyError):
            derive_shared_secret(alice.sk, bad_public_key)

    def test_shared_secret_differs_for_different_peers(self) -> None:
        alice = EncryptionKeyPair.generate()
        bob = EncryptionKeyPair.generate()
        carol = EncryptionKeyPair.generate()

        secret_with_bob = derive_shared_secret(alice.sk, bob.pk)
        secret_with_carol = derive_shared_secret(alice.sk, carol.pk)

        assert secret_with_bob != secret_with_carol

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from mesh_crypto.core import EncryptionKeyPair, SigningKeyPair
from mesh_crypto.core import EncryptionKeySerializer, SigningKeySerializer


class TestSigningKeyPair:
    def test_generate_returns_ed25519_key_pair(self) -> None:
        pair = SigningKeyPair.generate()

        assert isinstance(pair.sk, Ed25519PrivateKey)
        assert isinstance(pair.pk, Ed25519PublicKey)

    def test_generate_public_key_matches_private_key(self) -> None:
        pair = SigningKeyPair.generate()

        expected_public = pair.sk.public_key()

        assert SigningKeySerializer.serialize_public_key(pair.pk) == (
            SigningKeySerializer.serialize_public_key(expected_public)
        )


class TestEncryptionKeyPair:
    def test_generate_returns_x25519_key_pair(self) -> None:
        pair = EncryptionKeyPair.generate()

        assert isinstance(pair.sk, X25519PrivateKey)
        assert isinstance(pair.pk, X25519PublicKey)

    def test_generate_public_key_matches_private_key(self) -> None:
        pair = EncryptionKeyPair.generate()

        expected_public = pair.sk.public_key()

        assert EncryptionKeySerializer.serialize_public_key(pair.pk) == (
            EncryptionKeySerializer.serialize_public_key(expected_public)
        )

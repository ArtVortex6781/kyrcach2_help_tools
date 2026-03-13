import pytest

from mesh_crypto import keys


# ---------------------------------------------------------
# KeyId helpers
# ---------------------------------------------------------

def test_key_id_generation_unique():
    id1 = keys.KeyIdHelpers.new_key_id()
    id2 = keys.KeyIdHelpers.new_key_id()

    assert id1 != id2
    assert isinstance(id1, keys.KeyId)
    assert isinstance(id2, keys.KeyId)


def test_key_id_bytes_roundtrip():
    key_id = keys.KeyIdHelpers.new_key_id()

    b = keys.KeyIdHelpers.key_id_to_bytes(key_id)
    restored = keys.KeyIdHelpers.key_id_from_bytes(b)

    assert restored == key_id


def test_key_id_bytes_length():
    key_id = keys.KeyIdHelpers.new_key_id()
    b = keys.KeyIdHelpers.key_id_to_bytes(key_id)

    assert isinstance(b, bytes)
    assert len(b) == 16


# ---------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------

def test_ed25519_generate_keypair():
    pair = keys.SigningKeyPair.generate()

    assert pair.sk is not None
    assert pair.pk is not None


def test_ed25519_sign_verify():
    pair = keys.SigningKeyPair.generate()

    message = b"hello world"

    signature = pair.sk.sign(message)

    pair.pk.verify(signature, message)


def test_ed25519_verify_fails_on_modified_message():
    pair = keys.SigningKeyPair.generate()

    message = b"hello world"
    bad_message = b"hello world!"

    signature = pair.sk.sign(message)

    with pytest.raises(Exception):
        pair.pk.verify(signature, bad_message)


# ---------------------------------------------------------
# X25519 key exchange
# ---------------------------------------------------------

def test_x25519_generate_keypair():
    pair = keys.EncryptionKeyPair.generate()

    assert pair.sk is not None
    assert pair.pk is not None


def test_x25519_shared_secret_matches():
    alice = keys.EncryptionKeyPair.generate()
    bob = keys.EncryptionKeyPair.generate()

    secret1 = alice.sk.exchange(bob.pk)
    secret2 = bob.sk.exchange(alice.pk)

    assert secret1 == secret2


def test_x25519_shared_secret_length():
    alice = keys.EncryptionKeyPair.generate()
    bob = keys.EncryptionKeyPair.generate()

    secret = alice.sk.exchange(bob.pk)

    assert isinstance(secret, bytes)
    assert len(secret) == 32


# ---------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------

def test_ed25519_raw_serialization():
    pair = keys.SigningKeyPair.generate()

    from cryptography.hazmat.primitives import serialization

    sk_bytes = pair.sk.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption(),
    )

    pk_bytes = pair.pk.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw,
    )

    assert len(sk_bytes) == 32
    assert len(pk_bytes) == 32


def test_x25519_raw_serialization():
    pair = keys.EncryptionKeyPair.generate()

    from cryptography.hazmat.primitives import serialization

    sk_bytes = pair.sk.private_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PrivateFormat.Raw,
        encryption_algorithm = serialization.NoEncryption(),
    )

    pk_bytes = pair.pk.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw,
    )

    assert len(sk_bytes) == 32
    assert len(pk_bytes) == 32

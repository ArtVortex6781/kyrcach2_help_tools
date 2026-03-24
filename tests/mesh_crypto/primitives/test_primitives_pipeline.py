from __future__ import annotations

from mesh_crypto.primitives.aead import decrypt, encrypt
from mesh_crypto.primitives.kdf import derive_key_hkdf, derive_key_scrypt


class TestPrimitivesPipeline:
    def test_hkdf_derived_key_works_with_aead_roundtrip(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt"
        info = b"mesh/aead/session"
        plaintext = b"pipeline test payload"
        aad = b"pipeline-aad"

        key = derive_key_hkdf(
            secret,
            salt = salt,
            info = info,
            length = 32,
        )
        envelope = encrypt(key, plaintext, aad = aad)
        decrypted = decrypt(key, envelope, aad = aad)

        assert isinstance(key, bytes)
        assert len(key) == 32
        assert decrypted == plaintext

    def test_scrypt_derived_key_works_with_aead_roundtrip(self) -> None:
        password = b"correct horse battery staple"
        salt = b"0123456789abcdef"
        plaintext = b"pipeline test payload"
        aad = b"pipeline-aad"

        key = derive_key_scrypt(
            password,
            salt,
            length = 32,
        )
        envelope = encrypt(key, plaintext, aad = aad)
        decrypted = decrypt(key, envelope, aad = aad)

        assert isinstance(key, bytes)
        assert len(key) == 32
        assert decrypted == plaintext

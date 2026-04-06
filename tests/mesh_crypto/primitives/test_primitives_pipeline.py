from __future__ import annotations

from mesh_crypto.core import AAD_PURPOSE_STORAGE, HKDF_INFO_SESSION_KEY
from mesh_crypto.primitives import decrypt, derive_key_hkdf, derive_key_scrypt, encrypt


class TestPrimitivesPipeline:
    def test_hkdf_derived_key_works_with_aead_roundtrip(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt-123456"
        info = HKDF_INFO_SESSION_KEY
        plaintext = b"pipeline test payload"
        aad = AAD_PURPOSE_STORAGE

        key = derive_key_hkdf(
            secret,
            salt = salt,
            info = info,
            length = 32,
        )
        envelope = encrypt(key, plaintext, aad)
        decrypted = decrypt(key, envelope, aad)

        assert isinstance(key, bytes)
        assert len(key) == 32
        assert decrypted == plaintext

    def test_scrypt_derived_key_works_with_aead_roundtrip(self) -> None:
        password = b"correct horse battery staple"
        salt = b"0123456789abcdef"
        plaintext = b"pipeline test payload"
        aad = AAD_PURPOSE_STORAGE

        key = derive_key_scrypt(
            password,
            salt,
            length = 32,
        )
        envelope = encrypt(key, plaintext, aad)
        decrypted = decrypt(key, envelope, aad)

        assert isinstance(key, bytes)
        assert len(key) == 32
        assert decrypted == plaintext

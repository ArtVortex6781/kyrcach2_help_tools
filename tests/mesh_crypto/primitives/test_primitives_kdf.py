from __future__ import annotations

import pytest

from mesh_crypto.errors import InvalidKeyError
from mesh_crypto.primitives.kdf import derive_key_hkdf, derive_key_scrypt


class TestScrypt:
    def test_same_inputs_produce_same_output(self) -> None:
        password = b"correct horse battery staple"
        salt = b"fixed-salt-123456"

        first = derive_key_scrypt(password, salt, length = 32)
        second = derive_key_scrypt(password, salt, length = 32)

        assert first == second

    def test_different_salts_produce_different_output(self) -> None:
        password = b"correct horse battery staple"

        first = derive_key_scrypt(password, b"salt-000000000001", length = 32)
        second = derive_key_scrypt(password, b"salt-000000000002", length = 32)

        assert first != second

    @pytest.mark.parametrize("length", [16, 24, 32, 64])
    def test_output_length_matches_requested_length(self, length: int) -> None:
        derived = derive_key_scrypt(
            b"password",
            b"0123456789abcdef",
            length = length,
        )

        assert isinstance(derived, bytes)
        assert len(derived) == length

    @pytest.mark.parametrize(
        ("password", "salt", "kwargs"),
        [
            (None, b"salt", {}),
            ("password", b"salt", {}),
            (123, b"salt", {}),
            (b"password", None, {}),
            (b"password", "salt", {}),
            (b"password", 123, {}),
            (b"password", b"salt", {"length": 0}),
            (b"password", b"salt", {"length": -1}),
            (b"password", b"salt", {"n": 0}),
            (b"password", b"salt", {"n": -2}),
            (b"password", b"salt", {"n": 1000}),
            (b"password", b"salt", {"r": 0}),
            (b"password", b"salt", {"r": -1}),
            (b"password", b"salt", {"p": 0}),
            (b"password", b"salt", {"p": -1}),
        ],
    )
    def test_invalid_inputs_or_parameters_raise_invalid_key_error(
            self,
            password,
            salt,
            kwargs: dict[str, int],
    ) -> None:
        with pytest.raises(InvalidKeyError):
            derive_key_scrypt(password, salt, **kwargs)


class TestHkdf:
    def test_same_inputs_produce_same_output(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt"
        info = b"context-info"

        first = derive_key_hkdf(secret, salt = salt, info = info, length = 32)
        second = derive_key_hkdf(secret, salt = salt, info = info, length = 32)

        assert first == second

    def test_different_info_produces_different_output(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt"

        first = derive_key_hkdf(secret, salt = salt, info = b"context-a", length = 32)
        second = derive_key_hkdf(secret, salt = salt, info = b"context-b", length = 32)

        assert first != second

    @pytest.mark.parametrize("length", [16, 24, 32, 64])
    def test_output_length_matches_requested_length(self, length: int) -> None:
        derived = derive_key_hkdf(
            b"shared secret",
            salt = b"hkdf-salt",
            info = b"context",
            length = length,
        )

        assert isinstance(derived, bytes)
        assert len(derived) == length

    def test_hkdf_accepts_none_salt(self) -> None:
        derived = derive_key_hkdf(
            b"shared secret",
            salt = None,
            info = b"context",
            length = 32,
        )

        assert isinstance(derived, bytes)
        assert len(derived) == 32

    @pytest.mark.parametrize(
        ("secret", "kwargs"),
        [
            (None, {}),
            ("secret", {}),
            (123, {}),
            (b"secret", {"salt": "salt"}),
            (b"secret", {"salt": 123}),
            (b"secret", {"info": "info"}),
            (b"secret", {"info": 123}),
            (b"secret", {"length": 0}),
            (b"secret", {"length": -1}),
        ],
    )
    def test_invalid_inputs_or_parameters_raise_invalid_key_error(
            self,
            secret,
            kwargs: dict[str, object],
    ) -> None:
        with pytest.raises(InvalidKeyError):
            derive_key_hkdf(secret, **kwargs)

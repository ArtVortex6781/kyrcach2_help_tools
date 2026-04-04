from __future__ import annotations

import pytest

from mesh_crypto.core import HKDF_INFO_HANDSHAKE_BINDING, HKDF_INFO_SESSION_KEY
from mesh_crypto.errors import InvalidInputError, InvalidKeyError
from mesh_crypto.primitives import derive_key_hkdf, derive_key_scrypt


class TestScrypt:
    def test_same_inputs_produce_same_output(self) -> None:
        password = b"correct horse battery staple"
        salt = b"0123456789abcdef"

        first = derive_key_scrypt(password, salt, length = 32)
        second = derive_key_scrypt(password, salt, length = 32)

        assert first == second

    def test_different_salts_produce_different_output(self) -> None:
        password = b"correct horse battery staple"

        first = derive_key_scrypt(password, b"0123456789abcdef", length = 32)
        second = derive_key_scrypt(password, b"fedcba9876543210", length = 32)

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
            (None, b"0123456789abcdef", {}),
            ("password", b"0123456789abcdef", {}),
            (123, b"0123456789abcdef", {}),
            (b"password", None, {}),
            (b"password", "0123456789abcdef", {}),
            (b"password", 123, {}),
            (b"password", b"", {}),
            (b"password", b"short", {}),
            (b"password", b"0123456789abcdef", {"length": 0}),
            (b"password", b"0123456789abcdef", {"length": -1}),
            (b"password", b"0123456789abcdef", {"n": 0}),
            (b"password", b"0123456789abcdef", {"n": -1}),
            (b"password", b"0123456789abcdef", {"r": 0}),
            (b"password", b"0123456789abcdef", {"r": -1}),
            (b"password", b"0123456789abcdef", {"p": 0}),
            (b"password", b"0123456789abcdef", {"p": -1}),
            (b"password", b"0123456789abcdef", {"length": "32"}),
            (b"password", b"0123456789abcdef", {"n": "65536"}),
            (b"password", b"0123456789abcdef", {"r": "8"}),
            (b"password", b"0123456789abcdef", {"p": "1"}),
        ],
    )
    def test_invalid_api_inputs_raise_invalid_input_error(
            self,
            password,
            salt,
            kwargs: dict[str, object],
    ) -> None:
        with pytest.raises(InvalidInputError):
            derive_key_scrypt(password, salt, **kwargs)

    def test_crypto_parameter_failure_after_validation_raises_invalid_key_error(self) -> None:
        with pytest.raises(InvalidKeyError):
            derive_key_scrypt(
                b"password",
                b"0123456789abcdef",
                n = 3,
            )


class TestHkdf:
    def test_same_inputs_produce_same_output(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt-123456"
        info = HKDF_INFO_SESSION_KEY

        first = derive_key_hkdf(secret, salt = salt, info = info, length = 32)
        second = derive_key_hkdf(secret, salt = salt, info = info, length = 32)

        assert first == second

    def test_different_info_produces_different_output(self) -> None:
        secret = b"shared secret material"
        salt = b"hkdf-salt-123456"

        first = derive_key_hkdf(
            secret,
            salt = salt,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )
        second = derive_key_hkdf(
            secret,
            salt = salt,
            info = HKDF_INFO_HANDSHAKE_BINDING,
            length = 32,
        )

        assert first != second

    def test_different_salt_produces_different_output(self) -> None:
        secret = b"shared secret material"
        info = HKDF_INFO_SESSION_KEY

        first = derive_key_hkdf(
            secret,
            salt = b"hkdf-salt-111111",
            info = info,
            length = 32,
        )
        second = derive_key_hkdf(
            secret,
            salt = b"hkdf-salt-222222",
            info = info,
            length = 32,
        )

        assert first != second

    def test_hkdf_accepts_none_salt(self) -> None:
        derived = derive_key_hkdf(
            b"shared secret",
            salt = None,
            info = HKDF_INFO_SESSION_KEY,
            length = 32,
        )

        assert isinstance(derived, bytes)
        assert len(derived) == 32

    @pytest.mark.parametrize("length", [16, 24, 32, 64])
    def test_output_length_matches_requested_length(self, length: int) -> None:
        derived = derive_key_hkdf(
            b"shared secret",
            salt = b"hkdf-salt-123456",
            info = HKDF_INFO_SESSION_KEY,
            length = length,
        )

        assert isinstance(derived, bytes)
        assert len(derived) == length

    @pytest.mark.parametrize(
        ("secret", "kwargs"),
        [
            (None, {"info": HKDF_INFO_SESSION_KEY}),
            ("secret", {"info": HKDF_INFO_SESSION_KEY}),
            (123, {"info": HKDF_INFO_SESSION_KEY}),
            (b"secret", {"salt": "salt", "info": HKDF_INFO_SESSION_KEY}),
            (b"secret", {"salt": 123, "info": HKDF_INFO_SESSION_KEY}),
            (b"secret", {"info": None}),
            (b"secret", {"info": ""}),
            (b"secret", {"info": "info"}),
            (b"secret", {"info": 123}),
            (b"secret", {"info": b""}),
            (b"secret", {"info": HKDF_INFO_SESSION_KEY, "length": 0}),
            (b"secret", {"info": HKDF_INFO_SESSION_KEY, "length": -1}),
            (b"secret", {"info": HKDF_INFO_SESSION_KEY, "length": "32"}),
        ],
    )
    def test_invalid_api_inputs_raise_invalid_input_error(
            self,
            secret,
            kwargs: dict[str, object],
    ) -> None:
        with pytest.raises(InvalidInputError):
            derive_key_hkdf(secret, **kwargs)

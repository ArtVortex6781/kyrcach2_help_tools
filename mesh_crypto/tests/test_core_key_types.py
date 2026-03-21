from __future__ import annotations

import pytest

from mesh_crypto.core import KeyKind


def test_key_kind_values_are_stable() -> None:
    assert KeyKind.SYMMETRIC.value == "symmetric"
    assert KeyKind.ED25519.value == "ed25519"
    assert KeyKind.X25519.value == "x25519"


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("symmetric", KeyKind.SYMMETRIC),
        ("ed25519", KeyKind.ED25519),
        ("x25519", KeyKind.X25519),
    ],
)
def test_key_kind_can_be_created_from_string(raw_value: str, expected: KeyKind) -> None:
    assert KeyKind(raw_value) is expected


def test_key_kind_invalid_value_raises_error() -> None:
    with pytest.raises(ValueError):
        KeyKind("invalid")

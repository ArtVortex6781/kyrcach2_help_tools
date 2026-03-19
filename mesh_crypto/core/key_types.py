from __future__ import annotations

from enum import Enum

__all__ = ["KeyKind"]


class KeyKind(str, Enum):
    """
    Supported cryptographic key kinds for mesh_crypto.
    """

    SYMMETRIC = "symmetric"
    ED25519 = "ed25519"
    X25519 = "x25519"

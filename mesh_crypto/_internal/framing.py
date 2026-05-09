from __future__ import annotations

from .validation import require_non_negative_int
from ..errors import InvalidInputError

__all__ = [
    "frame_bytes",
    "frame_labeled_bytes",
    "frame_str",
    "frame_uint32",
    "frame_uint64",
]


def frame_bytes(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def frame_labeled_bytes(label: bytes, value: bytes) -> bytes:
    return frame_bytes(label) + frame_bytes(value)


def frame_str(value: str) -> bytes:
    return frame_bytes(value.encode("utf-8"))


def frame_uint32(value: int) -> bytes:
    require_non_negative_int(value, field_name = "value")
    if value > 2 ** 32 - 1:
        raise InvalidInputError("value must fit uint32")
    return value.to_bytes(4, "big")


def frame_uint64(value: int) -> bytes:
    require_non_negative_int(value, field_name = "value")
    if value > 2 ** 64 - 1:
        raise InvalidInputError("value must fit uint64")
    return value.to_bytes(8, "big")

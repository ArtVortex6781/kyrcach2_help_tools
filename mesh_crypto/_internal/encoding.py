from __future__ import annotations

import base64
from typing import Type

from ..errors import MalformedDataError, MeshCryptoError

__all__ = ["b64_encode", "b64_decode"]


def b64_encode(data: bytes) -> str:
    """
    Encode raw bytes as a base64 ASCII string.

    :param data: Raw bytes to encode.
    :return: Base64-encoded ASCII string.
    """
    return base64.b64encode(data).decode("ascii")


def b64_decode(data: str, *, field_name: str,
               error_cls: Type[MeshCryptoError] = MalformedDataError) -> bytes:
    """
    Decode a base64 ASCII string into raw bytes.

    :param data: Base64-encoded ASCII string.
    :param field_name: Field name used in error messages.
    :param error_cls: Exception class to raise on decode failure.
    :return: Decoded raw bytes.
    :raises MalformedDataError: By default, if the value is not valid base64 text.
    """
    try:
        return base64.b64decode(data.encode("ascii"), validate = True)
    except Exception as exc:
        raise error_cls(f"invalid base64 value for '{field_name}'") from exc

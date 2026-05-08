from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from ..errors import MeshCryptoError

__all__ = ["remap_crypto_error"]

T = TypeVar("T")


def remap_crypto_error(operation: Callable[[], T], *, error_cls: type[MeshCryptoError],
                       message: str) -> T:
    """
    Execute an operation and remap mesh_crypto errors to a layer-specific error.

    This helper is intended for boundary code that calls lower-level mesh_crypto
    helpers and wants to expose an error type appropriate for the current layer,
    without duplicating local try/except wrappers.

    It catches only MeshCryptoError. Unexpected programming errors such as
    TypeError or AttributeError are intentionally not swallowed.

    :param operation: Zero-argument operation to execute.
    :param error_cls: Error class to raise when operation fails with MeshCryptoError.
    :param message: Error message for the remapped exception.
    :return: Operation result.
    :raises MeshCryptoError: The provided error_cls when operation fails with MeshCryptoError.
    """
    try:
        return operation()
    except MeshCryptoError as exc:
        raise error_cls(message) from exc

from __future__ import annotations

from .._internal import (
    UINT64_MAX,
    require_exact_length_bytes,
    require_uint64,
)
from ..core.domain_separation import (
    HKDF_INFO_DIRECT_MESSAGE_KEY,
    HKDF_INFO_DIRECT_NEXT_CHAIN_KEY,
)
from ..errors import InvalidInputError, InvalidSessionStateError, SessionCounterError
from ..primitives.kdf import derive_key_hkdf

__all__ = [
    "derive_message_key",
    "derive_next_chain_key",
    "advance_chain",
]

_CHAIN_KEY_LENGTH = 32
_MESSAGE_KEY_LENGTH = 32


def _frame_uint64(value: int) -> bytes:
    """
    Encode uint64 counter as fixed-width big-endian bytes.

    :param value: Counter value.
    :return: 8-byte big-endian counter representation.
    """
    return value.to_bytes(8, "big")


def _require_chain_key(chain_key: bytes) -> None:
    """
    Validate direct session chain key bytes.

    :param chain_key: Chain key bytes.
    :raises InvalidSessionStateError: If the chain key is invalid.
    """
    try:
        require_exact_length_bytes(
            chain_key,
            field_name = "chain_key",
            length = _CHAIN_KEY_LENGTH,
        )
    except InvalidInputError as exc:
        raise InvalidSessionStateError("chain_key must be exactly 32 bytes") from exc


def _require_chain_counter(counter: int) -> None:
    """
    Validate direct session chain counter.

    :param counter: Message counter.
    :raises SessionCounterError: If counter is not uint64.
    """
    try:
        require_uint64(counter, field_name = "counter")
    except InvalidInputError as exc:
        raise SessionCounterError(str(exc)) from exc


def _build_chain_info(label: bytes, counter: int) -> bytes:
    """
    Build HKDF info for chain derivation.

    :param label: Domain separation label.
    :param counter: Message counter.
    :return: Context-bound HKDF info bytes.
    """
    return (
            len(label).to_bytes(4, "big")
            + label
            + counter.to_bytes(8, "big")
    )


def derive_message_key(chain_key: bytes, counter: int) -> bytes:
    """
    Derive a per-message AEAD key from a chain key and message counter.

    The chain key itself must never be used directly for payload encryption.

    :param chain_key: Current chain key bytes.
    :param counter: Message counter in the current chain.
    :return: 32-byte message key.
    :raises InvalidSessionStateError: If chain key is invalid.
    :raises SessionCounterError: If counter is invalid.
    :raises InvalidKeyError: If HKDF derivation fails.
    """
    _require_chain_key(chain_key)
    _require_chain_counter(counter)

    return derive_key_hkdf(
        chain_key,
        salt = None,
        info = _build_chain_info(HKDF_INFO_DIRECT_MESSAGE_KEY, counter),
        length = _MESSAGE_KEY_LENGTH,
    )


def derive_next_chain_key(chain_key: bytes, counter: int) -> bytes:
    """
    Derive the next chain key from a current chain key and message counter.

    :param chain_key: Current chain key bytes.
    :param counter: Message counter in the current chain.
    :return: 32-byte next chain key.
    :raises InvalidSessionStateError: If chain key is invalid.
    :raises SessionCounterError: If counter is invalid.
    :raises InvalidKeyError: If HKDF derivation fails.
    """
    _require_chain_key(chain_key)
    _require_chain_counter(counter)

    return derive_key_hkdf(
        chain_key,
        salt = None,
        info = _build_chain_info(HKDF_INFO_DIRECT_NEXT_CHAIN_KEY, counter),
        length = _CHAIN_KEY_LENGTH,
    )


def advance_chain(chain_key: bytes, counter: int) -> tuple[bytes, bytes, int]:
    """
    Advance a symmetric message chain by one step.

    Derives:
    - message_key for the current counter
    - next_chain_key for future messages
    - next_counter = counter + 1

    :param chain_key: Current chain key bytes.
    :param counter: Current message counter.
    :return: Tuple of (message_key, next_chain_key, next_counter).
    :raises InvalidSessionStateError: If chain key is invalid.
    :raises SessionCounterError: If counter is invalid or would overflow.
    :raises InvalidKeyError: If HKDF derivation fails.
    """
    _require_chain_key(chain_key)
    _require_chain_counter(counter)

    if counter == UINT64_MAX:
        raise SessionCounterError("chain counter overflow")

    message_key = derive_message_key(chain_key, counter)
    next_chain_key = derive_next_chain_key(chain_key, counter)

    return message_key, next_chain_key, counter + 1

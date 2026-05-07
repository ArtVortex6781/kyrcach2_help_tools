from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .._internal import (
    require_exact_length_bytes,
    require_instance,
    require_int,
    require_uint64,
)
from ..core.key_ids import KeyIdHelpers
from ..core.keys import EncryptionKeyPair
from ..core.types import KeyId
from ..errors import (
    InvalidInputError,
    InvalidSessionStateError,
    SessionCounterError,
    SkippedKeyLimitError,
)

__all__ = [
    "SessionId",
    "SessionRole",
    "SkippedMessageKey",
    "SessionState",
]

SessionId = KeyId

_DEFAULT_SESSION_VERSION = 1
_DIRECT_SESSION_ALGORITHM = "mesh-direct-v1"

_DEFAULT_KEY_LENGTH = 32
_IDENTITY_PUBLIC_KEY_LENGTH = 32
_RATCHET_PUBLIC_KEY_LENGTH = 32
_MESSAGE_KEY_LENGTH = 32

_DEFAULT_MAX_SKIP = 600


class SessionRole(str, Enum):
    """
    Local role in an authenticated direct E2EE session.
    """

    INITIATOR = "initiator"
    RESPONDER = "responder"


def _require_fixed_bytes(value: bytes, *, field_name: str, length: int) -> None:
    """
    Validate fixed-length session byte material.

    :param value: Byte value to validate.
    :param field_name: Field name used in error messages.
    :param length: Required byte length.
    :raises InvalidSessionStateError: If value is not bytes of the required length.
    """
    try:
        require_exact_length_bytes(
            value,
            field_name = field_name,
            length = length,
        )
    except InvalidInputError as exc:
        raise InvalidSessionStateError(
            f"{field_name} must be exactly {length} bytes"
        ) from exc


def _require_session_counter(value: int, *, field_name: str) -> None:
    """
    Validate uint64 session counter.

    :param value: Counter value.
    :param field_name: Field name used in error messages.
    :raises SessionCounterError: If counter is not uint64.
    """
    try:
        require_uint64(value, field_name = field_name)
    except InvalidInputError as exc:
        raise SessionCounterError(str(exc)) from exc


def _normalize_session_id(value: SessionId | str | bytes) -> SessionId:
    """
    Normalize direct session identifier.

    :param value: Session identifier.
    :return: Normalized UUID session identifier.
    :raises InvalidSessionStateError: If session id is invalid.
    """
    try:
        return KeyIdHelpers.normalize_key_id(value)
    except InvalidInputError as exc:
        raise InvalidSessionStateError("invalid session_id") from exc


def _normalize_key_id(value: KeyId | str | bytes, *, field_name: str) -> KeyId:
    """
    Normalize key identifier stored in session state.

    :param value: Key identifier.
    :param field_name: Field name used in error messages.
    :return: Normalized key identifier.
    :raises InvalidSessionStateError: If key id is invalid.
    """
    try:
        return KeyIdHelpers.normalize_key_id(value)
    except InvalidInputError as exc:
        raise InvalidSessionStateError(f"invalid {field_name}") from exc


def _normalize_role(value: SessionRole | str) -> SessionRole:
    """
    Normalize session role.

    :param value: Session role value.
    :return: Normalized SessionRole.
    :raises InvalidSessionStateError: If role is invalid.
    """
    if isinstance(value, SessionRole):
        return value

    if isinstance(value, str):
        try:
            return SessionRole(value)
        except Exception as exc:
            raise InvalidSessionStateError(f"unsupported session role: {value}") from exc

    raise InvalidSessionStateError("role must be SessionRole or string")


@dataclass(frozen = True)
class SkippedMessageKey:
    """
    Cached message key for bounded out-of-order direct message decryption.

    The cache key is logically `(ratchet_pub, counter)`. The message key is
    deleted after successful use so replayed messages cannot be decrypted again.
    """

    ratchet_pub: bytes
    counter: int
    message_key: bytes

    def __post_init__(self) -> None:
        """
        Validate skipped message key entry.

        :raises InvalidSessionStateError: If ratchet public key or message key is invalid.
        :raises SessionCounterError: If counter is invalid.
        """
        _require_fixed_bytes(
            self.ratchet_pub,
            field_name = "skipped.ratchet_pub",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
        )
        _require_session_counter(self.counter, field_name = "skipped.counter")
        _require_fixed_bytes(
            self.message_key,
            field_name = "skipped.message_key",
            length = _MESSAGE_KEY_LENGTH,
        )


@dataclass(frozen = True)
class SessionState:
    """
    In-memory authenticated direct E2EE session state.

    The external layer may keep this object in memory, but must not modify
    root keys, chain keys, counters, ratchet material, or skipped keys manually.
    All state transitions must be performed through mesh_crypto.sessions APIs.
    """

    version: int
    algorithm: str
    session_id: SessionId
    role: SessionRole

    local_identity_key_id: KeyId
    remote_identity_key_id: KeyId
    local_identity_public_key: bytes
    remote_identity_public_key: bytes

    root_key: bytes
    send_chain_key: bytes
    recv_chain_key: bytes

    send_counter: int
    recv_counter: int
    previous_send_chain_length: int

    local_ratchet_key_pair: EncryptionKeyPair
    remote_ratchet_public_key: bytes

    skipped_message_keys: tuple[SkippedMessageKey, ...] = ()

    def __post_init__(self) -> None:
        """
        Validate direct session state invariants.

        :raises InvalidSessionStateError: If state structure or key material is invalid.
        :raises SessionCounterError: If counters are invalid.
        :raises SkippedKeyLimitError: If skipped key cache exceeds Phase 4 limit.
        """
        try:
            require_int(self.version, field_name = "version")
        except InvalidInputError as exc:
            raise InvalidSessionStateError(str(exc)) from exc
        require_instance(self.algorithm, str, field_name = "algorithm", error_cls = InvalidSessionStateError)

        if self.version != _DEFAULT_SESSION_VERSION:
            raise InvalidSessionStateError(f"unsupported session state version: {self.version}")
        if self.algorithm != _DIRECT_SESSION_ALGORITHM:
            raise InvalidSessionStateError(f"unsupported session algorithm: {self.algorithm}")

        object.__setattr__(
            self,
            "session_id",
            _normalize_session_id(self.session_id),
        )
        object.__setattr__(
            self,
            "role",
            _normalize_role(self.role),
        )
        object.__setattr__(
            self,
            "local_identity_key_id",
            _normalize_key_id(self.local_identity_key_id, field_name = "local_identity_key_id"),
        )
        object.__setattr__(
            self,
            "remote_identity_key_id",
            _normalize_key_id(self.remote_identity_key_id, field_name = "remote_identity_key_id"),
        )

        _require_fixed_bytes(
            self.local_identity_public_key,
            field_name = "local_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
        )
        _require_fixed_bytes(
            self.remote_identity_public_key,
            field_name = "remote_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
        )

        _require_fixed_bytes(
            self.root_key,
            field_name = "root_key",
            length = _DEFAULT_KEY_LENGTH,
        )
        _require_fixed_bytes(
            self.send_chain_key,
            field_name = "send_chain_key",
            length = _DEFAULT_KEY_LENGTH,
        )
        _require_fixed_bytes(
            self.recv_chain_key,
            field_name = "recv_chain_key",
            length = _DEFAULT_KEY_LENGTH,
        )

        _require_session_counter(self.send_counter, field_name = "send_counter")
        _require_session_counter(self.recv_counter, field_name = "recv_counter")
        _require_session_counter(
            self.previous_send_chain_length,
            field_name = "previous_send_chain_length",
        )

        require_instance(
            self.local_ratchet_key_pair,
            EncryptionKeyPair,
            field_name = "local_ratchet_key_pair",
            error_cls = InvalidSessionStateError
        )
        _require_fixed_bytes(
            self.remote_ratchet_public_key,
            field_name = "remote_ratchet_public_key",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
        )

        require_instance(
            self.skipped_message_keys,
            tuple,
            field_name = "skipped_message_keys",
            error_cls = InvalidSessionStateError
        )

        if len(self.skipped_message_keys) > _DEFAULT_MAX_SKIP:
            raise SkippedKeyLimitError(
                f"skipped message key cache exceeds limit: {len(self.skipped_message_keys)} > {_DEFAULT_MAX_SKIP}"
            )

        seen: set[tuple[bytes, int]] = set()
        for skipped in self.skipped_message_keys:
            require_instance(
                skipped,
                SkippedMessageKey,
                field_name = "skipped_message_key",
                error_cls = InvalidSessionStateError
            )

            cache_key = (skipped.ratchet_pub, skipped.counter)
            if cache_key in seen:
                raise InvalidSessionStateError("duplicate skipped message key entry")
            seen.add(cache_key)

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .._internal import (
    remap_crypto_error,
    require_exact_length_bytes,
    require_instance,
    require_int,
    require_str,
    require_uint64,
    require_supported_algorithm,
    require_supported_version,
)
from ..core.key_ids import KeyIdHelpers
from ..core.keys import EncryptionKeyPair
from ..core.types import KeyId
from ..errors import (
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

_SESSION_VERSION = 1
_SESSION_ALGORITHM = "mesh-direct-v1"

_KEY_LENGTH = 32
_IDENTITY_PUBLIC_KEY_LENGTH = 32
_RATCHET_PUBLIC_KEY_LENGTH = 32
_MESSAGE_KEY_LENGTH = 32

_DEFAULT_MAX_SKIP = 600


class SessionRole(str, Enum):
    """
    Local role in an authenticated direct E2EE session.

    The role is assigned during handshake and is used to map directional chains:
    initiator-to-responder and responder-to-initiator.
    """

    INITIATOR = "initiator"
    RESPONDER = "responder"


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
        require_exact_length_bytes(
            self.ratchet_pub,
            field_name = "skipped.ratchet_pub",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )
        require_uint64(
            self.counter,
            field_name = "skipped.counter",
            error_cls = SessionCounterError,
        )
        require_exact_length_bytes(
            self.message_key,
            field_name = "skipped.message_key",
            length = _MESSAGE_KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )


@dataclass(frozen = True)
class SessionState:
    """
    In-memory authenticated direct E2EE session state.

    The external layer may keep this object in memory, but must not manually
    modify root keys, chain keys, counters, ratchet material, or skipped keys.
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
        require_int(
            self.version,
            field_name = "version",
            error_cls = InvalidSessionStateError,
        )
        require_str(
            self.algorithm,
            field_name = "algorithm",
            error_cls = InvalidSessionStateError,
        )

        require_supported_version(
            self.version,
            _SESSION_VERSION,
            error_cls = InvalidSessionStateError,
        )

        require_supported_algorithm(
            self.algorithm,
            _SESSION_ALGORITHM,
            error_cls = InvalidSessionStateError,
        )

        object.__setattr__(
            self,
            "session_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.session_id),
                error_cls = InvalidSessionStateError,
                message = "invalid session_id",
            ),
        )
        object.__setattr__(
            self,
            "local_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.local_identity_key_id),
                error_cls = InvalidSessionStateError,
                message = "invalid local_identity_key_id",
            ),
        )
        object.__setattr__(
            self,
            "remote_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.remote_identity_key_id),
                error_cls = InvalidSessionStateError,
                message = "invalid remote_identity_key_id",
            ),
        )

        object.__setattr__(
            self,
            "role",
            _normalize_role(self.role),
        )

        require_exact_length_bytes(
            self.local_identity_public_key,
            field_name = "local_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )
        require_exact_length_bytes(
            self.remote_identity_public_key,
            field_name = "remote_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )

        require_exact_length_bytes(
            self.root_key,
            field_name = "root_key",
            length = _KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )
        require_exact_length_bytes(
            self.send_chain_key,
            field_name = "send_chain_key",
            length = _KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )
        require_exact_length_bytes(
            self.recv_chain_key,
            field_name = "recv_chain_key",
            length = _KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )

        require_uint64(
            self.send_counter,
            field_name = "send_counter",
            error_cls = SessionCounterError,
        )
        require_uint64(
            self.recv_counter,
            field_name = "recv_counter",
            error_cls = SessionCounterError,
        )
        require_uint64(
            self.previous_send_chain_length,
            field_name = "previous_send_chain_length",
            error_cls = SessionCounterError,
        )

        require_instance(
            self.local_ratchet_key_pair,
            EncryptionKeyPair,
            field_name = "local_ratchet_key_pair",
            error_cls = InvalidSessionStateError,
        )
        require_exact_length_bytes(
            self.remote_ratchet_public_key,
            field_name = "remote_ratchet_public_key",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = InvalidSessionStateError,
        )

        require_instance(
            self.skipped_message_keys,
            tuple,
            field_name = "skipped_message_keys",
            error_cls = InvalidSessionStateError,
        )

        if len(self.skipped_message_keys) > _DEFAULT_MAX_SKIP:
            raise SkippedKeyLimitError(
                f"skipped message key cache exceeds limit: "
                f"{len(self.skipped_message_keys)} > {_DEFAULT_MAX_SKIP}"
            )

        seen: set[tuple[bytes, int]] = set()
        for skipped in self.skipped_message_keys:
            require_instance(
                skipped,
                SkippedMessageKey,
                field_name = "skipped_message_key",
                error_cls = InvalidSessionStateError,
            )

            cache_key = (skipped.ratchet_pub, skipped.counter)
            if cache_key in seen:
                raise InvalidSessionStateError("duplicate skipped message key entry")
            seen.add(cache_key)

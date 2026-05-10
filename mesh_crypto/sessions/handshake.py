from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from .._internal import (
    b64_decode,
    b64_encode,
    frame_labeled_bytes,
    frame_str,
    frame_uint32,
    remap_crypto_error,
    require_exact_keys,
    require_exact_length_bytes,
    require_instance,
    require_int,
    require_int_field,
    require_str,
    require_str_field,
    require_supported_algorithm,
    require_supported_type,
    require_supported_version,
)
from ..core.domain_separation import (
    HKDF_INFO_DIRECT_CHAIN_I2R,
    HKDF_INFO_DIRECT_CHAIN_R2I,
    HKDF_INFO_DIRECT_ROOT_KEY,
    SIGNING_CONTEXT_DIRECT_HANDSHAKE,
)
from ..core.key_ids import KeyIdHelpers
from ..core.keys import EncryptionKeyPair
from ..core.serialization import (
    EncryptionKeySerializer,
    SigningKeySerializer,
)
from ..core.types import KeyId
from ..errors import (
    HandshakeError,
    InvalidInputError,
    MalformedDataError,
)
from ..keystore.file_keystore import FileKeyStore
from ..keystore.operations import sign_with_key
from ..primitives.dh import derive_session_key
from ..primitives.kdf import derive_key_hkdf
from ..primitives.signatures import verify
from .ratchet import ratchet_public_key_bytes
from .state import SessionRole, SessionState

__all__ = [
    "PendingDirectHandshake",
    "DirectHandshakeInit",
    "DirectHandshakeResponse",
    "create_direct_handshake_init",
    "accept_direct_handshake_init",
    "complete_direct_handshake",
]

_HANDSHAKE_VERSION = 1
_HANDSHAKE_ALGORITHM = "mesh-direct-v1"
_HANDSHAKE_INIT_TYPE = "direct_handshake_init"
_HANDSHAKE_RESPONSE_TYPE = "direct_handshake_response"

_KEY_LENGTH = 32
_IDENTITY_PUBLIC_KEY_LENGTH = 32
_RATCHET_PUBLIC_KEY_LENGTH = 32
_SIGNATURE_LENGTH = 64
_TRANSCRIPT_HASH_LENGTH = 32

_TRANSCRIPT_CONTEXT_INIT = b"mesh_crypto:direct_handshake_init_transcript:v1"
_TRANSCRIPT_CONTEXT_RESPONSE = b"mesh_crypto:direct_handshake_response_transcript:v1"

_INIT_KEYS = {
    "version",
    "type",
    "algorithm",
    "session_id",
    "initiator_identity_key_id",
    "initiator_identity_public_key",
    "initiator_ratchet_public_key",
    "signature",
}

_RESPONSE_KEYS = {
    "version",
    "type",
    "algorithm",
    "session_id",
    "init_transcript_hash",
    "initiator_identity_key_id",
    "initiator_identity_public_key",
    "initiator_ratchet_public_key",
    "responder_identity_key_id",
    "responder_identity_public_key",
    "responder_ratchet_public_key",
    "signature",
}


def _transcript_hash(transcript: bytes) -> bytes:
    """
    Hash a canonical handshake transcript.

    :param transcript: Canonical transcript bytes.
    :return: SHA-256 transcript hash.
    """
    return hashlib.sha256(transcript).digest()


def _build_init_transcript(*, session_id: KeyId, initiator_identity_key_id: KeyId,
                           initiator_identity_public_key: bytes,
                           initiator_ratchet_public_key: bytes) -> bytes:
    """
    Build canonical initiator handshake transcript bytes.

    :param session_id: Direct session identifier.
    :param initiator_identity_key_id: Initiator Ed25519 identity key id.
    :param initiator_identity_public_key: Initiator raw Ed25519 public key bytes.
    :param initiator_ratchet_public_key: Initiator raw X25519 ratchet public key bytes.
    :return: Canonical transcript bytes to be signed by initiator.
    """
    return (
            frame_labeled_bytes(b"context", _TRANSCRIPT_CONTEXT_INIT)
            + frame_labeled_bytes(b"version", frame_uint32(_HANDSHAKE_VERSION))
            + frame_labeled_bytes(b"type", frame_str(_HANDSHAKE_INIT_TYPE))
            + frame_labeled_bytes(b"algorithm", frame_str(_HANDSHAKE_ALGORITHM))
            + frame_labeled_bytes(b"session_id", frame_str(str(session_id)))
            + frame_labeled_bytes(b"initiator_identity_key_id",
                                  frame_str(str(initiator_identity_key_id)))
            + frame_labeled_bytes(b"initiator_identity_public_key",
                                  initiator_identity_public_key)
            + frame_labeled_bytes(b"initiator_ratchet_public_key",
                                  initiator_ratchet_public_key)
    )


def _build_response_transcript(*, session_id: KeyId, init_transcript_hash: bytes,
                               initiator_identity_key_id: KeyId, initiator_identity_public_key: bytes,
                               initiator_ratchet_public_key: bytes, responder_identity_key_id: KeyId,
                               responder_identity_public_key: bytes, responder_ratchet_public_key: bytes) -> bytes:
    """
    Build canonical responder handshake transcript bytes.

    The response transcript includes the initiator transcript hash and both
    sides' identity and ratchet public keys.

    :param session_id: Direct session identifier.
    :param init_transcript_hash: SHA-256 hash of initiator transcript.
    :param initiator_identity_key_id: Initiator Ed25519 identity key id.
    :param initiator_identity_public_key: Initiator raw Ed25519 public key bytes.
    :param initiator_ratchet_public_key: Initiator raw X25519 ratchet public key bytes.
    :param responder_identity_key_id: Responder Ed25519 identity key id.
    :param responder_identity_public_key: Responder raw Ed25519 public key bytes.
    :param responder_ratchet_public_key: Responder raw X25519 ratchet public key bytes.
    :return: Canonical transcript bytes to be signed by responder.
    """
    return (
            frame_labeled_bytes(b"context", _TRANSCRIPT_CONTEXT_RESPONSE)
            + frame_labeled_bytes(b"version", frame_uint32(_HANDSHAKE_VERSION))
            + frame_labeled_bytes(b"type", frame_str(_HANDSHAKE_RESPONSE_TYPE))
            + frame_labeled_bytes(b"algorithm", frame_str(_HANDSHAKE_ALGORITHM))
            + frame_labeled_bytes(b"session_id", frame_str(str(session_id)))
            + frame_labeled_bytes(b"init_transcript_hash", init_transcript_hash)
            + frame_labeled_bytes(b"initiator_identity_key_id",
                                  frame_str(str(initiator_identity_key_id)))
            + frame_labeled_bytes(b"initiator_identity_public_key",
                                  initiator_identity_public_key)
            + frame_labeled_bytes(b"initiator_ratchet_public_key",
                                  initiator_ratchet_public_key)
            + frame_labeled_bytes(b"responder_identity_key_id",
                                  frame_str(str(responder_identity_key_id)))
            + frame_labeled_bytes(b"responder_identity_public_key",
                                  responder_identity_public_key)
            + frame_labeled_bytes(b"responder_ratchet_public_key",
                                  responder_ratchet_public_key)
    )


def _derive_initial_root_key(local_ratchet_key_pair: EncryptionKeyPair, remote_ratchet_public_key: bytes,
                             *, handshake_hash: bytes) -> bytes:
    """
    Derive initial direct session root key from handshake X25519 material.

    :param local_ratchet_key_pair: Local handshake X25519 key pair, retained as initial ratchet key.
    :param remote_ratchet_public_key: Remote handshake X25519 public key bytes.
    :param handshake_hash: Hash binding both handshake transcripts.
    :return: Initial 32-byte root key.
    :raises HandshakeError: If public key import or KDF derivation fails.
    """
    remote_public_key = remap_crypto_error(
        lambda: EncryptionKeySerializer.import_public_key_raw(remote_ratchet_public_key),
        error_cls = HandshakeError,
        message = "invalid remote X25519 handshake public key",
    )

    return remap_crypto_error(
        lambda: derive_session_key(
            local_ratchet_key_pair.sk,
            remote_public_key,
            salt = handshake_hash,
            info = HKDF_INFO_DIRECT_ROOT_KEY,
            length = _KEY_LENGTH,
        ),
        error_cls = HandshakeError,
        message = "failed to derive initial direct session root key",
    )


def _derive_initial_chain_key(root_key: bytes, info: bytes) -> bytes:
    """
    Derive an initial directional chain key from root key.

    :param root_key: Initial direct session root key.
    :param info: Directional HKDF info label.
    :return: Initial 32-byte chain key.
    :raises HandshakeError: If KDF derivation fails.
    """
    return remap_crypto_error(
        lambda: derive_key_hkdf(
            root_key,
            salt = None,
            info = info,
            length = _KEY_LENGTH,
        ),
        error_cls = HandshakeError,
        message = "failed to derive initial direct session chain key",
    )


def _verify_signature(*, identity_public_key: bytes,
                      transcript: bytes, signature: bytes) -> None:
    """
    Verify an Ed25519 signature over a canonical handshake transcript.

    :param identity_public_key: Raw Ed25519 identity public key bytes.
    :param transcript: Canonical transcript bytes.
    :param signature: Ed25519 signature bytes.
    :raises MeshCryptoError: If public key import or signature verification fails.
    """
    public_key = remap_crypto_error(
        lambda: SigningKeySerializer.import_public_key_raw(identity_public_key),
        error_cls = HandshakeError,
        message = "invalid Ed25519 identity public key",
    )

    verify(
        SIGNING_CONTEXT_DIRECT_HANDSHAKE,
        transcript,
        signature,
        public_key,
    )


def _require_expected_identity(*, actual_identity_public_key: bytes,
                               expected_identity_public_key: bytes) -> None:
    """
    Validate that actual peer identity matches the expected trust anchor.

    :param actual_identity_public_key: Identity public key from handshake.
    :param expected_identity_public_key: Identity public key expected by app/C++ layer.
    :raises HandshakeError: If expected key shape is invalid or keys differ.
    """
    require_exact_length_bytes(
        expected_identity_public_key,
        field_name = "expected_peer_identity_public_key",
        length = _IDENTITY_PUBLIC_KEY_LENGTH,
        error_cls = HandshakeError,
    )

    if actual_identity_public_key != expected_identity_public_key:
        raise HandshakeError("peer identity public key does not match expected identity")


def _create_session_state(*, session_id: KeyId, role: SessionRole,
                          local_identity_key_id: KeyId, remote_identity_key_id: KeyId,
                          local_identity_public_key: bytes, remote_identity_public_key: bytes,
                          local_ratchet_key_pair: EncryptionKeyPair, remote_ratchet_public_key: bytes,
                          handshake_hash: bytes) -> SessionState:
    """
    Create initial direct session state from verified handshake material.

    :param session_id: Direct session identifier.
    :param role: Local session role.
    :param local_identity_key_id: Local Ed25519 identity key id.
    :param remote_identity_key_id: Remote Ed25519 identity key id.
    :param local_identity_public_key: Local raw Ed25519 identity public key bytes.
    :param remote_identity_public_key: Remote raw Ed25519 identity public key bytes.
    :param local_ratchet_key_pair: Local handshake X25519 key pair retained as initial ratchet key.
    :param remote_ratchet_public_key: Remote handshake X25519 public key bytes.
    :param handshake_hash: Hash binding init and response transcripts.
    :return: Initial SessionState.
    """
    root_key = _derive_initial_root_key(
        local_ratchet_key_pair,
        remote_ratchet_public_key,
        handshake_hash = handshake_hash,
    )

    chain_i2r = _derive_initial_chain_key(root_key, HKDF_INFO_DIRECT_CHAIN_I2R)
    chain_r2i = _derive_initial_chain_key(root_key, HKDF_INFO_DIRECT_CHAIN_R2I)

    if role == SessionRole.INITIATOR:
        send_chain_key = chain_i2r
        recv_chain_key = chain_r2i
    else:
        send_chain_key = chain_r2i
        recv_chain_key = chain_i2r

    return SessionState(
        version = _HANDSHAKE_VERSION,
        algorithm = _HANDSHAKE_ALGORITHM,
        session_id = session_id,
        role = role,
        local_identity_key_id = local_identity_key_id,
        remote_identity_key_id = remote_identity_key_id,
        local_identity_public_key = local_identity_public_key,
        remote_identity_public_key = remote_identity_public_key,
        root_key = root_key,
        send_chain_key = send_chain_key,
        recv_chain_key = recv_chain_key,
        send_counter = 0,
        recv_counter = 0,
        previous_send_chain_length = 0,
        local_ratchet_key_pair = local_ratchet_key_pair,
        remote_ratchet_public_key = remote_ratchet_public_key,
        skipped_message_keys = (),
    )


@dataclass(frozen = True)
class PendingDirectHandshake:
    """
    Initiator-side pending direct handshake state.

    It keeps the initiator X25519 handshake key pair alive until the responder
    response is verified and the initial SessionState is created.
    """

    version: int
    algorithm: str
    session_id: KeyId
    local_identity_key_id: KeyId
    local_identity_public_key: bytes
    expected_remote_identity_public_key: bytes
    local_ratchet_key_pair: EncryptionKeyPair
    init_transcript_hash: bytes

    def __post_init__(self) -> None:
        """
        Validate pending handshake state.

        :raises HandshakeError: If pending handshake state is malformed.
        """
        require_int(self.version, field_name = "version", error_cls = HandshakeError)
        require_str(self.algorithm, field_name = "algorithm", error_cls = HandshakeError)
        require_supported_version(self.version, _HANDSHAKE_VERSION, error_cls = HandshakeError)
        require_supported_algorithm(self.algorithm, _HANDSHAKE_ALGORITHM, error_cls = HandshakeError)

        object.__setattr__(
            self,
            "session_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.session_id),
                error_cls = HandshakeError,
                message = "invalid pending handshake session_id",
            ),
        )
        object.__setattr__(
            self,
            "local_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.local_identity_key_id),
                error_cls = HandshakeError,
                message = "invalid pending handshake local_identity_key_id",
            ),
        )

        require_exact_length_bytes(
            self.local_identity_public_key,
            field_name = "local_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = HandshakeError,
        )
        require_exact_length_bytes(
            self.expected_remote_identity_public_key,
            field_name = "expected_remote_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = HandshakeError,
        )
        require_instance(
            self.local_ratchet_key_pair,
            EncryptionKeyPair,
            field_name = "local_ratchet_key_pair",
            error_cls = HandshakeError,
        )
        require_exact_length_bytes(
            self.init_transcript_hash,
            field_name = "init_transcript_hash",
            length = _TRANSCRIPT_HASH_LENGTH,
            error_cls = HandshakeError,
        )


@dataclass(frozen = True)
class DirectHandshakeInit:
    """
    Initiator-to-responder authenticated direct handshake message.
    """

    version: int
    type: str
    algorithm: str
    session_id: KeyId
    initiator_identity_key_id: KeyId
    initiator_identity_public_key: bytes
    initiator_ratchet_public_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        """
        Validate direct handshake init envelope.

        :raises MalformedDataError: If message structure is malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_int(self.version, field_name = "version", error_cls = MalformedDataError)
        require_str(self.type, field_name = "type", error_cls = MalformedDataError)
        require_str(self.algorithm, field_name = "algorithm", error_cls = MalformedDataError)

        require_supported_version(self.version, _HANDSHAKE_VERSION)
        require_supported_type(self.type, _HANDSHAKE_INIT_TYPE)
        require_supported_algorithm(self.algorithm, _HANDSHAKE_ALGORITHM)

        object.__setattr__(
            self,
            "session_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.session_id),
                error_cls = MalformedDataError,
                message = "invalid session_id",
            ),
        )
        object.__setattr__(
            self,
            "initiator_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.initiator_identity_key_id),
                error_cls = MalformedDataError,
                message = "invalid initiator_identity_key_id",
            ),
        )

        require_exact_length_bytes(
            self.initiator_identity_public_key,
            field_name = "initiator_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.initiator_ratchet_public_key,
            field_name = "initiator_ratchet_public_key",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.signature,
            field_name = "signature",
            length = _SIGNATURE_LENGTH,
            error_cls = MalformedDataError,
        )

    def transcript(self) -> bytes:
        """
        Build canonical transcript for this handshake init.

        :return: Canonical transcript bytes.
        """
        return _build_init_transcript(
            session_id = self.session_id,
            initiator_identity_key_id = self.initiator_identity_key_id,
            initiator_identity_public_key = self.initiator_identity_public_key,
            initiator_ratchet_public_key = self.initiator_ratchet_public_key,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert handshake init to a JSON-serializable dictionary.

        :return: Dictionary representation.
        """
        return {
            "version": self.version,
            "type": self.type,
            "algorithm": self.algorithm,
            "session_id": str(self.session_id),
            "initiator_identity_key_id": str(self.initiator_identity_key_id),
            "initiator_identity_public_key": b64_encode(self.initiator_identity_public_key),
            "initiator_ratchet_public_key": b64_encode(self.initiator_ratchet_public_key),
            "signature": b64_encode(self.signature),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DirectHandshakeInit":
        """
        Parse handshake init from dictionary.

        :param data: Dictionary representation.
        :return: Parsed DirectHandshakeInit.
        :raises MalformedDataError: If structure or fields are malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        require_exact_keys(data, _INIT_KEYS, schema_name = "direct handshake init")

        return DirectHandshakeInit(
            version = require_int_field(data, "version"),
            type = require_str_field(data, "type"),
            algorithm = require_str_field(data, "algorithm"),
            session_id = require_str_field(data, "session_id"),
            initiator_identity_key_id = require_str_field(data, "initiator_identity_key_id"),
            initiator_identity_public_key = b64_decode(
                require_str_field(data, "initiator_identity_public_key"),
                field_name = "initiator_identity_public_key",
            ),
            initiator_ratchet_public_key = b64_decode(
                require_str_field(data, "initiator_ratchet_public_key"),
                field_name = "initiator_ratchet_public_key",
            ),
            signature = b64_decode(
                require_str_field(data, "signature"),
                field_name = "signature",
            ),
        )

    def to_bytes(self) -> bytes:
        """
        Serialize handshake init to canonical UTF-8 JSON bytes.

        :return: Serialized handshake init bytes.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys = True,
            separators = (",", ":"),
        ).encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "DirectHandshakeInit":
        """
        Parse handshake init from serialized UTF-8 JSON bytes.

        :param data: Serialized handshake init bytes.
        :return: Parsed DirectHandshakeInit.
        :raises InvalidInputError: If data is not bytes.
        :raises MalformedDataError: If bytes are not valid handshake JSON.
        """
        require_instance(data, bytes, field_name = "data", error_cls = InvalidInputError)

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("direct handshake init is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("direct handshake init contains invalid JSON") from exc

        require_instance(raw, dict, field_name = "direct_handshake_init", error_cls = MalformedDataError)

        return DirectHandshakeInit.from_dict(raw)


@dataclass(frozen = True)
class DirectHandshakeResponse:
    """
    Responder-to-initiator authenticated direct handshake message.
    """

    version: int
    type: str
    algorithm: str
    session_id: KeyId
    init_transcript_hash: bytes
    initiator_identity_key_id: KeyId
    initiator_identity_public_key: bytes
    initiator_ratchet_public_key: bytes
    responder_identity_key_id: KeyId
    responder_identity_public_key: bytes
    responder_ratchet_public_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        """
        Validate direct handshake response envelope.

        :raises MalformedDataError: If message structure is malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_int(self.version, field_name = "version", error_cls = MalformedDataError)
        require_str(self.type, field_name = "type", error_cls = MalformedDataError)
        require_str(self.algorithm, field_name = "algorithm", error_cls = MalformedDataError)

        require_supported_version(self.version, _HANDSHAKE_VERSION)
        require_supported_type(self.type, _HANDSHAKE_RESPONSE_TYPE)
        require_supported_algorithm(self.algorithm, _HANDSHAKE_ALGORITHM)

        object.__setattr__(
            self,
            "session_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.session_id),
                error_cls = MalformedDataError,
                message = "invalid session_id",
            ),
        )
        object.__setattr__(
            self,
            "initiator_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.initiator_identity_key_id),
                error_cls = MalformedDataError,
                message = "invalid initiator_identity_key_id",
            ),
        )
        object.__setattr__(
            self,
            "responder_identity_key_id",
            remap_crypto_error(
                lambda: KeyIdHelpers.normalize_key_id(self.responder_identity_key_id),
                error_cls = MalformedDataError,
                message = "invalid responder_identity_key_id",
            ),
        )

        require_exact_length_bytes(
            self.init_transcript_hash,
            field_name = "init_transcript_hash",
            length = _TRANSCRIPT_HASH_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.initiator_identity_public_key,
            field_name = "initiator_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.responder_identity_public_key,
            field_name = "responder_identity_public_key",
            length = _IDENTITY_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.initiator_ratchet_public_key,
            field_name = "initiator_ratchet_public_key",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.responder_ratchet_public_key,
            field_name = "responder_ratchet_public_key",
            length = _RATCHET_PUBLIC_KEY_LENGTH,
            error_cls = MalformedDataError,
        )
        require_exact_length_bytes(
            self.signature,
            field_name = "signature",
            length = _SIGNATURE_LENGTH,
            error_cls = MalformedDataError,
        )

    def transcript(self) -> bytes:
        """
        Build canonical transcript for this handshake response.

        :return: Canonical transcript bytes.
        """
        return _build_response_transcript(
            session_id = self.session_id,
            init_transcript_hash = self.init_transcript_hash,
            initiator_identity_key_id = self.initiator_identity_key_id,
            initiator_identity_public_key = self.initiator_identity_public_key,
            initiator_ratchet_public_key = self.initiator_ratchet_public_key,
            responder_identity_key_id = self.responder_identity_key_id,
            responder_identity_public_key = self.responder_identity_public_key,
            responder_ratchet_public_key = self.responder_ratchet_public_key,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert handshake response to a JSON-serializable dictionary.

        :return: Dictionary representation.
        """
        return {
            "version": self.version,
            "type": self.type,
            "algorithm": self.algorithm,
            "session_id": str(self.session_id),
            "init_transcript_hash": b64_encode(self.init_transcript_hash),
            "initiator_identity_key_id": str(self.initiator_identity_key_id),
            "initiator_identity_public_key": b64_encode(self.initiator_identity_public_key),
            "initiator_ratchet_public_key": b64_encode(self.initiator_ratchet_public_key),
            "responder_identity_key_id": str(self.responder_identity_key_id),
            "responder_identity_public_key": b64_encode(self.responder_identity_public_key),
            "responder_ratchet_public_key": b64_encode(self.responder_ratchet_public_key),
            "signature": b64_encode(self.signature),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DirectHandshakeResponse":
        """
        Parse handshake response from dictionary.

        :param data: Dictionary representation.
        :return: Parsed DirectHandshakeResponse.
        :raises MalformedDataError: If structure or fields are malformed.
        :raises UnsupportedFormatError: If version, type, or algorithm is unsupported.
        """
        require_instance(data, dict, field_name = "data", error_cls = MalformedDataError)
        require_exact_keys(data, _RESPONSE_KEYS, schema_name = "direct handshake response")

        return DirectHandshakeResponse(
            version = require_int_field(data, "version"),
            type = require_str_field(data, "type"),
            algorithm = require_str_field(data, "algorithm"),
            session_id = require_str_field(data, "session_id"),
            init_transcript_hash = b64_decode(
                require_str_field(data, "init_transcript_hash"),
                field_name = "init_transcript_hash",
            ),
            initiator_identity_key_id = require_str_field(data, "initiator_identity_key_id"),
            initiator_identity_public_key = b64_decode(
                require_str_field(data, "initiator_identity_public_key"),
                field_name = "initiator_identity_public_key",
            ),
            initiator_ratchet_public_key = b64_decode(
                require_str_field(data, "initiator_ratchet_public_key"),
                field_name = "initiator_ratchet_public_key",
            ),
            responder_identity_key_id = require_str_field(data, "responder_identity_key_id"),
            responder_identity_public_key = b64_decode(
                require_str_field(data, "responder_identity_public_key"),
                field_name = "responder_identity_public_key",
            ),
            responder_ratchet_public_key = b64_decode(
                require_str_field(data, "responder_ratchet_public_key"),
                field_name = "responder_ratchet_public_key",
            ),
            signature = b64_decode(
                require_str_field(data, "signature"),
                field_name = "signature",
            ),
        )

    def to_bytes(self) -> bytes:
        """
        Serialize handshake response to canonical UTF-8 JSON bytes.

        :return: Serialized handshake response bytes.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys = True,
            separators = (",", ":"),
        ).encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "DirectHandshakeResponse":
        """
        Parse handshake response from serialized UTF-8 JSON bytes.

        :param data: Serialized handshake response bytes.
        :return: Parsed DirectHandshakeResponse.
        :raises InvalidInputError: If data is not bytes.
        :raises MalformedDataError: If bytes are not valid handshake JSON.
        """
        require_instance(data, bytes, field_name = "data", error_cls = InvalidInputError)

        try:
            raw = json.loads(data.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise MalformedDataError("direct handshake response is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise MalformedDataError("direct handshake response contains invalid JSON") from exc

        require_instance(raw, dict, field_name = "direct_handshake_response", error_cls = MalformedDataError)

        return DirectHandshakeResponse.from_dict(raw)


def create_direct_handshake_init(keystore: FileKeyStore, identity_key_id: KeyId | str | bytes,
                                 identity_public_key: bytes,
                                 expected_peer_identity_public_key: bytes) -> (
        tuple[PendingDirectHandshake, DirectHandshakeInit]):
    """
    Create initiator-side authenticated direct handshake init.

    :param keystore: Loaded local FileKeyStore.
    :param identity_key_id: Local Ed25519 identity key id.
    :param identity_public_key: Local raw Ed25519 identity public key bytes.
    :param expected_peer_identity_public_key: Expected remote Ed25519 identity public key bytes.
    :return: Pending handshake state and outbound DirectHandshakeInit.
    :raises HandshakeError: If local identity inputs are invalid.
    :raises KeystoreError: If signing through FileKeyStore fails.
    """
    local_identity_key_id = remap_crypto_error(
        lambda: KeyIdHelpers.normalize_key_id(identity_key_id),
        error_cls = HandshakeError,
        message = "invalid local identity key_id",
    )
    require_exact_length_bytes(
        identity_public_key,
        field_name = "identity_public_key",
        length = _IDENTITY_PUBLIC_KEY_LENGTH,
        error_cls = HandshakeError,
    )
    require_exact_length_bytes(
        expected_peer_identity_public_key,
        field_name = "expected_peer_identity_public_key",
        length = _IDENTITY_PUBLIC_KEY_LENGTH,
        error_cls = HandshakeError,
    )

    session_id = uuid.uuid4()
    local_ratchet_key_pair = EncryptionKeyPair.generate()
    local_ratchet_public_key = ratchet_public_key_bytes(local_ratchet_key_pair)

    transcript = _build_init_transcript(
        session_id = session_id,
        initiator_identity_key_id = local_identity_key_id,
        initiator_identity_public_key = identity_public_key,
        initiator_ratchet_public_key = local_ratchet_public_key,
    )

    signature = sign_with_key(
        keystore,
        local_identity_key_id,
        context = SIGNING_CONTEXT_DIRECT_HANDSHAKE,
        data = transcript,
    )

    init = DirectHandshakeInit(
        version = _HANDSHAKE_VERSION,
        type = _HANDSHAKE_INIT_TYPE,
        algorithm = _HANDSHAKE_ALGORITHM,
        session_id = session_id,
        initiator_identity_key_id = local_identity_key_id,
        initiator_identity_public_key = identity_public_key,
        initiator_ratchet_public_key = local_ratchet_public_key,
        signature = signature,
    )

    pending = PendingDirectHandshake(
        version = _HANDSHAKE_VERSION,
        algorithm = _HANDSHAKE_ALGORITHM,
        session_id = session_id,
        local_identity_key_id = local_identity_key_id,
        local_identity_public_key = identity_public_key,
        expected_remote_identity_public_key = expected_peer_identity_public_key,
        local_ratchet_key_pair = local_ratchet_key_pair,
        init_transcript_hash = _transcript_hash(transcript),
    )

    return pending, init


def accept_direct_handshake_init(keystore: FileKeyStore, identity_key_id: KeyId | str | bytes,
                                 identity_public_key: bytes, expected_peer_identity_public_key: bytes,
                                 init: DirectHandshakeInit) -> tuple[SessionState, DirectHandshakeResponse]:
    """
    Accept initiator handshake init and create responder session state.

    :param keystore: Loaded local FileKeyStore.
    :param identity_key_id: Local responder Ed25519 identity key id.
    :param identity_public_key: Local responder raw Ed25519 identity public key bytes.
    :param expected_peer_identity_public_key: Expected initiator Ed25519 identity public key bytes.
    :param init: Parsed DirectHandshakeInit.
    :return: Responder SessionState and outbound DirectHandshakeResponse.
    :raises HandshakeError: If verification, identity binding, or key schedule fails.
    :raises KeystoreError: If signing through FileKeyStore fails.
    """
    require_instance(init, DirectHandshakeInit, field_name = "init", error_cls = HandshakeError)

    local_identity_key_id = remap_crypto_error(
        lambda: KeyIdHelpers.normalize_key_id(identity_key_id),
        error_cls = HandshakeError,
        message = "invalid local identity key_id",
    )
    require_exact_length_bytes(
        identity_public_key,
        field_name = "identity_public_key",
        length = _IDENTITY_PUBLIC_KEY_LENGTH,
        error_cls = HandshakeError,
    )

    _require_expected_identity(
        actual_identity_public_key = init.initiator_identity_public_key,
        expected_identity_public_key = expected_peer_identity_public_key,
    )

    init_transcript = init.transcript()
    _verify_signature(
        identity_public_key = init.initiator_identity_public_key,
        transcript = init_transcript,
        signature = init.signature,
    )

    responder_ratchet_key_pair = EncryptionKeyPair.generate()
    responder_ratchet_public_key = ratchet_public_key_bytes(responder_ratchet_key_pair)
    init_hash = _transcript_hash(init_transcript)

    response_transcript = _build_response_transcript(
        session_id = init.session_id,
        init_transcript_hash = init_hash,
        initiator_identity_key_id = init.initiator_identity_key_id,
        initiator_identity_public_key = init.initiator_identity_public_key,
        initiator_ratchet_public_key = init.initiator_ratchet_public_key,
        responder_identity_key_id = local_identity_key_id,
        responder_identity_public_key = identity_public_key,
        responder_ratchet_public_key = responder_ratchet_public_key,
    )

    response_signature = sign_with_key(
        keystore,
        local_identity_key_id,
        context = SIGNING_CONTEXT_DIRECT_HANDSHAKE,
        data = response_transcript,
    )

    response = DirectHandshakeResponse(
        version = _HANDSHAKE_VERSION,
        type = _HANDSHAKE_RESPONSE_TYPE,
        algorithm = _HANDSHAKE_ALGORITHM,
        session_id = init.session_id,
        init_transcript_hash = init_hash,
        initiator_identity_key_id = init.initiator_identity_key_id,
        initiator_identity_public_key = init.initiator_identity_public_key,
        initiator_ratchet_public_key = init.initiator_ratchet_public_key,
        responder_identity_key_id = local_identity_key_id,
        responder_identity_public_key = identity_public_key,
        responder_ratchet_public_key = responder_ratchet_public_key,
        signature = response_signature,
    )

    full_handshake_hash = _transcript_hash(init_transcript + response_transcript)

    state = _create_session_state(
        session_id = init.session_id,
        role = SessionRole.RESPONDER,
        local_identity_key_id = local_identity_key_id,
        remote_identity_key_id = init.initiator_identity_key_id,
        local_identity_public_key = identity_public_key,
        remote_identity_public_key = init.initiator_identity_public_key,
        local_ratchet_key_pair = responder_ratchet_key_pair,
        remote_ratchet_public_key = init.initiator_ratchet_public_key,
        handshake_hash = full_handshake_hash,
    )

    return state, response


def complete_direct_handshake(pending: PendingDirectHandshake, init: DirectHandshakeInit,
                              response: DirectHandshakeResponse,
                              expected_peer_identity_public_key: bytes) -> SessionState:
    """
    Complete initiator-side authenticated direct handshake.

    :param pending: Pending initiator handshake state returned by create_direct_handshake_init().
    :param init: Original outbound DirectHandshakeInit.
    :param response: Parsed DirectHandshakeResponse.
    :param expected_peer_identity_public_key: Expected responder Ed25519 identity public key bytes.
    :return: Initiator SessionState.
    :raises HandshakeError: If verification, identity binding, or key schedule fails.
    """
    require_instance(pending, PendingDirectHandshake, field_name = "pending", error_cls = HandshakeError)
    require_instance(init, DirectHandshakeInit, field_name = "init", error_cls = HandshakeError)
    require_instance(response, DirectHandshakeResponse, field_name = "response", error_cls = HandshakeError)

    if init.session_id != pending.session_id or response.session_id != pending.session_id:
        raise HandshakeError("handshake session_id mismatch")

    if response.init_transcript_hash != pending.init_transcript_hash:
        raise HandshakeError("handshake init transcript hash mismatch")

    if response.initiator_identity_key_id != init.initiator_identity_key_id:
        raise HandshakeError("handshake initiator identity key_id mismatch")
    if response.initiator_identity_public_key != init.initiator_identity_public_key:
        raise HandshakeError("handshake initiator identity public key mismatch")
    if response.initiator_ratchet_public_key != init.initiator_ratchet_public_key:
        raise HandshakeError("handshake initiator ratchet public key mismatch")

    _require_expected_identity(
        actual_identity_public_key = response.responder_identity_public_key,
        expected_identity_public_key = expected_peer_identity_public_key,
    )
    _require_expected_identity(
        actual_identity_public_key = response.responder_identity_public_key,
        expected_identity_public_key = pending.expected_remote_identity_public_key,
    )

    response_transcript = response.transcript()
    _verify_signature(
        identity_public_key = response.responder_identity_public_key,
        transcript = response_transcript,
        signature = response.signature,
    )

    full_handshake_hash = _transcript_hash(init.transcript() + response_transcript)

    return _create_session_state(
        session_id = pending.session_id,
        role = SessionRole.INITIATOR,
        local_identity_key_id = pending.local_identity_key_id,
        remote_identity_key_id = response.responder_identity_key_id,
        local_identity_public_key = pending.local_identity_public_key,
        remote_identity_public_key = response.responder_identity_public_key,
        local_ratchet_key_pair = pending.local_ratchet_key_pair,
        remote_ratchet_public_key = response.responder_ratchet_public_key,
        handshake_hash = full_handshake_hash,
    )

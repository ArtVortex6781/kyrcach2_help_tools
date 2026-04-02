from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..errors import InvalidKeyError, SignatureVerificationError

from .._validation import require_bytes, require_non_empty_bytes, \
    require_ed25519_private_key, require_ed25519_public_key

__all__ = ["sign", "verify"]
_SIGNING_PAYLOAD_PREFIX = b"mesh_crypto:sign:v1"


def _encode_len_prefixed(part: bytes) -> bytes:
    """
    Encode a binary part using 4-byte big-endian length prefix.

    :param part: Binary payload part.
    :return: Length-prefixed binary representation.
    """
    return len(part).to_bytes(4, "big") + part


def _build_signed_payload(context: bytes, data: bytes) -> bytes:
    """
    Build canonical context-bound payload for signing and verification.

    :param context: Non-empty signing context bytes.
    :param data: Binary payload bytes.
    :return: Canonically framed signed payload.
    """
    return (
            _SIGNING_PAYLOAD_PREFIX
            + _encode_len_prefixed(context)
            + _encode_len_prefixed(data)
    )


def _validate_sign_inputs(context: bytes, data: bytes, sk: Ed25519PrivateKey) -> None:
    """
    Validate public API inputs for Ed25519 signing.

    :param context: Non-empty signing context bytes.
    :param data: Binary payload bytes.
    :param sk: Ed25519 private key.
    :raises InvalidInputError: If context or data are invalid.
    :raises WrongKeyTypeError: If the key object has the wrong type.
    """
    require_non_empty_bytes(context, field_name = "context")
    require_bytes(data, field_name = "data")
    require_ed25519_private_key(sk, field_name = "sk")


def _validate_verify_inputs(context: bytes, data: bytes,
                            signature: bytes, pk: Ed25519PublicKey) -> None:
    """
    Validate public API inputs for Ed25519 verification.

    :param context: Non-empty signing context bytes.
    :param data: Binary payload bytes.
    :param signature: Signature bytes.
    :param pk: Ed25519 public key.
    :raises InvalidInputError: If context, data, or signature are invalid.
    :raises WrongKeyTypeError: If the key object has the wrong type.
    """
    require_non_empty_bytes(context, field_name = "context")
    require_bytes(data, field_name = "data")
    require_bytes(signature, field_name = "signature")
    require_ed25519_public_key(pk, field_name = "pk")


def sign(context: bytes, data: bytes, sk: Ed25519PrivateKey) -> bytes:
    """
    Sign binary data using Ed25519 with mandatory context binding.

    The signed payload is not `data` directly. Instead, a canonical framed
    payload is constructed from:
    - global signing prefix
    - context
    - data

    :param context: Non-empty signing context bytes.
    :param data: Binary payload bytes.
    :param sk: Ed25519 private key.
    :return: Signature bytes.
    :raises InvalidInputError: If context or data are invalid.
    :raises WrongKeyTypeError: If the key object has the wrong type.
    :raises InvalidKeyError: If signing fails after successful pre-validation.
    """
    _validate_sign_inputs(context, data, sk)
    payload = _build_signed_payload(context, data)

    try:
        return sk.sign(payload)
    except Exception as exc:
        raise InvalidKeyError("failed to sign context-bound payload") from exc


def verify(context: bytes, data: bytes,
           signature: bytes, pk: Ed25519PublicKey) -> None:
    """
    Verify an Ed25519 signature for binary data with mandatory context binding.

    Verification reconstructs the exact same canonical framed payload as sign().

    :param context: Non-empty signing context bytes.
    :param data: Binary payload bytes.
    :param signature: Signature bytes to verify.
    :param pk: Ed25519 public key.
    :raises InvalidInputError: If context, data, or signature are invalid.
    :raises WrongKeyTypeError: If the key object has the wrong type.
    :raises SignatureVerificationError: If the signature is invalid.
    :raises InvalidKeyError: If verification fails for reasons other than
        invalid signature after successful pre-validation.
    """
    _validate_verify_inputs(context, data, signature, pk)
    payload = _build_signed_payload(context, data)

    try:
        pk.verify(signature, payload)
    except InvalidSignature as exc:
        raise SignatureVerificationError("invalid Ed25519 signature") from exc
    except Exception as exc:
        raise InvalidKeyError("failed to verify context-bound signature") from exc

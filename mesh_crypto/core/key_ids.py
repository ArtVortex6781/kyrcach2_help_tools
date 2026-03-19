from __future__ import annotations

import uuid

from ..errors import InvalidKeyError
from .types import KeyId

__all__ = ["KeyIdHelpers"]


class KeyIdHelpers:
    """
    Utility helpers for working with cryptographic key identifiers.
    """

    @staticmethod
    def new_key_id() -> KeyId:
        """
        Generate a new random key identifier.

        :return: Randomly generated UUID4 key identifier.
        """
        return uuid.uuid4()

    @staticmethod
    def key_id_to_bytes(key_id: KeyId) -> bytes:
        """
        Convert a KeyId to its 16-byte binary representation.

        :param key_id: Key identifier.
        :return: Raw UUID bytes.
        """
        return key_id.bytes

    @staticmethod
    def key_id_from_bytes(data: bytes) -> KeyId:
        """
        Restore a KeyId from its 16-byte binary representation.

        :param data: Raw UUID bytes.
        :return: Parsed KeyId.
        :raises InvalidKeyError: If the input cannot be parsed as UUID bytes.
        """
        try:
            return uuid.UUID(bytes = data)
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidKeyError("invalid key_id byte representation") from exc

    @staticmethod
    def normalize_key_id(value: KeyId | str | bytes) -> KeyId:
        """
        Normalize a supported key identifier representation into KeyId.

        Supported inputs:
        - KeyId
        - UUID string
        - 16-byte UUID representation

        :param value: Key identifier in supported representation.
        :return: Normalized KeyId instance.
        :raises InvalidKeyError: If the input type or value is invalid.
        """
        if isinstance(value, uuid.UUID):
            return value
        try:
            if isinstance(value, str):
                return uuid.UUID(value)
            if isinstance(value, (bytes, bytearray)):
                return uuid.UUID(bytes = bytes(value))
        except (ValueError, AttributeError, TypeError) as exc:
            raise InvalidKeyError("invalid key_id representation") from exc
        raise InvalidKeyError("key_id must be UUID, UUID string, or 16-byte UUID bytes")

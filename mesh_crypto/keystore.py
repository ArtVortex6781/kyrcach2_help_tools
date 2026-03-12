from __future__ import annotations

import base64
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple
from uuid import UUID, uuid4
from .keys import *

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization

__all__ = [
    "FileKeyStore",
    "PasswordProtector",
    "KeyringProtector",
    "Protector",
]

try:
    import keyring
except Exception:
    keyring = None


def _b64(b: bytes) -> str:
    """
    Encode bytes to base64 string for JSON storage.
    """
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    """
    Decode base64 string back to bytes.
    """
    return base64.b64decode(s.encode("ascii"))


def _ensure_mode_600(path: Path) -> None:
    """
    Attempt to set file permissions to 0600 (owner read/write only).
    This protects private keys on Unix-like systems.
    """
    try:
        path.chmod(0o600)
    except Exception:
        pass


# -------------------------
# Protector abstraction
# -------------------------
class Protector(Protocol):
    """
    Protector abstracts wrapping/unwrapping of the master_key.
    Implementations return/consume JSON-serializable dict metadata
    that will be stored in master.key.
    """

    def wrap(self, master_key: bytes) -> Dict[str, Any]:
        """Wrap master_key and return serializable metadata dict."""
        ...

    def unwrap(self, meta: Dict[str, Any]) -> bytes:
        """Unwrap metadata dict and return the plaintext master_key bytes."""
        ...


# -------------------------
# Password-based protector
# -------------------------
@dataclass
class PasswordProtector:
    """
    Wrap/unwrap master_key using a password-derived key (scrypt -> AESGCM).

    Attributes:
        password: user-supplied passphrase (utf-8).
        scrypt_n/r/p: scrypt parameters (tunable).
    """

    password: str
    scrypt_n: int = 16384
    scrypt_r: int = 8
    scrypt_p: int = 1
    salt_len: int = 16
    nonce_len: int = 12

    def _derive(self, salt: bytes) -> bytes:
        """
        Derive a symmetric encryption key from the password using scrypt.

        :param salt: Random salt used during key derivation.
        :return: bytes: 32-byte encryption key derived from the password.
        """
        kdf = Scrypt(salt = salt, length = 32, n = self.scrypt_n, r = self.scrypt_r, p = self.scrypt_p)
        return kdf.derive(self.password.encode("utf-8"))

    def wrap(self, master_key: bytes) -> Dict[str, Any]:
        """
        Encrypt the master key using a password-derived key.

        :param master_key: Raw master key bytes to protect.
        :return: JSON-serializable metadata containing
            encryption parameters and ciphertext.
        """
        salt = os.urandom(self.salt_len)
        enc_key = self._derive(salt)
        aesgcm = AESGCM(enc_key)
        nonce = os.urandom(self.nonce_len)
        ct = aesgcm.encrypt(nonce, master_key, None)
        return {
            "version": 1,
            "provider": "password",
            "kdf": "scrypt",
            "kdf_salt": _b64(salt),
            "kdf_params": {"n": self.scrypt_n, "r": self.scrypt_r, "p": self.scrypt_p, "len": 32},
            "enc": "aesgcm",
            "nonce": _b64(nonce),
            "ciphertext": _b64(ct),
        }

    def unwrap(self, meta: Dict[str, Any]) -> bytes:
        """
        Decrypt the master key from stored metadata.

        :param meta: Metadata dictionary previously produced by wrap().
        :return: Decrypted master key.
        """
        if meta.get("provider") != "password":
            raise ValueError("PasswordProtector cannot unwrap meta from other provider")
        salt = _unb64(meta["kdf_salt"])
        enc_key = self._derive(salt)
        aesgcm = AESGCM(enc_key)
        nonce = _unb64(meta["nonce"])
        ct = _unb64(meta["ciphertext"])
        return aesgcm.decrypt(nonce, ct, None)


# -------------------------
# Keyring-based protector (OS keystore)
# -------------------------
@dataclass
class KeyringProtector:
    """
    Protector that stores master_key in the system keyring (via python-keyring).
    """

    service_name: str = "mesh_keystore"
    entry_name: str | None = None

    def wrap(self, master_key: bytes) -> Dict[str, Any]:
        """
        Store a key in the system keyring.

        :param master_key: Raw master key bytes to store securely.
        :return: Metadata describing stored key.
        """
        if keyring is None:
            raise RuntimeError("keyring package not available")
        name = self.entry_name or f"mesh-master-{uuid4().hex}"
        keyring.set_password(self.service_name, name, _b64(master_key))
        return {"version": 1, "provider": "keyring", "service": self.service_name, "name": name}

    @staticmethod
    def unwrap(meta: Dict[str, Any]) -> bytes:
        """
        Retrieve a key from the system keyring.

        :param meta: Metadata dictionary previously produced by wrap().
        :return bytes: Raw master key bytes.
        """
        if meta.get("provider") != "keyring":
            raise ValueError("KeyringProtector cannot unwrap meta from other provider")
        if keyring is None:
            raise RuntimeError("keyring package not available")
        name = meta["name"]
        val = keyring.get_password(meta["service"], name)
        if val is None:
            raise RuntimeError("no secret found in keyring for given metadata")
        return _unb64(val)


# -------------------------
# FileKeyStore
# -------------------------
class FileKeyStore:
    """
    File-based keystore.

    Directory layout (default ~/.mesh/keystore):
      master.key           # JSON container with protector metadata
      keys/
        <uuid>.key         # JSON containers with encrypted key blobs
      keystore.json        # optional metadata (active key etc.)

    The master.key content is produced/consumed by the selected Protector
    implementation. Individual key files are encrypted using AES-GCM with the master_key.
    """

    MASTER_FILENAME = "master.key"
    KEYS_DIRNAME = "keys"
    METADATA_FILENAME = "keystore.json"

    def __init__(self, path: str | Path, protector: Protector):
        """
        Initialize the FileKeyStore.

        :param path: Path to the keystore directory. It will be created if missing.
        :param protector: Protector instance used to wrap/unwrap the master key.
        """
        self.path = Path(path).expanduser()
        self.path.mkdir(parents = True, exist_ok = True)
        (self.path / self.KEYS_DIRNAME).mkdir(parents = True, exist_ok = True)
        self._master_meta_path = self.path / self.MASTER_FILENAME
        self._keys_dir = self.path / self.KEYS_DIRNAME
        self._meta_path = self.path / self.METADATA_FILENAME
        self._protector = protector
        self._master_key: Optional[bytes] = None
        self._meta: Dict[str, Any] = {}

        _ensure_mode_600(self.path)
        _ensure_mode_600(self._keys_dir)

    # ---------- master key management ----------
    def exists(self) -> bool:
        """
        Check if the master key file exists.

        :return: True if master.key exists, False otherwise.
        """
        return self._master_meta_path.exists()

    def create_new(self, overwrite: bool = False) -> None:
        """
        Generate a new master key and store it using the configured Protector.

        :param overwrite: If True, overwrite existing master.key; otherwise raise FileExistsError.
        """
        if self.exists() and not overwrite:
            raise FileExistsError("master.key already exists")
        master_key = os.urandom(32)
        meta = self._protector.wrap(master_key)
        self._master_meta_path.write_text(json.dumps(meta, separators = (",", ":")), encoding = "utf-8")
        _ensure_mode_600(self._master_meta_path)
        self._master_key = master_key
        self._meta = {"created_at": int(time.time()), "active_key": None}
        self._write_meta()

    def load(self) -> None:
        """
        Load master key using protector.unwrap(meta).
        """
        if not self.exists():
            raise FileNotFoundError("master.key not found")
        raw = json.loads(self._master_meta_path.read_text(encoding = "utf-8"))
        master_key = self._protector.unwrap(raw)
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != 32:
            raise ValueError("invalid master key")
        self._master_key = bytes(master_key)
        if self._meta_path.exists():
            self._meta = json.loads(self._meta_path.read_text(encoding = "utf-8"))
        else:
            self._meta = {"created_at": int(time.time()), "active_key": None}

    # ---------- metadata ----------
    def _write_meta(self) -> None:
        """
        Persist the in-memory metadata to keystore.json.
        Ensures file permissions are restricted to owner (mode 600).
        """
        self._meta_path.write_text(json.dumps(self._meta, separators = (",", ":")), encoding = "utf-8")
        _ensure_mode_600(self._meta_path)

    # ---------- low-level key file helpers ----------
    def _key_file_path(self, key_id: UUID) -> Path:
        """
        Compute the filesystem path for a given key file.

        :param key_id: UUID of the key.
        :return: Path object pointing to the key file (keys/<uuid>.key).
        """
        return self._keys_dir / f"{key_id.hex}.key"

    def _encrypt_with_master(self, plaintext: bytes) -> Dict[str, Any]:
        """
        Encrypt data using the loaded master key with AES-GCM.

        :param plaintext: Raw bytes to encrypt.
        :return: Dictionary containing:
                 - version: format version (int)
                 - nonce: base64-encoded AES-GCM nonce
                 - ciphertext: base64-encoded encrypted data
        """
        if self._master_key is None:
            raise ValueError("master key not loaded")
        aesgcm = AESGCM(self._master_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext, None)
        return {"version": 1, "nonce": _b64(nonce), "ciphertext": _b64(ct)}

    def _decrypt_with_master(self, blob: Dict[str, Any]) -> bytes:
        """
        Decrypt a blob previously encrypted with _encrypt_with_master.

        :param blob: Dictionary containing version, nonce, and ciphertext.
        :return: Decrypted bytes.
        """
        if self._master_key is None:
            raise ValueError("master key not loaded")
        aesgcm = AESGCM(self._master_key)
        nonce = _unb64(blob["nonce"])
        ct = _unb64(blob["ciphertext"])
        return aesgcm.decrypt(nonce, ct, None)

    # ---------- public API ----------
    def generate_key(self, kind: str = "symmetric") -> UUID:
        """
        Generate a new cryptographic key of the specified type, encrypt it with the master key,
        and store it in the keystore. If no active key exists, set this key as active.

        Supported key types:
        - "symmetric": 32-byte symmetric key (AEAD).
        - "ed25519": private key for Ed25519 digital signatures.
        - "x25519": private key for X25519 key exchange (ECDH).

        :return: UUID of the generated key.
        """
        if self._master_key is None:
            raise ValueError("master key not loaded; call load() or create_new() first")

        key_id: UUID = KeyIdHelpers.new_key_id()
        created_at = int(time.time())

        if kind == "symmetric":
            key_bytes = os.urandom(32)
            meta = {"type": "symmetric", "created_at": created_at}
        elif kind == "ed25519":
            pair = SigningKeyPair.generate()
            sk_bytes = pair.sk.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
            pk_bytes = pair.pk.public_bytes(
                encoding = serialization.Encoding.Raw, format = serialization.PublicFormat.Raw
            )
            key_bytes = sk_bytes
            meta = {"type": "ed25519", "created_at": created_at, "pub": _b64(pk_bytes)}
        elif kind == "x25519":
            pair = EncryptionKeyPair.generate()
            sk_bytes = pair.sk.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption(),
            )
            pk_bytes = pair.pk.public_bytes(
                encoding = serialization.Encoding.Raw, format = serialization.PublicFormat.Raw
            )
            key_bytes = sk_bytes
            meta = {"type": "x25519", "created_at": created_at, "pub": _b64(pk_bytes)}
        else:
            raise ValueError("unsupported key kind")

        blob = self._encrypt_with_master(key_bytes)
        blob["meta"] = meta
        path = self._key_file_path(key_id)
        path.write_text(json.dumps(blob, separators = (",", ":")), encoding = "utf-8")
        _ensure_mode_600(path)
        if self._meta.get("active_key") is None:
            self._meta["active_key"] = key_id.hex
            self._write_meta()
        return key_id

    def import_key(self, key_id: UUID, key_bytes: bytes, kind: str) -> None:
        """
        Import an externally-provided raw key into the keystore under the given key_id.

        :param key_id: UUID under which to store the key.
        :param key_bytes: Raw key bytes (format depends on kind).
        :param kind: Type of the key ("symmetric", "ed25519", "x25519").
        """
        if self._master_key is None:
            raise ValueError("master key not loaded")
        created_at = int(time.time())
        meta = {"type": kind, "created_at": created_at}
        blob = self._encrypt_with_master(key_bytes)
        blob["meta"] = meta
        path = self._key_file_path(key_id)
        path.write_text(json.dumps(blob, separators = (",", ":")), encoding = "utf-8")
        _ensure_mode_600(path)

    def get_key(self, key_id: UUID) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieve the raw key bytes and metadata for a given key_id.

        :param key_id: UUID of the key to fetch.
        :return: Tuple of (raw_key_bytes, metadata dictionary).
        """
        path = self._key_file_path(key_id)
        if not path.exists():
            raise KeyError(key_id.hex)
        blob = json.loads(path.read_text(encoding = "utf-8"))
        key_bytes = self._decrypt_with_master(blob)
        meta = blob.get("meta", {})
        return key_bytes, meta

    def list_keys(self) -> List[Dict[str, Any]]:
        """
        List metadata of all keys present in the keystore (does not return raw key bytes).

        :return: List of dictionaries containing "key_id" and "meta" for each key.
        :raises OSError: if reading the directory fails.
        """
        out: List[Dict[str, Any]] = []
        for p in sorted(self._keys_dir.glob("*.key")):
            try:
                blob = json.loads(p.read_text(encoding = "utf-8"))
                meta = blob.get("meta", {})
                key_id_hex = p.stem
                out.append({"key_id": key_id_hex, "meta": meta})
            except Exception:
                continue
        return out

    def set_active_key(self, key_id: UUID) -> None:
        """
        Set the specified key as the active key in the keystore metadata.

        :param key_id: UUID of the key to set as active.
        """
        self._meta["active_key"] = key_id.hex
        self._write_meta()

    def get_active_key_id(self) -> Optional[UUID]:
        """
        Return the UUID of the currently active key, or None if no active key is set.

        :return: UUID of the active key or None.
        """
        v = self._meta.get("active_key")
        return UUID(v) if v else None

    def rotate_key(self, old_key_id: UUID, new_key_id: UUID, migrator: Optional[callable] = None) -> None:
        """
        Rotate the keystore to use a new active key and optionally migrate existing data.

        :param old_key_id: UUID of the old key (for migrator reference).
        :param new_key_id: UUID of the new key to activate.
        :param migrator: Optional callable(old_key_id, new_key_id) to migrate existing encrypted data.
        """
        if not self._key_file_path(new_key_id).exists():
            raise FileNotFoundError("new key not found")
        self.set_active_key(new_key_id)
        if migrator:
            migrator(old_key_id, new_key_id)

    def get_active_key(self) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """
        Rotate the keystore to use a new active key and optionally migrate existing data.

        :param old_key_id: UUID of the old key (for migrator reference).
        :param new_key_id: UUID of the new key to activate.
        :param migrator: Optional callable(old_key_id, new_key_id) to migrate existing encrypted data.
        """
        kid = self.get_active_key_id()
        if kid is None:
            return None
        return self.get_key(kid)

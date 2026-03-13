from __future__ import annotations

import base64
import json
import os
from typing import Dict, Optional
from uuid import UUID

import pytest

from mesh_crypto import keys as keys_mod
from mesh_crypto.keystore import (
    FileKeyStore,
    PasswordProtector,
    KeyringProtector,
)

# -------------------------
# Helpers
# -------------------------


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# -------------------------
# Tests
# -------------------------


def test_password_keystore_lifecycle(tmp_path):
    """
    Create a keystore with PasswordProtector, generate a symmetric key,
    close the keystore (wipe master), then reload using the same password
    and verify the stored key decrypts to the same bytes and metadata.
    """
    ks_dir = tmp_path / "keystore_pw"
    protector = PasswordProtector("strong-passphrase")
    ks = FileKeyStore(ks_dir, protector)

    ks.create_new()
    kid = ks.generate_key("symmetric")
    raw1, meta1 = ks.get_key(kid)
    assert isinstance(raw1, (bytes, bytearray))
    assert meta1["type"] == "symmetric"

    ks.close()

    ks2 = FileKeyStore(ks_dir, protector)
    ks2.load()
    raw2, meta2 = ks2.get_key(kid)
    assert raw1 == raw2
    assert meta1 == meta2


def test_import_and_list_keys(tmp_path):
    """
    Import an externally-provided symmetric key and verify list_keys includes it.
    """
    ks_dir = tmp_path / "keystore_import"
    protector = PasswordProtector("pw")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    external_key = os.urandom(32)
    kid = keys_mod.KeyIdHelpers.new_key_id()
    ks.import_key(kid, external_key, "symmetric")

    listed = ks.list_keys()

    found = [e for e in listed if str(e["key_id"]) == str(kid)]
    assert len(found) == 1
    meta = found[0]["meta"]
    assert meta["type"] == "symmetric"

    got, got_meta = ks.get_key(kid)
    assert got == external_key
    assert got_meta["type"] == "symmetric"


def test_ed25519_meta_public(tmp_path):
    """
    Generating an ed25519 key should store 'pub' in meta (base64-encoded 32 bytes).
    """
    ks_dir = tmp_path / "keystore_ed"
    protector = PasswordProtector("pw2")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    kid = ks.generate_key("ed25519")
    _, meta = ks.get_key(kid)
    assert meta["type"] == "ed25519"
    assert "pub" in meta
    pub_b64 = meta["pub"]
    pub = base64.b64decode(pub_b64.encode("ascii"))
    assert isinstance(pub, bytes)
    assert len(pub) == 32


def test_set_active_and_rotate(tmp_path):
    """
    Generate two keys, set the second as active, rotate with a migrator and verify migrator called.
    """
    ks_dir = tmp_path / "keystore_rotate"
    protector = PasswordProtector("pw3")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    kid1 = ks.generate_key("symmetric")
    kid2 = ks.generate_key("symmetric")

    active_before = ks.get_active_key_id()
    assert active_before is not None

    ks.set_active_key(kid2)
    assert ks.get_active_key_id() == kid2

    called = {}

    def migrator(old_k, new_k):
        called["old"] = old_k
        called["new"] = new_k

    ks.rotate_key(kid1, kid2, migrator=migrator)
    assert called.get("old") == UUID(str(kid1))
    assert called.get("new") == UUID(str(kid2))
    assert ks.get_active_key_id() == kid2


def test_wipe_master_and_operations_after(tmp_path):
    """
    Ensure wipe_master clears in-memory master key and subsequent operations that require
    the master (like get_key) raise an error.
    """
    ks_dir = tmp_path / "keystore_wipe"
    protector = PasswordProtector("pw4")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    kid = ks.generate_key("symmetric")
    raw, _ = ks.get_key(kid)
    assert isinstance(raw, bytes)

    ks.wipe_master()

    with pytest.raises(ValueError):
        ks.get_key(kid)


def test_keyring_protector_roundtrip(tmp_path, monkeypatch):
    """
    Simulate keyring backend (in-memory dict) so KeyringProtector can store master_key.
    Ensure create_new stores the key in mocked keyring and load recovers it.
    """
    ks_dir = tmp_path / "keystore_keyring"

    store: Dict[str, str] = {}

    def fake_set_password(service: str, name: str, secret: str) -> None:
        store[(service, name)] = secret

    def fake_get_password(service: str, name: str) -> Optional[str]:
        return store.get((service, name))

    import mesh_crypto.keystore as kc_mod

    monkeypatch.setattr(kc_mod, "keyring", kc_mod.keyring)
    monkeypatch.setattr(kc_mod.keyring, "set_password", fake_set_password, raising=False)
    monkeypatch.setattr(kc_mod.keyring, "get_password", fake_get_password, raising=False)

    protector = KeyringProtector(service_name="mesh-test-svc", entry_name="mesh-test-entry")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    meta = read_json(ks_dir / "master.key")
    assert meta["provider"] == "keyring"
    assert meta["service"] == "mesh-test-svc"
    assert "name" in meta

    ks2 = FileKeyStore(ks_dir, protector)
    ks2.load()

    kid = ks2.generate_key("symmetric")
    _, m = ks2.get_key(kid)
    assert m["type"] == "symmetric"


def test_invalid_master_meta_raises(tmp_path):
    """
    If master.key contains invalid JSON or wrong structure, load() should raise.
    """
    ks_dir = tmp_path / "keystore_bad"
    ks_dir.mkdir(parents=True, exist_ok=True)

    (ks_dir / "master.key").write_text("not-a-json", encoding="utf-8")

    protector = PasswordProtector("pwx")
    ks = FileKeyStore(ks_dir, protector)

    with pytest.raises(Exception):
        ks.load()


def test_list_keys_returns_keyids(tmp_path):
    """
    list_keys should return list of dicts with key_id as KeyId instances and meta dicts.
    """
    ks_dir = tmp_path / "keystore_list"
    protector = PasswordProtector("pw5")
    ks = FileKeyStore(ks_dir, protector)
    ks.create_new()

    k1 = ks.generate_key("symmetric")
    k2 = ks.generate_key("ed25519")

    listed = ks.list_keys()
    ids = {str(x["key_id"]) for x in listed}
    assert str(k1) in ids
    assert str(k2) in ids

    for entry in listed:
        assert "meta" in entry
        assert "type" in entry["meta"]

import sqlite3
import pytest

from mesh_node_db import NodeDB, Entity


class DummyCrypto:
    """Very small deterministic 'crypto' used only for tests."""

    def encrypt(self, plaintext: bytes) -> bytes:
        return b"ENC:" + plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise ValueError("ciphertext not bytes")
        if not ciphertext.startswith(b"ENC:"):
            raise ValueError("bad ciphertext")
        return bytes(ciphertext[4:])


def test_crud_create_read_update_delete(tmp_path):
    db_file = tmp_path / "node.db"
    db = NodeDB(str(db_file))
    db.open()

    db.create("id1", {"name": "Alice", "age": 30}, kind = "user")
    ent = db.read("id1")
    assert isinstance(ent, Entity)
    assert ent.id == "id1"
    assert ent.kind == "user"
    assert ent.data["name"] == "Alice"
    assert ent.data["age"] == 30

    db.update("id1", {"age": 31, "active": True})
    ent2 = db.read("id1")
    assert ent2.data["name"] == "Alice"
    assert ent2.data["age"] == 31
    assert ent2.data["active"] is True

    db.delete("id1")
    assert db.read("id1") is None

    db.close()


def test_create_duplicate_raises(tmp_path):
    db_file = tmp_path / "node_dup.db"
    db = NodeDB(str(db_file))
    db.open()
    db.create("x", {"v": 1})

    with pytest.raises(sqlite3.IntegrityError):
        db.create("x", {"v": 2})
    db.close()


def test_batch_write_and_upsert(tmp_path):
    db_file = tmp_path / "batch.db"
    db = NodeDB(str(db_file))
    db.open()

    items = [
        ("a", "kind1", {"val": 1}),
        ("b", "kind1", {"val": 2}),
    ]
    db.batch_write(items)

    a = db.read("a")
    b = db.read("b")
    assert a.data["val"] == 1
    assert b.data["val"] == 2

    db.batch_write([("a", "kind1", {"val": 100})])
    a2 = db.read("a")
    assert a2.data["val"] == 100

    db.close()


def test_crypto_integration_stores_encrypted_blob(tmp_path):
    db_file = tmp_path / "crypto.db"
    crypto = DummyCrypto()
    db = NodeDB(str(db_file), crypto = crypto)
    db.open()

    payload = {"msg": "hello"}
    db.create("c1", payload)
    ent = db.read("c1")
    assert ent.data == payload

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT data FROM entities WHERE id = ?", ("c1",))
    row = cur.fetchone()
    conn.close()
    assert row is not None
    raw_blob = row[0]
    assert isinstance(raw_blob, (bytes, bytearray))
    assert raw_blob.startswith(b"ENC:")

    db.close()


def test_iter_all_strict_false_skips_corrupted(tmp_path):
    db_file = tmp_path / "iter.db"
    db = NodeDB(str(db_file))
    db.open()

    db.create("good", {"a": 1})

    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("INSERT INTO entities (id, kind, created_at, updated_at, data) VALUES (?, ?, ?, ?, ?)",
                ("bad", "kind", 1, 1, b"NOTJSONORDECRYPT"))
    conn.commit()
    conn.close()

    ids = [e.id for e in db.iter_all(strict = False)]
    assert "good" in ids
    assert "bad" not in ids

    with pytest.raises(Exception):
        list(db.iter_all(strict = True))

    db.close()


def test_backup_creates_file(tmp_path):
    db_file = tmp_path / "orig.db"
    dest = tmp_path / "copy.db"
    db = NodeDB(str(db_file))
    db.open()
    db.create("one", {"x": 1})
    db.backup(str(dest))
    assert dest.exists()
    assert dest.stat().st_size > 0
    conn = sqlite3.connect(str(dest))
    cur = conn.cursor()
    cur.execute("SELECT id FROM entities WHERE id = ?", ("one",))
    assert cur.fetchone() is not None
    conn.close()
    db.close()


def test_run_migration_script(tmp_path):
    db_file = tmp_path / "mig.db"
    db = NodeDB(str(db_file))
    db.open()
    sql = """
    CREATE TABLE IF NOT EXISTS temp_table (
        tid INTEGER PRIMARY KEY,
        note TEXT
    );
    """
    db.run_migration_script(sql)
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='temp_table'")
    assert cur.fetchone() is not None
    conn.close()
    db.close()

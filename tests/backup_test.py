import hashlib
import json
import pathlib
import sqlite3
import tempfile
import subprocess
import sys

tool = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "backup.py"
with tempfile.TemporaryDirectory(prefix="private-sync-backup-test-") as temp:
    root = pathlib.Path(temp)
    data = root / "data"
    (data / "blobs").mkdir(parents=True)
    payloads = [b"synthetic current block", b"synthetic old block"]
    hashes = [hashlib.sha256(b).hexdigest() for b in payloads]
    for h, b in zip(hashes, payloads):
        (data / "blobs" / h).write_bytes(b)
    db = sqlite3.connect(data / "meta.sqlite")
    db.executescript("CREATE TABLE files (path TEXT, chunks TEXT); CREATE TABLE versions (path TEXT, chunks TEXT); CREATE TABLE devices (id INT); CREATE TABLE pairs (id INT);")
    db.execute("INSERT INTO files VALUES (?,?)", ("test", json.dumps([hashes[0]])))
    db.execute("INSERT INTO versions VALUES (?,?)", ("test", json.dumps([hashes[1]])))
    db.execute("INSERT INTO devices VALUES (1)")
    db.execute("INSERT INTO pairs VALUES (1)")
    db.commit()
    db.close()
    subprocess.run([sys.executable, str(tool), "snapshot", "--data", str(data), "--backups", str(root / "backups")], check=True)
    snap = next((root / "backups").iterdir())
    target = root / "restored"
    subprocess.run([sys.executable, str(tool), "restore", "--snapshot", str(snap), "--target", str(target)], check=True)
    for h, b in zip(hashes, payloads):
        assert (target / "blobs" / h).read_bytes() == b
    db = sqlite3.connect(target / "meta.sqlite")
    for table, count in [("files", 1), ("versions", 1), ("devices", 0), ("pairs", 0)]:
        assert db.execute("SELECT count(*) FROM " + table).fetchone()[0] == count
    db.close()
    (snap / "blobs" / hashes[0]).write_bytes(b"corrupt")
    assert subprocess.run([sys.executable, str(tool), "verify", "--snapshot", str(snap)], capture_output=True).returncode != 0
    print("PASS: nonempty snapshot, current and historical blocks restored exactly, device enrollment reset, corruption detected")

#!/usr/bin/env python3
"""Verified snapshots of the Private Vault Sync store. No recovery key required."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import tempfile
from contextlib import closing

def connect(path):
    return sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)

def inventory(db):
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("SQLite integrity check failed")
    refs = set()
    for table in ("files", "versions"):
        for (chunks,) in db.execute("SELECT chunks FROM " + table):
            for h in json.loads(chunks):
                if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                    raise ValueError("Invalid block identifier")
                refs.add(h)
    return refs

def verify(snapshot):
    with closing(connect(snapshot / "meta.sqlite")) as db:
        refs = inventory(db)
        counts = {t: db.execute("SELECT count(*) FROM " + t).fetchone()[0]
                  for t in ("files", "versions", "devices")}
    for h in refs:
        with (snapshot / "blobs" / h).open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != h:
                raise ValueError("Block checksum mismatch")
    return counts, len(refs)

def sync_file(p):
    with p.open("rb") as f:
        os.fsync(f.fileno())

def sync_dir(p):
    if os.name != "nt":
        fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

def snapshot(data, backups, keep):
    backups.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".partial-", dir=backups))
    try:
        with closing(connect(data / "meta.sqlite")) as src, closing(sqlite3.connect(stage / "meta.sqlite")) as dst:
            src.backup(dst)
            refs = inventory(dst)
        (stage / "blobs").mkdir()
        for h in refs:
            target = stage / "blobs" / h
            shutil.copyfile(data / "blobs" / h, target)
            sync_file(target)
        counts, blocks = verify(stage)
        (stage / "manifest.json").write_text(json.dumps(
            {"created": stamp, "counts": counts, "blocks": blocks}, indent=2))
        for p in (stage / "meta.sqlite", stage / "manifest.json"):
            sync_file(p)
        sync_dir(stage / "blobs")
        sync_dir(stage)
        target = backups / stamp
        stage.rename(target)
        sync_dir(backups)
        # Only rotate snapshot directories created by this tool.
        snapshots = sorted(p for p in backups.iterdir()
                           if p.is_dir() and not p.is_symlink() and p.name.endswith("Z")
                           and (p / "manifest.json").is_file())
        for p in snapshots[:-keep]:
            shutil.rmtree(p)
        print("Backup verified:", stamp, counts, "blocks:", blocks)
        return target
    finally:
        if stage.exists():
            shutil.rmtree(stage)

def restore(source, target):
    verify(source)
    if target.exists():
        raise FileExistsError("Restore target must not exist; never overwrite a running store")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".restore-", dir=target.parent))
    try:
        shutil.copyfile(source / "meta.sqlite", stage / "meta.sqlite")
        shutil.copytree(source / "blobs", stage / "blobs")
        # Re-enroll all devices after restoring; avoid reviving revoked credentials.
        with closing(sqlite3.connect(stage / "meta.sqlite")) as db:
            db.execute("DELETE FROM pairs")
            db.execute("DELETE FROM devices")
            db.commit()
        counts, blocks = verify(stage)
        for p in stage.rglob("*"):
            if p.is_file():
                sync_file(p)
        sync_dir(stage / "blobs")
        sync_dir(stage)
        stage.rename(target)
        sync_dir(target.parent)
        print("Restore verified:", counts, "blocks:", blocks)
    finally:
        if stage.exists():
            shutil.rmtree(stage)

def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--data", type=pathlib.Path, required=True)
    s.add_argument("--backups", type=pathlib.Path, required=True)
    s.add_argument("--keep", type=int, default=7)
    v = sub.add_parser("verify")
    v.add_argument("--snapshot", type=pathlib.Path, required=True)
    r = sub.add_parser("restore")
    r.add_argument("--snapshot", type=pathlib.Path, required=True)
    r.add_argument("--target", type=pathlib.Path, required=True)
    args = p.parse_args()
    if args.command == "snapshot":
        if args.keep < 1:
            p.error("--keep must be positive")
        snapshot(args.data, args.backups, args.keep)
    elif args.command == "verify":
        print("Verified:", *verify(args.snapshot))
    else:
        restore(args.snapshot, args.target)

if __name__ == "__main__":
    main()

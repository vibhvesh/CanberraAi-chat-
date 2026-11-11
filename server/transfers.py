"""Encrypted, resumable server-relay file transfers for CanberraAI.

Files are encrypted in independently authenticated AES-GCM chunks. A per-transfer
key is wrapped with the server master key. Keep CBRIDGE_FILE_KEY outside the
application data directory and back it up securely.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA = Path(os.getenv("CBRIDGE_DATA_DIR", "/var/lib/cbridge"))
ROOT = DATA / "transfers"
DB = DATA / "transfers.sqlite3"
CHUNK_SIZE = 1024 * 1024
MAX_SIZE = int(os.getenv("CBRIDGE_TRANSFER_MAX_BYTES", str(10 * 1024**3)))
RETENTION = int(os.getenv("CBRIDGE_TRANSFER_RETENTION_DAYS", "7"))
KEY_TEXT = os.getenv("CBRIDGE_FILE_KEY", "")
if not KEY_TEXT:
    raise RuntimeError("CBRIDGE_FILE_KEY is required for encrypted file transfers")
try:
    MASTER = bytes.fromhex(KEY_TEXT)
except ValueError as exc:
    raise RuntimeError("CBRIDGE_FILE_KEY must be a 32-byte hex key") from exc
if len(MASTER) != 32:
    raise RuntimeError("CBRIDGE_FILE_KEY must decode to exactly 32 bytes")

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    ROOT.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS transfers (
        id TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER NOT NULL,
        sha256 TEXT, key_wrap BLOB NOT NULL, chunk_count INTEGER NOT NULL,
        uploaded_chunks INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
        created REAL NOT NULL, expires REAL NOT NULL, sender TEXT NOT NULL,
        recipient TEXT NOT NULL DEFAULT '')""")
    db.commit()
    return db

def _wrap(key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(MASTER).encrypt(nonce, key, b"cbridge-transfer-key-v1")

def _unwrap(blob: bytes) -> bytes:
    return AESGCM(MASTER).decrypt(blob[:12], blob[12:], b"cbridge-transfer-key-v1")

def _path(tid: str, index: int) -> Path:
    if not tid.isalnum() or len(tid) != 32 or index < 0:
        raise ValueError("Invalid transfer identifier")
    return ROOT / tid / f"{index:08d}.bin"

def create(filename: str, size: int, sender: str, recipient: str = ""):
    if size < 0 or size > MAX_SIZE:
        raise ValueError(f"File size must be between 0 and {MAX_SIZE} bytes")
    tid = secrets.token_hex(16)
    key = AESGCM.generate_key(bit_length=256)
    chunks = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    now = time.time()
    with connect() as db:
        db.execute("INSERT INTO transfers VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (tid, Path(filename).name[:180], size, None, _wrap(key), chunks,
                    0, "uploading", now, now + RETENTION * 86400,
                    sender[:100], recipient[:100]))
    (ROOT / tid).mkdir(mode=0o700, parents=True, exist_ok=True)
    return {"id": tid, "chunk_size": CHUNK_SIZE, "chunks": chunks, "expires": now + RETENTION * 86400}

def put_chunk(tid: str, index: int, data: bytes):
    with connect() as db:
        row = db.execute("SELECT * FROM transfers WHERE id=?", (tid,)).fetchone()
        if not row or row["status"] != "uploading" or row["expires"] < time.time():
            raise LookupError("Transfer not found, expired, or not accepting chunks")
        if index >= row["chunk_count"]:
            raise ValueError("Chunk index out of range")
        expected = min(CHUNK_SIZE, max(0, row["size"] - index * CHUNK_SIZE))
        if len(data) != expected:
            raise ValueError(f"Expected {expected} bytes for this chunk")
        key = _unwrap(row["key_wrap"])
        nonce = secrets.token_bytes(12)
        aad = f"{tid}:{index}:{row['size']}".encode()
        encrypted = nonce + AESGCM(key).encrypt(nonce, data, aad)
        path = _path(tid, index)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(encrypted)
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        count = sum(1 for i in range(row["chunk_count"]) if _path(tid, i).exists())
        db.execute("UPDATE transfers SET uploaded_chunks=? WHERE id=?", (count, tid))
        return {"uploaded_chunks": count, "chunks": row["chunk_count"]}

def complete(tid: str):
    with connect() as db:
        row = db.execute("SELECT * FROM transfers WHERE id=?", (tid,)).fetchone()
        if not row or row["status"] != "uploading":
            raise LookupError("Transfer not found or already completed")
        digest = hashlib.sha256()
        key = _unwrap(row["key_wrap"])
        for i in range(row["chunk_count"]):
            raw = _path(tid, i).read_bytes()
            aad = f"{tid}:{i}:{row['size']}".encode()
            digest.update(AESGCM(key).decrypt(raw[:12], raw[12:], aad))
        if sum(_path(tid, i).stat().st_size - 28 for i in range(row["chunk_count"])) != row["size"]:
            raise ValueError("Encrypted chunk size validation failed")
        sha = digest.hexdigest()
        db.execute("UPDATE transfers SET sha256=?,status='ready' WHERE id=?", (sha, tid))
        return {"id": tid, "sha256": sha, "status": "ready"}

def listing():
    now = time.time()
    with connect() as db:
        db.execute("DELETE FROM transfers WHERE expires < ?", (now,))
        db.commit()
        rows = db.execute("SELECT id,filename,size,sha256,status,created,expires,sender,recipient FROM transfers ORDER BY created DESC LIMIT 500").fetchall()
        return [dict(r) for r in rows]

def read_file(tid: str):
    with connect() as db:
        row = db.execute("SELECT * FROM transfers WHERE id=? AND status='ready' AND expires>=?", (tid, time.time())).fetchone()
        if not row:
            raise LookupError("Completed transfer not found or expired")
        key = _unwrap(row["key_wrap"])
        output = bytearray()
        for i in range(row["chunk_count"]):
            raw = _path(tid, i).read_bytes()
            aad = f"{tid}:{i}:{row['size']}".encode()
            output.extend(AESGCM(key).decrypt(raw[:12], raw[12:], aad))
        return row["filename"], bytes(output), row["sha256"]

def remove(tid: str):
    with connect() as db:
        row = db.execute("SELECT id FROM transfers WHERE id=?", (tid,)).fetchone()
        if not row:
            return False
        db.execute("DELETE FROM transfers WHERE id=?", (tid,))
    import shutil
    shutil.rmtree(ROOT / tid, ignore_errors=True)
    return True

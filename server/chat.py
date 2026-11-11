"""Shared-password device pairing and live chat presence."""
import hashlib, hmac, os, secrets, sqlite3, time
from pathlib import Path

DATA=Path(os.getenv("CBRIDGE_DATA_DIR","/var/lib/cbridge"))
DB=DATA/"chat.sqlite3"
PAIR_PASSWORD=os.getenv("CBRIDGE_CHAT_PASSWORD","C1nb3rr1")

def db():
    DATA.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS devices(
      id TEXT PRIMARY KEY,name TEXT NOT NULL,token_hash TEXT NOT NULL,
      created REAL NOT NULL,last_seen REAL NOT NULL)""")
    c.commit(); return c

def pair(name,password):
    if not hmac.compare_digest(str(password),PAIR_PASSWORD):
        raise PermissionError("Incorrect pairing password")
    name="".join(ch for ch in str(name)[:48] if ch.isalnum() or ch in "-_. ") or "Linux device"
    did=secrets.token_hex(8); token=secrets.token_urlsafe(32); now=time.time()
    with db() as c:
        c.execute("INSERT INTO devices VALUES(?,?,?,?,?)",
                  (did,name,hashlib.sha256(token.encode()).hexdigest(),now,now))
    return {"device_id":did,"device_token":token,"name":name}

def authenticate(token):
    if not token: return None
    digest=hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row=c.execute("SELECT id,name FROM devices WHERE token_hash=?",(digest,)).fetchone()
        if row: c.execute("UPDATE devices SET last_seen=? WHERE id=?",(time.time(),row["id"]))
    return dict(row) if row else None

def devices(online_ids):
    now=time.time()
    with db() as c:
        rows=c.execute("SELECT id,name,last_seen FROM devices ORDER BY name").fetchall()
    return [{"id":r["id"],"name":r["name"],"online":r["id"] in online_ids,
             "last_seen":r["last_seen"]} for r in rows]

def device_name(did):
    with db() as c:
        r=c.execute("SELECT name FROM devices WHERE id=?",(did,)).fetchone()
    return r["name"] if r else did

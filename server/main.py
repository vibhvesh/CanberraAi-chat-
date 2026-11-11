import asyncio
import hmac
import os
import secrets
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse
from server.sentinel import ingest as ingest_sentinel, query_events, stats as sentinel_stats

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
DATA = Path(os.getenv("CBRIDGE_DATA_DIR", "/var/lib/cbridge"))
FILES = DATA / "files"
FILES.mkdir(parents=True, exist_ok=True)
TOKEN = os.getenv("CBRIDGE_TOKEN", "")
MAX_UPLOAD = int(os.getenv("CBRIDGE_MAX_UPLOAD", str(100 * 1024 * 1024)))
app = FastAPI(title="CanberraAI Chat + Sentinel", version="0.2.0")
clients = set()
latest = {"type": "clipboard", "text": "", "source": "server"}

def authorize(value):
    supplied = (value or "").removeprefix("Bearer ").strip()
    if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
        raise HTTPException(status_code=401, detail="Invalid access token")

def safe_name(value):
    name = Path(value or "upload.bin").name
    name = "".join(c for c in name if c.isalnum() or c in " ._-()")
    return name[:160] or "upload.bin"

@app.get("/", response_class=HTMLResponse)
async def index():
    return (WEB / "index.html").read_text(encoding="utf-8")

@app.get("/health")
async def health():
    return {"status": "ok", "app": "CanberraAI Chat + Sentinel"}

@app.get("/api/files")
async def list_files(authorization: str | None = Header(default=None)):
    authorize(authorization)
    result = []
    for p in sorted(FILES.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            result.append({"name": p.name, "size": p.stat().st_size, "modified": int(p.stat().st_mtime)})
    return {"files": result}

@app.post("/api/files")
async def upload(file: UploadFile = File(...), authorization: str | None = Header(default=None)):
    authorize(authorization)
    target = FILES / (secrets.token_hex(5) + "_" + safe_name(file.filename))
    size = 0
    try:
        with target.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(status_code=413, detail="File exceeds upload limit")
                out.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    return {"name": target.name, "size": size}

def get_file(name):
    target = (FILES / Path(name).name).resolve()
    if target.parent != FILES.resolve() or not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return target

@app.get("/api/files/{name}")
async def download(name: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    target = get_file(name)
    return FileResponse(target, filename=target.name)

@app.delete("/api/files/{name}")
async def delete(name: str, authorization: str | None = Header(default=None)):
    authorize(authorization)
    get_file(name).unlink()
    return {"deleted": True}

@app.post("/api/sentinel/events")
async def sentinel_ingest(payload: dict, authorization: str | None = Header(default=None)):
    authorize(authorization)
    events = payload.get("events", []) if isinstance(payload, dict) else []
    if not isinstance(events, list) or len(events) > 100:
        raise HTTPException(status_code=400, detail="Send an events array with at most 100 entries")
    accepted = ingest_sentinel(events)
    return {"accepted": len(accepted)}

@app.get("/api/sentinel/events")
async def sentinel_event_list(authorization: str | None = Header(default=None),
                              limit: int = Query(default=100, ge=1, le=500),
                              category: str | None = None, host: str | None = None,
                              q: str | None = None, since: float | None = None):
    authorize(authorization)
    return {"events": query_events(limit, category, host, q, since)}

@app.get("/api/sentinel/stats")
async def sentinel_summary(authorization: str | None = Header(default=None)):
    authorize(authorization)
    return sentinel_stats()

async def broadcast(message, sender=None):
    stale = []
    for ws in tuple(clients):
        if ws is sender:
            continue
        try:
            await ws.send_json(message)
        except Exception:
            stale.append(ws)
    for ws in stale:
        clients.discard(ws)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        auth = await asyncio.wait_for(ws.receive_json(), timeout=10)
        supplied = str(auth.get("token", "")) if isinstance(auth, dict) else ""
        if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
            await ws.close(code=4401, reason="Unauthorized")
            return
        clients.add(ws)
        await ws.send_json(latest)
        while True:
            msg = await ws.receive_json()
            if not isinstance(msg, dict) or msg.get("type") != "clipboard":
                continue
            latest.update(type="clipboard", text=str(msg.get("text", ""))[:100000], source=str(msg.get("source", "device"))[:80])
            await broadcast(latest, sender=ws)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        clients.discard(ws)

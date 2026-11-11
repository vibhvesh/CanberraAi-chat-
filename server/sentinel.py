import json
import os
import sqlite3
import time
from pathlib import Path

DATA = Path(os.getenv("CBRIDGE_DATA_DIR", "/var/lib/cbridge"))
DB = DATA / "sentinel.sqlite3"
RETENTION_DAYS = int(os.getenv("SENTINEL_RETENTION_DAYS", "90"))

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL, host TEXT NOT NULL, category TEXT NOT NULL,
        label TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL,
        details TEXT NOT NULL
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events(host, ts DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_events_category_ts ON events(category, ts DESC)")
    db.execute("DELETE FROM events WHERE ts < ?", (time.time() - RETENTION_DAYS * 86400,))
    return db

def ingest(items):
    now = time.time()
    accepted = []
    with connect() as db:
        cutoff = now - RETENTION_DAYS * 86400
        db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        for item in items[:100]:
            if not isinstance(item, dict):
                continue
            ts = item.get("ts", now)
            try: ts = float(ts)
            except (TypeError, ValueError): ts = now
            # Reject timestamps too far from server time.
            if abs(ts - now) > 86400: ts = now
            host = str(item.get("host", "unknown"))[:128]
            category = str(item.get("category", "SYSTEM"))[:32].upper()
            label = str(item.get("label", "EVENT"))[:48].upper()
            severity = str(item.get("severity", "info")).lower()
            if severity not in ("info", "notice", "warning", "critical"): severity = "info"
            summary = str(item.get("summary", label))[:500]
            details = item.get("details", {})
            if not isinstance(details, dict): details = {"value": str(details)[:1000]}
            db.execute("INSERT INTO events(ts,host,category,label,severity,summary,details) VALUES(?,?,?,?,?,?,?)",
                       (ts, host, category, label, severity, summary, json.dumps(details, ensure_ascii=False)[:8000]))
            accepted.append({"ts": ts, "host": host, "category": category, "label": label,
                             "severity": severity, "summary": summary, "details": details})
    return accepted

def query_events(limit=100, category=None, host=None, q=None, since=None):
    limit = max(1, min(int(limit), 500))
    clauses, params = [], []
    if category:
        clauses.append("category=?"); params.append(category.upper()[:32])
    if host:
        clauses.append("host=?"); params.append(host[:128])
    if q:
        clauses.append("(summary LIKE ? OR details LIKE ? OR label LIKE ?)")
        term = "%" + q[:100] + "%"
        params.extend([term, term, term])
    if since:
        clauses.append("ts>=?"); params.append(float(since))
    sql = "SELECT * FROM events"
    if clauses: sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
    with connect() as db:
        rows = db.execute(sql, params).fetchall()
    return [{"id":r["id"],"ts":r["ts"],"host":r["host"],"category":r["category"],
             "label":r["label"],"severity":r["severity"],"summary":r["summary"],
             "details":json.loads(r["details"])} for r in rows]

def stats():
    now = time.time()
    with connect() as db:
        total = db.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (now-86400,)).fetchone()[0]
        hosts = db.execute("SELECT COUNT(DISTINCT host) FROM events WHERE ts>=?", (now-300,)).fetchone()[0]
        categories = {r["category"]: r["n"] for r in db.execute(
            "SELECT category,COUNT(*) n FROM events WHERE ts>=? GROUP BY category", (now-86400,)).fetchall()}
        alerts = db.execute("SELECT COUNT(*) FROM events WHERE ts>=? AND severity IN ('warning','critical')",
                            (now-86400,)).fetchone()[0]
    return {"events_24h":total,"active_hosts_5m":hosts,"alerts_24h":alerts,"categories_24h":categories,
            "retention_days":RETENTION_DAYS}

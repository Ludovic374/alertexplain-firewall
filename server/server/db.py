import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "events.db"

def _conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = _conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        event_type TEXT,
        severity TEXT,
        title TEXT,
        src TEXT,
        dst TEXT,
        proto TEXT,
        dport INTEGER,
        ports TEXT,
        what TEXT,
        risk TEXT,
        do TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS state (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    cur.execute("INSERT OR IGNORE INTO state(key,value) VALUES('scan_enabled','1')")

    conn.commit()
    conn.close()

def insert_event(d: dict):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events(ts,event_type,severity,title,src,dst,proto,dport,ports,what,risk,do)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        d.get("ts"),
        d.get("event_type"),
        d.get("severity"),
        d.get("title"),
        d.get("src"),
        d.get("dst"),
        d.get("proto"),
        d.get("dport"),
        d.get("ports"),
        d.get("what"),
        d.get("risk"),
        d.get("do"),
    ))
    conn.commit()
    conn.close()

def delete_event(event_id: int) -> int:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE id=?", (event_id,))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n

def clear_events():
    conn = _conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM events")
    conn.commit()
    conn.close()

def set_scan_state(enabled: bool):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO state(key,value) VALUES('scan_enabled',?)",
                ("1" if enabled else "0",))
    conn.commit()
    conn.close()

def get_scan_state() -> bool:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT value FROM state WHERE key='scan_enabled' LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return (row is None) or (row[0] == "1")
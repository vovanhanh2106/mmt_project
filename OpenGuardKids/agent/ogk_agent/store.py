"""Kho cục bộ (SQLite): bản sao chính sách, hàng đợi sự kiện (có batch_id chống trùng), bộ đếm sử dụng, thông báo."""
from __future__ import annotations
import json, sqlite3, threading, uuid


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT, subject TEXT,
                duration_sec INTEGER, policy_id TEXT, batch_id TEXT);
            CREATE TABLE IF NOT EXISTS usage(day TEXT, grp TEXT, seconds REAL, PRIMARY KEY(day, grp));
            """)

    # --- kv ---
    def set(self, k: str, v) -> None:
        with self.lock:
            self.db.execute("INSERT INTO kv VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))
            self.db.commit()

    def get(self, k: str, default=None):
        with self.lock:
            r = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default

    # --- usage ---
    def usage_add(self, day: str, grp: str, sec: float) -> None:
        with self.lock:
            self.db.execute("INSERT INTO usage VALUES(?,?,?) ON CONFLICT(day,grp) DO UPDATE SET seconds=seconds+excluded.seconds", (day, grp, sec))
            self.db.commit()

    def usage_get(self, day: str, grp: str) -> float:
        with self.lock:
            r = self.db.execute("SELECT seconds FROM usage WHERE day=? AND grp=?", (day, grp)).fetchone()
        return r[0] if r else 0.0

    # --- events ---
    def enqueue_event(self, ev: dict) -> None:
        with self.lock:
            self.db.execute("INSERT INTO events(ts,type,subject,duration_sec,policy_id) VALUES(?,?,?,?,?)",
                            (ev["ts"], ev["type"], ev["subject"], ev.get("duration_sec", 0), ev.get("policy_id")))
            self.db.commit()

    def freeze_batch(self, limit: int = 200):
        """Gán batch_id cố định cho các dòng chưa gửi; gửi lại cùng batch_id => server loại trùng (idempotent)."""
        with self.lock:
            row = self.db.execute("SELECT batch_id FROM events WHERE batch_id IS NOT NULL LIMIT 1").fetchone()
            if row:
                bid = row[0]
            else:
                ids = [r[0] for r in self.db.execute("SELECT id FROM events WHERE batch_id IS NULL ORDER BY id LIMIT ?", (limit,))]
                if not ids:
                    return None, []
                bid = uuid.uuid4().hex
                self.db.executemany("UPDATE events SET batch_id=? WHERE id=?", [(bid, i) for i in ids])
                self.db.commit()
            rows = self.db.execute("SELECT ts,type,subject,duration_sec,policy_id FROM events WHERE batch_id=? ORDER BY id", (bid,)).fetchall()
        return bid, [{"ts": r[0], "type": r[1], "subject": r[2], "duration_sec": r[3], **({"policy_id": r[4]} if r[4] else {})} for r in rows]

    def ack_batch(self, batch_id: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM events WHERE batch_id=?", (batch_id,))
            self.db.commit()

    def pending_events(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def recent_events(self, limit: int = 500):
        with self.lock:
            return self.db.execute("SELECT ts,type,subject,duration_sec FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def purge_all(self) -> None:
        """'Xóa toàn bộ dữ liệu của con tôi' – phía agent."""
        with self.lock:
            self.db.execute("DELETE FROM events"); self.db.execute("DELETE FROM usage")
            self.db.execute("DELETE FROM kv WHERE k LIKE 'notice:%' OR k LIKE 'req:%'")
            self.db.commit()

import hashlib
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from honeyglobe.events import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    dedup_hash TEXT UNIQUE,
    event_type TEXT, ts TEXT, src_ip TEXT, src_port INTEGER,
    protocol TEXT, session_id TEXT, username TEXT, password TEXT,
    command TEXT, url TEXT, dataset_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ds_ts ON events(dataset_id, ts);
CREATE TABLE IF NOT EXISTS enrichment (
    ip TEXT PRIMARY KEY, country TEXT, asn TEXT, abuse_confidence INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    rule_id TEXT, ts TEXT, src_ip TEXT, details_json TEXT, dataset_id TEXT
);
"""

FIELDS = ("event_type", "ts", "src_ip", "src_port", "protocol", "session_id",
          "username", "password", "command", "url", "dataset_id")


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open a fresh connection for this operation (thread-safe: one per call)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert_events(self, events: Iterable[Event]) -> int:
        count = 0
        with self._connect() as conn, conn:
            for e in events:
                values = [getattr(e, f) for f in FIELDS]
                dedup = hashlib.sha256(
                    "\x00".join("" if v is None else str(v) for v in values).encode()
                ).hexdigest()
                cur = conn.execute(
                    f"INSERT OR IGNORE INTO events ({', '.join(FIELDS)}, dedup_hash) "
                    f"VALUES ({', '.join('?' * len(FIELDS))}, ?)",
                    [*values, dedup],
                )
                count += cur.rowcount
        return count

    def all_events(self, dataset_id: str) -> Iterator[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, dedup_hash, " + ", ".join(FIELDS) +
                " FROM events WHERE dataset_id = ? ORDER BY ts, id", (dataset_id,)
            )
            for row in cur:
                yield dict(row)

    def all_events_enriched(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT e.event_type, e.ts, e.src_ip, e.src_port, e.protocol, "
                "e.session_id, e.username, e.password, e.command, e.url, "
                "e.dataset_id, n.country AS country "
                "FROM events e LEFT JOIN enrichment n ON n.ip = e.src_ip "
                "ORDER BY e.ts, e.id"
            )
            return [dict(r) for r in cur]

    def insert_enrichment(self, ip: str, country: str | None,
                          asn: str | None, abuse_confidence: int | None) -> None:
        with self._connect() as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO enrichment VALUES (?, ?, ?, ?)",
                (ip, country, asn, abuse_confidence),
            )

    def get_enrichment(self, ip: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT country, asn, abuse_confidence FROM enrichment WHERE ip = ?", (ip,)
            ).fetchone()
            return None if row is None else dict(row)

    def insert_alerts(self, alerts: Iterable[dict]) -> None:
        with self._connect() as conn, conn:
            conn.executemany(
                "INSERT INTO alerts (rule_id, ts, src_ip, details_json, dataset_id) "
                "VALUES (?, ?, ?, ?, ?)",
                [(a["rule_id"], a["ts"], a["src_ip"], a["details_json"], a["dataset_id"])
                 for a in alerts],
            )

    def clear_alerts(self, dataset_id: str) -> None:
        with self._connect() as conn, conn:
            conn.execute("DELETE FROM alerts WHERE dataset_id = ?", (dataset_id,))

    def get_alerts(self, dataset_id: str) -> list[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT rule_id, ts, src_ip, details_json, dataset_id "
                "FROM alerts WHERE dataset_id = ? ORDER BY ts, id", (dataset_id,)
            )
            return [dict(r) for r in cur]

    def get_alerts_all(self) -> list[dict]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT rule_id, ts, src_ip, details_json, dataset_id "
                "FROM alerts ORDER BY ts, id"
            )
            return [dict(r) for r in cur]

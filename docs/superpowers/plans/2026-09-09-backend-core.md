# HoneyGlobe Backend Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full ingest → normalize → enrich → detect → API pipeline for HoneyGlobe over real honeypot datasets, ending with a deterministic replay stream over WebSocket.

**Architecture:** A `SourceAdapter` protocol yields normalized events; a `DatasetSource` implementation parses real Cowrie-format JSON-lines. Events land in SQLite via a storage layer. An ingest pipeline runs GeoLite2 + AbuseIPDB enrichment and batch detection at ingest time (dataset-timestamp order). A FastAPI app exposes REST endpoints and a WS replay engine whose state derives only from `(dataset, cursor, speed)`.

**Tech Stack:** Python 3.12+, FastAPI, pytest, ruff, SQLite (stdlib `sqlite3`), httpx (AbuseIPDB client), maxminddb-geolite2 vendored databases. No other runtime deps.

**Spec:** `docs/superpowers/specs/2026-09-09-honey-globe-design.md` — read it before starting. The plan argues from the spec.

## Global Constraints

- Python 3.12+; runtime deps limited to: `fastapi`, `uvicorn`, `httpx`, `maxminddb-geolite2`. Dev deps: `pytest`, `ruff`. Nothing else without amending the spec.
- Event schema fields exactly as spec §Event schema: `event_type`, `ts`, `src_ip`, `src_port`, `protocol`, `session_id`, `username`, `password`, `command`, `url`, `dataset_id`. `event_type` ∈ {`session_open`, `login_attempt`, `login_success`, `command`, `download_attempt`, `session_close`}.
- Detections run **at ingest time, batch, in dataset-timestamp order** (spec §Detection engine).
- Replay determinism: state derives from `(dataset, cursor, speed)` only (spec §API).
- Attacker-controlled strings are never trusted — escape at render time is frontend's job, but the backend must never *execute or fetch* anything from the data (no URL fetching, no shell).
- `.env` for API keys, gitignored; `.env.example` committed (spec §Security hygiene).
- Dataset license/attribution recorded in `docs/data-sources.md` before any dataset is committed (spec §Dataset selection criteria).
- All commands below run from repo root `honey-globe/` on Windows (pwsh). Use `python -m pytest` (not bare `pytest`) to avoid PATH issues.
- Commits after every green test cycle; conventional-commit messages (`feat:`, `test:`, `docs:`, `chore:`).

---

### Task 0: Project scaffolding

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `.env.example`, `README.md`, `docs/data-sources.md`
- Create: `src/honeyglobe/__init__.py`, `src/honeyglobe/events.py`
- Test: `tests/test_events.py`

**Interfaces:**
- Produces: package `honeyglobe` importable as `from honeyglobe import events`; `events.Event` dataclass and `events.EVENT_TYPES` constant used by every later task.

- [ ] **Step 1: Write failing test for the Event schema**

Create `tests/test_events.py`:

```python
from honeyglobe.events import Event, EVENT_TYPES

def test_event_holds_all_schema_fields():
    e = Event(
        event_type="login_attempt", ts="2023-01-01T00:00:00Z",
        src_ip="1.2.3.4", src_port=51234, protocol="ssh",
        session_id="abc", username="root", password="123456",
        command=None, url=None, dataset_id="kaggle-ssh-2023",
    )
    assert e.event_type == "login_attempt"
    assert e.username == "root"

def test_event_types_constant():
    assert set(EVENT_TYPES) == {
        "session_open", "login_attempt", "login_success",
        "command", "download_attempt", "session_close",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_events.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'honeyglobe'`

- [ ] **Step 3: Scaffold project**

`pyproject.toml`:

```toml
[project]
name = "honeyglobe"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn>=0.30",
    "httpx>=0.27",
    "maxminddb-geolite2>=2018.1",
]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff>=0.5"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/honeyglobe"]

[tool.ruff]
line-length = 100
src = ["src", "tests"]
```

`.gitignore`:

```
.env
__pycache__/
*.pyc
.venv/
data/datasets/
data/honeyglobe.db
data/*.mmdb
dist/
node_modules/
```

Note: `data/datasets/` gitignored — raw datasets stay local (license + size); `docs/data-sources.md` (committed) tells others how to fetch them.

`.env.example`:

```
ABUSEIPDB_KEY=your-key-here
```

`src/honeyglobe/__init__.py`: empty file.

`src/honeyglobe/events.py`:

```python
from dataclasses import dataclass

EVENT_TYPES = frozenset(
    {"session_open", "login_attempt", "login_success",
     "command", "download_attempt", "session_close"}
)

@dataclass(slots=True)
class Event:
    event_type: str
    ts: str
    src_ip: str
    src_port: int | None
    protocol: str
    session_id: str | None
    username: str | None
    password: str | None
    command: str | None
    url: str | None
    dataset_id: str
```

`README.md`: project title, one-liner from spec, badges placeholder text "CI badge — added Plan 3".

`docs/data-sources.md`: skeleton with selection criteria table headers (License / Contains IPs+timestamps / Format / Event count / URL). Fill in Task 1.

- [ ] **Step 4: Install and run tests**

Run: `python -m pip install -e ".[dev]"` then `python -m pytest tests/test_events.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .gitignore .env.example README.md docs/data-sources.md src/ tests/
git commit -m "chore: project scaffold with Event schema"
```

---

### Task 1: Curate dataset + DatasetSource adapter

**Files:**
- Create: `src/honeyglobe/sources/__init__.py`, `src/honeyglobe/sources/base.py`, `src/honeyglobe/sources/dataset.py`
- Create: `data/datasets/.gitkeep`
- Modify: `docs/data-sources.md`
- Test: `tests/test_dataset_source.py`, `tests/fixtures/sample_cowrie.jsonl`

**Interfaces:**
- Produces: `sources.base.SourceAdapter` protocol with single method `events() -> Iterator[Event]`; `sources.dataset.DatasetSource(dataset_id, path)` parses Cowrie JSON-lines. Used by Task 3 (ingest).
- Consumes: `events.Event` from Task 0.

Dataset choice (decided per spec §Dataset selection criteria): **Kaggle "SSH Honeypot Session Logs" style Cowrie captures; primary source: the `cowrie` JSON logs published as JSON-lines with `eventid` fields (`cowrie.login.failed`, `cowrie.session.connect`, `cowrie.command.input`, `cowrie.session.file_download`, `cowrie.session.closed`).** Before implementing, the executor must download one real dataset and record it in `docs/data-sources.md` (Step 1). If a listed candidate is unavailable, fall back per criteria: license permitting, has IPs + timestamps, ≥10k events, JSONL. If volume dataset lacks commands, note it — session replay view (frontend) will use whatever sessions exist.

- [ ] **Step 1: Fetch dataset and record provenance**

Download a Cowrie JSON-lines dataset to `data/datasets/`. Actionable candidates (try in order):
1. Kaggle datasets matching "cowrie" (e.g. "SSH Honeypot Log" captures) — check license field on the dataset page allows educational/portfolio use; record exact URL, license, event count.
2. GitHub repos publishing raw `cowrie.json` logs (search "cowrie.json dataset") — verify license file or explicit permission.
3. Stratosphere Labs honeypot captures (research group; CC-BY-NC style) — check compatibility with a public portfolio repo; record terms verbatim.

Count events: `Get-Content data/datasets/<file> | Measure-Object -Line` (pwsh). Record in `docs/data-sources.md`: dataset id, URL, license text/quote, event count, format, date range. Commit `docs/data-sources.md` **before** writing any parsing code (spec constraint).

```bash
git add docs/data-sources.md data/datasets/.gitkeep
git commit -m "docs: record dataset provenance and license"
```

- [ ] **Step 2: Write failing test with a fixture in real Cowrie format**

`tests/fixtures/sample_cowrie.jsonl` (hand-built from the real format; real lines are longer, these are minimal but shape-exact):

```jsonl
{"eventid": "cowrie.session.connect", "timestamp": "2023-06-12T14:00:01.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "protocol": ["ssh"] }
{"eventid": "cowrie.login.failed", "timestamp": "2023-06-12T14:00:03.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "username": "root", "password": "123456"}
{"eventid": "cowrie.login.failed", "timestamp": "2023-06-12T14:00:04.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "username": "admin", "password": "admin"}
{"eventid": "cowrie.login.success", "timestamp": "2023-06-12T14:00:05.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "username": "root", "password": "123456"}
{"eventid": "cowrie.command.input", "timestamp": "2023-06-12T14:00:10.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "input": "cat /etc/passwd"}
{"eventid": "cowrie.session.file_download", "timestamp": "2023-06-12T14:00:20.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "url": "http://example.invalid/x.sh"}
{"eventid": "cowrie.session.closed", "timestamp": "2023-06-12T14:00:25.000Z", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11"}
{"eventid": "cowrie.login.failed", "timestamp": "NOT-A-DATE", "src_ip": "203.0.113.5", "src_port": 51234, "session": "aa11", "username": "root", "password": "x"}
{"this line is": "not cowrie json"}
```

`tests/test_dataset_source.py`:

```python
from pathlib import Path

from honeyglobe.sources.dataset import DatasetSource

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cowrie.jsonl"


def _events():
    return list(DatasetSource(dataset_id="fixture", path=FIXTURE).events())


def test_yields_events_in_schema_order():
    events = _events()
    assert [e.event_type for e in events] == [
        "session_open", "login_attempt", "login_attempt", "login_success",
        "command", "download_attempt", "session_close",
    ]
    first = events[0]
    assert first.dataset_id == "fixture"
    assert first.src_ip == "203.0.113.5"
    assert first.ts == "2023-06-12T14:00:01.000Z"


def test_maps_cowrie_fields():
    events = _events()
    cmd = events[4]
    assert cmd.command == "cat /etc/passwd"
    assert cmd.username is None
    dl = events[5]
    assert dl.url == "http://example.invalid/x.sh"
    login = events[1]
    assert login.username == "root" and login.password == "123456"


def test_protocol_defaults_to_ssh():
    assert all(e.protocol == "ssh" for e in _events())


def test_malformed_lines_are_skipped_never_crash():
    events = _events()
    # 9 lines, 2 malformed (bad date skipped, garbage line skipped) -> 7 events
    assert len(events) == 7
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/test_dataset_source.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'honeyglobe.sources'`

- [ ] **Step 4: Implement SourceAdapter protocol and DatasetSource**

`src/honeyglobe/sources/__init__.py`: empty.

`src/honeyglobe/sources/base.py`:

```python
from collections.abc import Iterator
from typing import Protocol

from honeyglobe.events import Event


class SourceAdapter(Protocol):
    """Any event source: dataset replay or (future) live honeypot."""

    def events(self) -> Iterator[Event]: ...
```

`src/honeyglobe/sources/dataset.py`:

```python
import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from honeyglobe.events import Event

COWRIE_MAP = {
    "cowrie.session.connect": "session_open",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download_attempt",
    "cowrie.session.closed": "session_close",
}


class DatasetSource:
    """Replays a Cowrie JSON-lines file as normalized Events."""

    def __init__(self, dataset_id: str, path: Path) -> None:
        self.dataset_id = dataset_id
        self.path = Path(path)

    def events(self) -> Iterator[Event]:
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line)
                if event is not None:
                    yield event

    def _parse_line(self, line: str) -> Event | None:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return None
        mapped = COWRIE_MAP.get(raw.get("eventid", ""))
        if mapped is None:
            return None
        ts = self._valid_ts(raw.get("timestamp"))
        src_ip = raw.get("src_ip")
        if ts is None or not src_ip:
            return None
        return Event(
            event_type=mapped,
            ts=ts or "",
            src_ip=src_ip or "",
            src_port=raw.get("src_port"),
            protocol="ssh",
            session_id=raw.get("session"),
            username=raw.get("username"),
            password=raw.get("password"),
            command=raw.get("input"),
            url=raw.get("url"),
            dataset_id=self.dataset_id,
        )

    @staticmethod
    def _valid_ts(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return value
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_dataset_source.py tests/test_events.py -v`
Expected: all PASS

- [ ] **Step 6: Validate against the real dataset (sanity, not a test)**

Run: `python -c "from pathlib import Path; from honeyglobe.sources.dataset import DatasetSource; es=list(DatasetSource('real', Path('data/datasets/<your-file>')).events()); print(len(es)); print(es[0])"`
Expected: prints a five-figure event count and one Event. If count is tiny, the format differs from assumed Cowrie — inspect raw lines (`Get-Content data/datasets/<file> -TotalCount 5`) and adjust `COWRIE_MAP`/fields, then re-run tests.

- [ ] **Step 7: Commit**

```bash
git add src/honeyglobe/sources/ tests/test_dataset_source.py tests/fixtures/
git commit -m "feat: DatasetSource adapter parsing Cowrie JSONL with malformed-line tolerance"
```

---

### Task 2: SQLite storage layer

**Files:**
- Create: `src/honeyglobe/storage.py`
- Test: `tests/test_storage.py`

**Interfaces:**
- Consumes: `events.Event` (Task 0).
- Produces: `Storage(db_path: Path)` with methods used by later tasks:
  - `insert_events(events: Iterable[Event]) -> int` (returns count inserted, dedupes on hash)
  - `all_events(dataset_id: str) -> Iterator[dict]` (timestamp order; dicts with all schema fields)
  - `insert_enrichment(ip: str, country: str | None, asn: str | None, abuse_confidence: int | None) -> None`
  - `get_enrichment(ip: str) -> dict | None` (returns `{"country", "asn", "abuse_confidence"}` or None)
  - `insert_alerts(alerts: Iterable[dict]) -> None` (dicts: `rule_id, ts, src_ip, details_json, dataset_id`)
  - `clear_alerts(dataset_id: str) -> None` (makes re-ingest idempotent for alerts)
  - `get_alerts(dataset_id: str) -> list[dict]`

- [ ] **Step 1: Write failing tests**

`tests/test_storage.py`:

```python
from pathlib import Path

import pytest

from honeyglobe.events import Event
from honeyglobe.storage import Storage


def _event(**overrides):
    base = dict(
        event_type="login_attempt", ts="2023-06-12T14:00:03.000Z",
        src_ip="203.0.113.5", src_port=51234, protocol="ssh",
        session_id="aa11", username="root", password="123456",
        command=None, url=None, dataset_id="ds1",
    )
    base.update(overrides)
    return Event(**base)


@pytest.fixture()
def storage(tmp_path: Path):
    return Storage(db_path=tmp_path / "test.db")


def test_insert_and_read_back(storage):
    n = storage.insert_events([_event(), _event(src_ip="198.51.100.7", ts="2023-06-12T13:00:00.000Z")])
    assert n == 2
    rows = list(storage.all_events("ds1"))
    assert len(rows) == 2
    assert rows[0]["src_ip"] == "198.51.100.7"  # timestamp order
    assert rows[1]["username"] == "root"


def test_duplicate_insert_is_deduped(storage):
    e = _event()
    assert storage.insert_events([e]) == 1
    assert storage.insert_events([e]) == 0
    assert len(list(storage.all_events("ds1"))) == 1


def test_enrichment_roundtrip(storage):
    storage.insert_enrichment("203.0.113.5", country="AU", asn="AS64496", abuse_confidence=100)
    got = storage.get_enrichment("203.0.113.5")
    assert got == {"country": "AU", "asn": "AS64496", "abuse_confidence": 100}


def test_enrichment_missing_ip(storage):
    assert storage.get_enrichment("10.0.0.1") is None


def test_alert_roundtrip(storage):
    storage.insert_alerts([
        {"rule_id": "CRED_BURST", "ts": "2023-06-12T14:00:03.000Z", "src_ip": "203.0.113.5",
         "details_json": '{"attempts": 10}', "dataset_id": "ds1"},
    ])
    alerts = storage.get_alerts("ds1")
    assert alerts[0]["rule_id"] == "CRED_BURST"
    assert '"attempts": 10' in alerts[0]["details_json"]


def test_clear_alerts_scoped_to_dataset(storage):
    storage.insert_alerts([
        {"rule_id": "R", "ts": "2023-06-12T14:00:03.000Z", "src_ip": "1.1.1.1",
         "details_json": "{}", "dataset_id": "ds1"},
        {"rule_id": "R", "ts": "2023-06-12T15:00:03.000Z", "src_ip": "1.1.1.1",
         "details_json": "{}", "dataset_id": "ds2"},
    ])
    storage.clear_alerts("ds1")
    assert storage.get_alerts("ds1") == []
    assert len(storage.get_alerts("ds2")) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_storage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'honeyglobe.storage'`

- [ ] **Step 3: Implement Storage**

`src/honeyglobe/storage.py`:

```python
import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
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
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def insert_events(self, events: Iterable[Event]) -> int:
        count = 0
        with self.conn:
            for e in events:
                values = [getattr(e, f) for f in FIELDS]
                dedup = hashlib.sha256(
                    "\x00".join("" if v is None else str(v) for v in values).encode()
                ).hexdigest()
                cur = self.conn.execute(
                    f"INSERT OR IGNORE INTO events ({', '.join(FIELDS)}, dedup_hash) "
                    f"VALUES ({', '.join('?' * len(FIELDS))}, ?)",
                    [*values, dedup],
                )
                count += cur.rowcount
        return count

    def all_events(self, dataset_id: str) -> Iterator[dict]:
        cur = self.conn.execute(
            "SELECT id, dedup_hash, " + ", ".join(FIELDS) +
            " FROM events WHERE dataset_id = ? ORDER BY ts, id", (dataset_id,)
        )
        for row in cur:
            yield dict(row)

    def insert_enrichment(self, ip: str, country: str | None,
                          asn: str | None, abuse_confidence: int | None) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO enrichment VALUES (?, ?, ?, ?)",
                (ip, country, asn, abuse_confidence),
            )

    def get_enrichment(self, ip: str) -> dict | None:
        row = self.conn.execute(
            "SELECT country, asn, abuse_confidence FROM enrichment WHERE ip = ?", (ip,)
        ).fetchone()
        return None if row is None else dict(row)

    def insert_alerts(self, alerts: Iterable[dict]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO alerts (rule_id, ts, src_ip, details_json, dataset_id) "
                "VALUES (?, ?, ?, ?, ?)",
                [(a["rule_id"], a["ts"], a["src_ip"], a["details_json"], a["dataset_id"])
                 for a in alerts],
            )

    def clear_alerts(self, dataset_id: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM alerts WHERE dataset_id = ?", (dataset_id,))

    def get_alerts(self, dataset_id: str) -> list[dict]:
        cur = self.conn.execute(
            "SELECT rule_id, ts, src_ip, details_json, dataset_id "
            "FROM alerts WHERE dataset_id = ? ORDER BY ts, id", (dataset_id,)
        )
        return [dict(r) for r in cur]
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_storage.py -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/honeyglobe/storage.py tests/test_storage.py
git commit -m "feat: SQLite storage with event dedup, enrichment and alert tables"
```

---

### Task 3: Detection engine

**Files:**
- Create: `src/honeyglobe/detect/__init__.py`, `src/honeyglobe/detect/engine.py`, `src/honeyglobe/detect/rules.py`
- Test: `tests/test_rules.py`, `tests/test_engine.py`

**Interfaces:**
- Consumes: event dicts as produced by `Storage.all_events` (Task 2) — dicts with schema fields.
- Produces:
  - `rules.Rule` dataclass: `rule_id: str`, `evaluate: Callable[[list[dict]], list[dict]]` returning alert dicts `{rule_id, ts, src_ip, details_json, dataset_id}`.
  - Rule singletons exported by name: `CRED_BURST, FIRST_COUNTRY, PERSISTENT_IP, POPULAR_CRED, DOWNLOAD_ATTEMPT`, plus `RULES: dict[str, Rule]`.
  - `engine.run_all(events: list[dict]) -> list[dict]` — runs every rule, returns concatenated alerts in ts order. Used by Task 4 (ingest) and tests; determinism comes free (pure functions over the full event list).

Rules implement spec §Detection engine: `CRED_BURST` ≥10 login attempts / 10 min per IP; `FIRST_COUNTRY` informational.

**Design decision — enrichment access for FIRST_COUNTRY:** rules stay pure (no DB/network access). `FIRST_COUNTRY.evaluate` reads an optional `country` key that Task 4's ingest pipeline annotates onto each event dict after enrichment lookup. Missing key ⇒ rule yields nothing.

- [ ] **Step 1: Write failing tests for rules**

`tests/test_rules.py`:

```python
from honeyglobe.detect.rules import CRED_BURST, FIRST_COUNTRY, PERSISTENT_IP, POPULAR_CRED, DOWNLOAD_ATTEMPT

def _ev(ts, ip="1.2.3.4", et="login_attempt", user="root", pw="x", session="s1", **extra):
    e = dict(event_type=et, ts=ts, src_ip=ip, src_port=1, protocol="ssh",
             session_id=session, username=user, password=pw, command=None,
             url=None, dataset_id="ds1")
    e.update(extra)
    return e


def test_cred_burst_fires_at_threshold():
    events = [_ev("2023-06-12T14:00:00Z", user=f"u{i}") for i in range(10)]
    events = [dict(e, ts=f"2023-06-12T14:{i:02d}:00Z") for i, e in enumerate(events)]
    alerts = CRED_BURST.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "CRED_BURST"
    assert '"attempts": 10' in alerts[0]["details_json"]


def test_cred_burst_quiet_below_threshold():
    events = [dict(_ev("2023-06-12T14:00:00Z"), ts=f"2023-06-12T14:0{i}:00Z") for i in range(9)]
    assert CRED_BURST.evaluate(events) == []


def test_cred_burst_window_respected():
    # 10 attempts but spread over 25 minutes -> no single 10-min window has 10
    events = [dict(_ev("2023-06-12T14:00:00Z"), ts=f"2023-06-12T1{4 + i // 2}:{i % 2 * 30:02d}:00Z")
              for i in range(10)]
    assert CRED_BURST.evaluate(events) == []


def test_first_country_fires_once():
    events = [
        _ev("2023-06-12T14:00:00Z", ip="1.1.1.1", country="AU"),
        _ev("2023-06-12T15:00:00Z", ip="2.2.2.2", country="CN"),
        _ev("2023-06-12T16:00:00Z", ip="3.3.3.3", country="AU"),  # AU already seen
    ]
    alerts = FIRST_COUNTRY.evaluate(events)
    assert [a["rule_id"] for a in alerts] == ["FIRST_COUNTRY"] * 2


def test_first_country_ignores_missing_country():
    events = [_ev("2023-06-12T14:00:00Z")]  # no country key
    assert FIRST_COUNTRY.evaluate(events) == []


def test_persistent_ip_fires_on_third_day():
    events = [
        _ev("2023-06-10T01:00:00Z", ip="9.9.9.9"),
        _ev("2023-06-11T01:00:00Z", ip="9.9.9.9"),
        _ev("2023-06-12T01:00:00Z", ip="9.9.9.9"),
    ]
    alerts = PERSISTENT_IP.evaluate(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PERSISTENT_IP"
    assert '"days": 3' in alerts[0]["details_json"]


def test_persistent_ip_quiet_on_two_days():
    events = [_ev("2023-06-10T01:00:00Z", ip="9.9.9.9"), _ev("2023-06-11T01:00:00Z", ip="9.9.9.9")]
    assert PERSISTENT_IP.evaluate(events) == []


def test_popular_cred_fires_on_share():
    # 100 attempts, 60 for "root" -> 60% >= 5%
    events = [dict(_ev("2023-06-12T14:00:00Z", ip=f"10.0.0.{i}", user="root", pw="r"))
              for i in range(60)]
    events += [dict(_ev("2023-06-12T14:00:00Z", ip=f"10.0.1.{i}", user=f"u{i}", pw="x"))
               for i in range(40)]
    alerts = POPULAR_CRED.evaluate(events)
    assert [a["rule_id"] for a in alerts] == ["POPULAR_CRED"]
    assert '"username": "root"' in alerts[0]["details_json"]


def test_download_attempt_alerts_each_download():
    events = [
        _ev("2023-06-12T14:00:00Z", et="download_attempt", ip="5.5.5.5",
            url="http://example.invalid/a"),
        _ev("2023-06-12T14:01:00Z", et="login_attempt", ip="5.5.5.5"),
    ]
    alerts = DOWNLOAD_ATTEMPT.evaluate(events)
    assert len(alerts) == 1
    assert '"url": "http://example.invalid/a"' in alerts[0]["details_json"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_rules.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'honeyglobe.detect'`

- [ ] **Step 3: Implement rules**

`src/honeyglobe/detect/__init__.py`: empty.

`src/honeyglobe/detect/rules.py`:

```python
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=10)
CRED_BURST_THRESHOLD = 10
PERSISTENT_DAYS = 3
POPULAR_SHARE = 0.05


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _alert(rule_id: str, ts: str, src_ip: str, details: dict, dataset_id: str) -> dict:
    return {
        "rule_id": rule_id, "ts": ts, "src_ip": src_ip,
        "details_json": json.dumps(details, sort_keys=True),
        "dataset_id": dataset_id,
    }


@dataclass(slots=True)
class Rule:
    rule_id: str
    evaluate: object  # callable(list[dict]) -> list[dict]


def _cred_burst(events: list[dict]) -> list[dict]:
    by_ip: dict[str, list[dict]] = {}
    for e in events:
        if e["event_type"] == "login_attempt":
            by_ip.setdefault(e["src_ip"], []).append(e)
    alerts = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda e: _ts(e["ts"]))
        i = 0
        while i < len(attempts):
            j = i
            while j < len(attempts) and _ts(attempts[j]["ts"]) <= _ts(attempts[i]["ts"]) + WINDOW:
                j += 1
            if j - i >= CRED_BURST_THRESHOLD:
                alerts.append(_alert(
                    "CRED_BURST", attempts[i]["ts"], ip,
                    {"attempts": j - i, "window_minutes": 10}, attempts[i]["dataset_id"],
                ))
                i = j
            else:
                i += 1
    return alerts


def _first_country(events: list[dict]) -> list[dict]:
    seen: set[str] = set()
    alerts = []
    for e in events:
        country = e.get("country")
        if country is None or country in seen:
            continue
        seen.add(country)
        alerts.append(_alert(
            "FIRST_COUNTRY", e["ts"], e["src_ip"],
            {"country": country}, e["dataset_id"],
        ))
    return alerts


def _persistent_ip(events: list[dict]) -> list[dict]:
    days: dict[str, set[str]] = {}
    for e in events:
        days.setdefault(e["src_ip"], set()).add(e["ts"][:10])
    alerts = []
    for ip, day_set in days.items():
        if len(day_set) >= PERSISTENT_DAYS:
            first = next(e for e in events if e["src_ip"] == ip)
            alerts.append(_alert(
                "PERSISTENT_IP", first["ts"], ip,
                {"days": len(day_set)}, first["dataset_id"],
            ))
    return alerts


def _popular_cred(events: list[dict]) -> list[dict]:
    attempts = [e for e in events if e["event_type"] == "login_attempt"]
    if not attempts:
        return []
    counter = Counter(e["username"] for e in attempts)
    total = len(attempts)
    alerts = []
    for username, count in counter.most_common():
        if count / total < POPULAR_SHARE:
            continue
        first = next(e for e in attempts if e["username"] == username)
        alerts.append(_alert(
            "POPULAR_CRED", first["ts"], first["src_ip"],
            {"username": username, "share": round(count / total, 3), "count": count},
            first["dataset_id"],
        ))
    return alerts


def _download_attempt(events: list[dict]) -> list[dict]:
    return [
        _alert("DOWNLOAD_ATTEMPT", e["ts"], e["src_ip"], {"url": e["url"]}, e["dataset_id"])
        for e in events if e["event_type"] == "download_attempt" and e.get("url")
    ]


CRED_BURST = Rule("CRED_BURST", _cred_burst)
FIRST_COUNTRY = Rule("FIRST_COUNTRY", _first_country)
PERSISTENT_IP = Rule("PERSISTENT_IP", _persistent_ip)
POPULAR_CRED = Rule("POPULAR_CRED", _popular_cred)
DOWNLOAD_ATTEMPT = Rule("DOWNLOAD_ATTEMPT", _download_attempt)

RULES = {r.rule_id: r for r in (CRED_BURST, FIRST_COUNTRY, PERSISTENT_IP, POPULAR_CRED, DOWNLOAD_ATTEMPT)}
```

- [ ] **Step 4: Run rule tests**

Run: `python -m pytest tests/test_rules.py -v`
Expected: all PASS

- [ ] **Step 5: Write failing test for engine**

`tests/test_engine.py`:

```python
from honeyglobe.detect.engine import run_all


def test_run_all_concatenates_and_sorts_by_ts():
    events = [
        dict(event_type="download_attempt", ts="2023-06-12T16:00:00Z", src_ip="5.5.5.5",
             src_port=1, protocol="ssh", session_id="s", username=None, password=None,
             command=None, url="http://x.invalid/a", dataset_id="ds1"),
        dict(event_type="login_attempt", ts="2023-06-12T14:00:00Z", src_ip="1.2.3.4",
             src_port=1, protocol="ssh", session_id="s", username="root", password="x",
             command=None, url=None, dataset_id="ds1"),
    ]
    # give the first event 9 more attempts to trigger CRED_BURST too
    events += [
        dict(event_type="login_attempt", ts=f"2023-06-12T14:0{i}:00Z", src_ip="1.2.3.4",
             src_port=1, protocol="ssh", session_id="s", username="root", password="x",
             command=None, url=None, dataset_id="ds1")
        for i in range(1, 10)
    ]
    alerts = run_all(events)
    ids = [a["rule_id"] for a in alerts]
    assert "CRED_BURST" in ids and "DOWNLOAD_ATTEMPT" in ids
    assert alerts == sorted(alerts, key=lambda a: a["ts"])


def test_run_all_deterministic():
    events = [
        dict(event_type="login_attempt", ts="2023-06-12T14:00:00Z", src_ip="1.2.3.4",
             src_port=1, protocol="ssh", session_id="s", username="root", password="x",
             command=None, url=None, dataset_id="ds1"),
    ]
    assert run_all(events) == run_all(events)
```

- [ ] **Step 6: Run to verify it fails, then implement engine**

Run: `python -m pytest tests/test_engine.py -v` — FAIL (no module).

`src/honeyglobe/detect/engine.py`:

```python
from honeyglobe.detect.rules import RULES


def run_all(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda e: (e["ts"], e.get("src_ip", "")))
    alerts = []
    for rule in RULES.values():
        alerts.extend(rule.evaluate(ordered))
    alerts.sort(key=lambda a: a["ts"])
    return alerts
```

- [ ] **Step 7: Run all detect tests**

Run: `python -m pytest tests/test_rules.py tests/test_engine.py -v`
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add src/honeyglobe/detect/ tests/test_rules.py tests/test_engine.py
git commit -m "feat: detection engine with 5 tested rules over event dicts"
```

---

### Task 4: Enrichment + ingest pipeline

**Files:**
- Create: `src/honeyglobe/enrich.py`, `src/honeyglobe/ingest.py`
- Test: `tests/test_enrich.py`, `tests/test_ingest.py`

**Interfaces:**
- Consumes: `DatasetSource` (Task 1), `Storage` (Task 2), `detect.engine.run_all` (Task 3).
- Produces:
  - `enrich.Enricher(storage)` with `enrich_ips(ips: list[str]) -> dict[str, dict]` — GeoLite2 (local mmdb via `maxminddb-geolite2`) + AbuseIPDB (httpx, key from env, cache in storage, rate-limit friendly: batch 1 req per unique uncached IP, skip silently if no key/DB/errors). Returns `{ip: {"country", "asn", "abuse_confidence"}}`.
  - `ingest.run(source: SourceAdapter, storage: Storage, enricher: Enricher, dataset_id: str) -> dict` — full pipeline: insert events → collect unique IPs → enrich → annotate events with `country` → run detections → store alerts → return summary `{"events": n, "alerts": m, "ips": k}`. CLI entry `python -m honeyglobe.ingest <dataset_id> <path>` prints summary and writes `data/honeyglobe.db`.

- [ ] **Step 1: Write failing enrichment test (offline — no network)**

`tests/test_enrich.py`:

```python
from pathlib import Path

from honeyglobe.enrich import Enricher
from honeyglobe.storage import Storage


class FakeGeoDB:
    def get(self, ip):
        if ip == "203.0.113.5":
            return {"country": {"iso_code": "AU"}, "autonomous_system": {"number": 64496, "organization": "Example"}}
        return None


def test_enrich_ips_offline(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    result = enricher.enrich_ips(["203.0.113.5", "10.0.0.1"])
    assert result["203.0.113.5"]["country"] == "AU"
    assert result["203.0.113.5"]["asn"] == "AS64496"
    assert result["10.0.0.1"]["country"] is None


def test_enrichment_cached_in_storage(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    storage.insert_enrichment("203.0.113.5", "AU", "AS64496", 88)
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    calls = []
    orig = enricher.enrich_ips

    def counting(ips):
        calls.extend(ips)
        return orig(ips)

    enricher.enrich_ips = counting  # type: ignore[method-assign]
    result = enricher.enrich_ips(["203.0.113.5"])
    assert "203.0.113.5" not in calls  # served from cache
    assert result["203.0.113.5"]["abuse_confidence"] == 88
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_enrich.py -v`
Expected: FAIL — no module `honeyglobe.enrich`.

- [ ] **Step 3: Implement Enricher**

`src/honeyglobe/enrich.py`:

```python
import os

import httpx


class Enricher:
    def __init__(self, storage, geo_db=None, abuse_client=None) -> None:
        self.storage = storage
        self.geo_db = geo_db  # maxminddb reader-like or None
        self.abuse_client = abuse_client  # httpx.Client with auth header or None

    def enrich_ips(self, ips: list[str]) -> dict[str, dict]:
        result: dict[str, dict] = {}
        uncached: list[str] = []
        for ip in set(ips):
            cached = self.storage.get_enrichment(ip)
            if cached is not None:
                result[ip] = cached
            else:
                uncached.append(ip)
        for ip in uncached:
            country, asn = self._geo(ip)
            abuse = self._abuse(ip)
            record = {"country": country, "asn": asn, "abuse_confidence": abuse}
            self.storage.insert_enrichment(ip, **record)
            result[ip] = record
        return result

    def _geo(self, ip: str) -> tuple[str | None, str | None]:
        if self.geo_db is None:
            return None, None
        try:
            match = self.geo_db.get(ip)
        except Exception:
            return None, None
        if not match:
            return None, None
        country = match.get("country", {}).get("iso_code")
        asn_obj = match.get("autonomous_system", {})
        asn = f"AS{asn_obj['number']}" if "number" in asn_obj else None
        return country, asn

    def _abuse(self, ip: str) -> int | None:
        if self.abuse_client is None:
            return None
        try:
            resp = self.abuse_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 30},
            )
            data = resp.json()["data"]["abuseConfidenceScore"]
            return int(data)
        except Exception:
            return None


def make_abuse_client() -> httpx.Client | None:
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    return httpx.Client(
        headers={"Key": key, "Accept": "application/json"}, timeout=10.0
    )
```

- [ ] **Step 4: Run enrichment tests**

Run: `python -m pytest tests/test_enrich.py -v`
Expected: PASS

- [ ] **Step 5: Write failing ingest test**

`tests/test_ingest.py`:

```python
from pathlib import Path

from honeyglobe.enrich import Enricher
from honeyglobe.ingest import run
from honeyglobe.sources.dataset import DatasetSource
from honeyglobe.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cowrie.jsonl"


class FakeGeoDB:
    def get(self, ip):
        return {"country": {"iso_code": "ZZ"}, "autonomous_system": {"number": 64500}}


def test_ingest_full_pipeline(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    source = DatasetSource(dataset_id="fixture", path=FIXTURE)
    summary = run(source, storage, enricher, dataset_id="fixture")
    # 7 valid events in fixture (2 malformed lines skipped)
    assert summary["events"] == 7
    assert summary["ips"] == 1
    assert summary["alerts"] >= 1  # DOWNLOAD_ATTEMPT fires on fixture download
    alerts = storage.get_alerts("fixture")
    assert any(a["rule_id"] == "DOWNLOAD_ATTEMPT" for a in alerts)
    # events retrievable in ts order with country annotation available via enrichment
    events = list(storage.all_events("fixture"))
    assert events[0]["event_type"] == "session_open"


def test_ingest_is_idempotent(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    source = DatasetSource(dataset_id="fixture", path=FIXTURE)
    first = run(source, storage, enricher, dataset_id="fixture")
    second = run(source, storage, enricher, dataset_id="fixture")
    assert second["events"] == 0  # dedup
    assert len(list(storage.all_events("fixture"))) == first["events"]
    assert len(storage.get_alerts("fixture")) == first["alerts"]  # no alert duplication
```

- [ ] **Step 6: Run to verify it fails, then implement ingest**

Run: `python -m pytest tests/test_ingest.py -v` — FAIL.

`src/honeyglobe/ingest.py`:

```python
import sys
from pathlib import Path

from honeyglobe.detect.engine import run_all
from honeyglobe.enrich import Enricher, make_abuse_client
from honeyglobe.sources.base import SourceAdapter
from honeyglobe.storage import Storage

try:
    from geolite2 import geolite2  # maxminddb-geolite2
    _GEO = geolite2.reader()
except Exception:
    _GEO = None


def run(source: SourceAdapter, storage: Storage, enricher: Enricher, dataset_id: str) -> dict:
    events = list(source.events())
    inserted = storage.insert_events(events)
    ip_set = sorted({e.src_ip for e in events if e.src_ip})
    enricher.enrich_ips(ip_set)
    enriched = {ip: (storage.get_enrichment(ip) or {}) for ip in ip_set}
    stored = list(storage.all_events(dataset_id))
    for e in stored:
        e["country"] = enriched.get(e["src_ip"], {}).get("country")
    storage.clear_alerts(dataset_id)  # re-ingest must not duplicate alerts
    alerts = run_all(stored)
    storage.insert_alerts(alerts)
    return {"events": inserted, "alerts": len(alerts), "ips": len(ip_set)}


def main() -> None:
    dataset_id, path = sys.argv[1], sys.argv[2]
    storage = Storage(Path("data/honeyglobe.db"))
    enricher = Enricher(storage, geo_db=_GEO, abuse_client=make_abuse_client())
    source = DatasetSource(dataset_id=dataset_id, path=Path(path))
    print(run(source, storage, enricher, dataset_id))


if __name__ == "__main__":
    main()
```

- [ ] **Step 7: Run all tests**

Run: `python -m pytest -v`
Expected: everything PASS (events, dataset_source, storage, rules, engine, enrich, ingest).

- [ ] **Step 8: Run ingestion on the real dataset**

Run: `python -m honeyglobe.ingest <dataset_id_from_docs> data/datasets/<file>`
Expected: prints `{'events': <5-figure>, 'alerts': <positive>, 'ips': <3-4 figure>}`.

- [ ] **Step 9: Commit**

```bash
git add src/honeyglobe/enrich.py src/honeyglobe/ingest.py tests/test_enrich.py tests/test_ingest.py
git commit -m "feat: ingest pipeline with enrichment and batch detection at ingest time"
```

---

### Task 5: FastAPI REST API

**Files:**
- Create: `src/honeyglobe/api.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `Storage` (Task 2).
- Produces: FastAPI app `api.app` with routes (spec §API):
  - `GET /api/stats/summary` → `{"total_events", "total_alerts", "unique_ips", "top_countries" (list of `[country, count]`), "top_usernames", "top_passwords", "timeline" (list of `{"hour": "ISO", "count": n}`)}`
  - `GET /api/events?from=&to=&page=&page_size=` → `{"items": [...], "total": n}` (ts-ordered)
  - `GET /api/sessions/{session_id}` → `{"session_id", "events": [...]}` (ts-ordered)
  - `GET /api/alerts` → `[...]`
  - `GET /api/health` → `{"status": "ok"}` (used by CI smoke test)
- App constructed with a `create_app(db_path: Path) -> FastAPI` factory so tests use `tmp_path` DBs.

- [ ] **Step 1: Write failing API tests**

`tests/test_api.py`:

```python
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from honeyglobe.api import create_app
from honeyglobe.events import Event
from honeyglobe.storage import Storage


@pytest.fixture()
def client(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    storage.insert_events([
        Event("session_open", "2023-06-12T14:00:01Z", "203.0.113.5", 51234, "ssh",
              "aa11", None, None, None, None, "ds1"),
        Event("login_attempt", "2023-06-12T14:00:03Z", "203.0.113.5", 51234, "ssh",
              "aa11", "root", "123456", None, None, "ds1"),
        Event("login_attempt", "2023-06-12T15:00:03Z", "198.51.100.7", 40000, "ssh",
              "bb22", "admin", "password", None, None, "ds1"),
    ])
    storage.insert_enrichment("203.0.113.5", "AU", "AS64496", 100)
    storage.insert_enrichment("198.51.100.7", "CN", "AS64500", 40)
    storage.insert_alerts([
        {"rule_id": "CRED_BURST", "ts": "2023-06-12T14:00:03Z", "src_ip": "203.0.113.5",
         "details_json": '{"attempts": 10}', "dataset_id": "ds1"},
    ])
    app = create_app(tmp_path / "t.db")
    return TestClient(app)


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_summary(client):
    body = client.get("/api/stats/summary").json()
    assert body["total_events"] == 3
    assert body["total_alerts"] == 1
    assert body["unique_ips"] == 2
    assert body["top_countries"] == [["AU", 2], ["CN", 1]]
    assert body["top_usernames"][0] == ["root", 1]


def test_events_pagination_and_range(client):
    body = client.get("/api/events", params={"page": 1, "page_size": 2}).json()
    assert body["total"] == 3 and len(body["items"]) == 2
    assert body["items"][0]["ts"] == "2023-06-12T14:00:01Z"
    ranged = client.get("/api/events", params={"from": "2023-06-12T15:00:00Z",
                                               "to": "2023-06-12T16:00:00Z"}).json()
    assert ranged["total"] == 1
    assert ranged["items"][0]["src_ip"] == "198.51.100.7"


def test_sessions(client):
    body = client.get("/api/sessions/aa11").json()
    assert body["session_id"] == "aa11"
    assert [e["event_type"] for e in body["events"]] == ["session_open", "login_attempt"]


def test_alerts(client):
    alerts = client.get("/api/alerts").json()
    assert alerts[0]["rule_id"] == "CRED_BURST"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_api.py -v`
Expected: FAIL — no module `honeyglobe.api`.

- [ ] **Step 3: Implement the API**

`src/honeyglobe/api.py`:

```python
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query

from honeyglobe.storage import Storage


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="HoneyGlobe API")
    storage = Storage(db_path)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/stats/summary")
    def summary() -> dict:
        events = _all_events_flat(storage)
        countries = Counter(e["country"] for e in events if e.get("country"))
        usernames = Counter(e["username"] for e in events
                             if e["event_type"] == "login_attempt" and e["username"])
        passwords = Counter(e["password"] for e in events
                            if e["event_type"] == "login_attempt" and e["password"])
        hours = Counter(e["ts"][:13] for e in events)
        return {
            "total_events": len(events),
            "total_alerts": len(storage.get_alerts_all()),
            "unique_ips": len({e["src_ip"] for e in events}),
            "top_countries": countries.most_common(10),
            "top_usernames": usernames.most_common(10),
            "top_passwords": passwords.most_common(10),
            "timeline": [{"hour": h, "count": c} for h, c in sorted(hours.items())],
        }

    @app.get("/api/events")
    def events(page: int = Query(1, ge=1), page_size: int = Query(50, le=500),
               frm: str | None = Query(None, alias="from"),
               to: str | None = Query(None, alias="to")) -> dict:
        all_rows = _all_events_flat(storage)
        if frm:
            all_rows = [e for e in all_rows if e["ts"] >= frm]
        if to:
            all_rows = [e for e in all_rows if e["ts"] <= to]
        total = len(all_rows)
        start = (page - 1) * page_size
        return {"items": all_rows[start:start + page_size], "total": total}

    @app.get("/api/sessions/{session_id}")
    def session(session_id: str) -> dict:
        rows = [e for e in _all_events_flat(storage) if e.get("session_id") == session_id]
        if not rows:
            raise HTTPException(status_code=404, detail="session not found")
        return {"session_id": session_id, "events": rows}

    @app.get("/api/alerts")
    def alerts() -> list[dict]:
        return storage.get_alerts_all()

    return app


def _all_events_flat(storage: Storage) -> list[dict]:
    rows = []
    ips = {r["ip"]: r for r in storage.conn.execute("SELECT ip, country, asn, abuse_confidence FROM enrichment")}
    for row in storage.conn.execute(
        "SELECT " + ", ".join(
            ["event_type", "ts", "src_ip", "src_port", "protocol", "session_id",
             "username", "password", "command", "url", "dataset_id"]) +
        " FROM events ORDER BY ts, id"
    ):
        d = dict(row)
        d["country"] = (ips.get(d["src_ip"]) or {}).get("country")
        rows.append(d)
    return rows
```

Also add to `Storage` (Task 2 file) one method the API needs (dataset-independent, all ingested data):

```python
    def get_alerts_all(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT rule_id, ts, src_ip, details_json, dataset_id "
            "FROM alerts ORDER BY ts, id"
        )
        return [dict(r) for r in cur]
```

(Add a matching test in `tests/test_storage.py`:

```python
def test_alerts_all_spans_datasets(storage):
    storage.insert_alerts([
        {"rule_id": "R", "ts": "2023-06-12T14:00:03.000Z", "src_ip": "1.1.1.1",
         "details_json": "{}", "dataset_id": "dsA"},
        {"rule_id": "R", "ts": "2023-06-12T15:00:03.000Z", "src_ip": "1.1.1.2",
         "details_json": "{}", "dataset_id": "dsB"},
    ])
    assert [a["dataset_id"] for a in storage.get_alerts_all()] == ["dsA", "dsB"]
```

)

- [ ] **Step 4: Run all tests**

Run: `python -m pytest -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/honeyglobe/api.py tests/test_api.py tests/test_storage.py
git commit -m "feat: FastAPI REST endpoints for stats, events, sessions, alerts"
```

---

### Task 6: WebSocket replay engine

**Files:**
- Create: `src/honeyglobe/replay.py`
- Modify: `src/honeyglobe/api.py` (add `/ws` route)
- Test: `tests/test_replay.py`

**Interfaces:**
- Consumes: event dicts (from storage via API app).
- Produces: `replay.ReplayClock` class + `/ws` endpoint. Protocol (spec §API): client sends `{"action": "play" | "pause" | "seek", "speed": 1 | 10 | 60 | 3600}` (speed optional on play; seek takes `"ts"`); server pushes `{"type": "events", "events": [...]}` batches (in dataset-time order) and `{"type": "done"}` at end. Determinism: emitted sequence depends only on `(dataset, cursor, speed)`.

**Implementation note:** no `await asyncio.sleep(real_seconds * speed)` wall-clock waiting in tests — the clock is injectable (`ReplayClock(events, speed, sleep=asyncio.sleep)`); tests pass a no-op sleep. Production uses `asyncio.sleep` with event-gap-based delay: delay = max(0.01, gap_seconds / speed), capped at 2s so long dead air doesn't stall the demo.

- [ ] **Step 1: Write failing replay tests**

`tests/test_replay.py`:

```python
import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from honeyglobe.api import create_app
from honeyglobe.events import Event
from honeyglobe.replay import ReplayClock
from honeyglobe.storage import Storage


def _ev(ts, et="login_attempt", ip="1.2.3.4"):
    return dict(event_type=et, ts=ts, src_ip=ip, src_port=1, protocol="ssh",
                session_id="s", username=None, password=None, command=None,
                url=None, dataset_id="ds1")


async def _nosleep(delay: float) -> None:
    pass


def test_clock_emits_in_order_and_finishes():
    events = [_ev("2023-06-12T14:00:00Z"), _ev("2023-06-12T14:00:10Z"),
              _ev("2023-06-12T14:00:20Z")]
    clock = ReplayClock(events, speed=60, sleep=_nosleep)

    async def collect():
        return [b async for b in clock.batches()]

    batches = asyncio.run(collect())
    flat = [e for b in batches if b["type"] == "events" for e in b["events"]]
    assert [e["ts"] for e in flat] == [e["ts"] for e in events]
    assert batches[-1]["type"] == "done"


def test_clock_speed_changes_rate_not_order():
    events = [_ev("2023-06-12T14:00:00Z"), _ev("2023-06-12T14:00:10Z")]
    for speed in (1, 10, 60, 3600):
        clock = ReplayClock(events, speed=speed, sleep=_nosleep)

        async def collect():
            return [b async for b in clock.batches()]

        batches = asyncio.run(collect())
        flat = [e for b in batches if b["type"] == "events" for e in b["events"]]
        assert len(flat) == 2


def test_seek_past_end_yields_done_only():
    events = [_ev("2023-06-12T14:00:00Z")]
    clock = ReplayClock(events, speed=1, sleep=_nosleep)
    clock.seek("2024-01-01T00:00:00Z")

    async def collect():
        return [b async for b in clock.batches()]

    batches = asyncio.run(collect())
    assert batches[-1]["type"] == "done"
    assert sum(len(b.get("events", [])) for b in batches) == 0


@pytest.fixture()
def client(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    storage.insert_events([
        Event("login_attempt", "2023-06-12T14:00:00Z", "1.2.3.4", 1, "ssh",
              "s", "root", "x", None, None, "ds1"),
        Event("login_attempt", "2023-06-12T14:00:10Z", "1.2.3.4", 1, "ssh",
              "s", "root", "x", None, None, "ds1"),
    ])
    return TestClient(create_app(tmp_path / "t.db"))


def test_ws_replay_roundtrip(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"action": "play", "speed": 3600})
        got = []
        while True:
            msg = ws.receive_json()
            if msg["type"] == "done":
                break
            got.extend(msg["events"])
        assert len(got) == 2
        assert got[0]["ts"] <= got[1]["ts"]


def test_ws_pause_stops_stream(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"action": "play", "speed": 1})
        ws.send_json({"action": "pause"})
        first = ws.receive_json()
        assert first["type"] in {"events", "done"}
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_replay.py -v`
Expected: FAIL — no module `honeyglobe.replay`.

- [ ] **Step 3: Implement ReplayClock and the /ws route**

`src/honeyglobe/replay.py`:

```python
import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime

MAX_DELAY = 2.0
MIN_DELAY = 0.01


class ReplayClock:
    """Deterministic replay over a ts-ordered event list.

    State derives only from (events, cursor, speed).
    """

    def __init__(self, events: list[dict], speed: int = 1,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.events = sorted(events, key=lambda e: e["ts"])
        self.speed = speed
        self.cursor = 0
        self.paused = False
        self._sleep = sleep

    def play(self, speed: int | None = None) -> None:
        if speed is not None:
            self.speed = speed
        self.paused = False

    def pause(self) -> None:
        self.paused = True

    def seek(self, ts: str) -> None:
        target = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        self.cursor = 0
        for i, e in enumerate(self.events):
            if datetime.fromisoformat(e["ts"].replace("Z", "+00:00")) >= target:
                self.cursor = i
                break
        else:
            self.cursor = len(self.events)

    async def batches(self) -> AsyncIterator[dict]:
        batch: list[dict] = []
        last_ts: datetime | None = None
        while self.cursor < len(self.events):
            while self.paused:
                await self._sleep(0.05)
            e = self.events[self.cursor]
            now = datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
            if last_ts is not None:
                gap = (now - last_ts).total_seconds()
                delay = max(MIN_DELAY, min(gap / max(self.speed, 1), MAX_DELAY))
                await self._sleep(delay)
            batch.append(e)
            self.cursor += 1
            last_ts = now
            if len(batch) >= 100:
                yield {"type": "events", "events": batch}
                batch = []
        if batch:
            yield {"type": "events", "events": batch}
        yield {"type": "done"}
```

Add to `api.py` inside `create_app` (after REST routes):

```python
    from honeyglobe.replay import ReplayClock  # noqa: local import keeps app importable without ws deps

    class _ConnectionState:
        def __init__(self) -> None:
            self.clock: ReplayClock | None = None

    from fastapi import WebSocket, WebSocketDisconnect

    @app.websocket("/ws")
    async def ws_replay(websocket: WebSocket) -> None:
        await websocket.accept()
        state = _ConnectionState()
        try:
            while True:
                msg = await websocket.receive_json()
                action = msg.get("action")
                if action == "play":
                    if state.clock is None or msg.get("reset"):
                        state.clock = ReplayClock(_all_events_flat(storage), speed=msg.get("speed", 1))
                    else:
                        state.clock.play(speed=msg.get("speed"))
                    async for batch in state.clock.batches():
                        await websocket.send_json(batch)
                elif action == "pause" and state.clock is not None:
                    state.clock.pause()
                elif action == "seek" and state.clock is not None:
                    state.clock.seek(msg.get("ts", "1970-01-01T00:00:00Z"))
        except WebSocketDisconnect:
            return
```

- [ ] **Step 4: Run replay + WS tests**

Run: `python -m pytest tests/test_replay.py -v`
Expected: all PASS. Note: `test_ws_pause_stops_stream` asserts only that pause doesn't crash the connection (the clock's paused loop yields no further batches until play).

- [ ] **Step 5: Run the full suite + lint**

Run: `python -m pytest -v` then `python -m ruff check src tests`
Expected: all PASS, no lint errors.

- [ ] **Step 6: Commit**

```bash
git add src/honeyglobe/replay.py src/honeyglobe/api.py tests/test_replay.py
git commit -m "feat: deterministic WebSocket replay engine with play/pause/seek/speed"
```

---

### Task 7: Determinism golden test + CI

**Files:**
- Create: `tests/test_golden.py`, `.github/workflows/ci.yml`
- Modify: `README.md` (local dev instructions)

**Interfaces:**
- Consumes: everything above.
- Produces: CI gate that enforces spec's determinism requirement: same dataset ⇒ same alerts.

- [ ] **Step 1: Write the golden test**

`tests/test_golden.py`:

```python
import json
from pathlib import Path

from honeyglobe.detect.engine import run_all
from honeyglobe.sources.dataset import DatasetSource

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cowrie.jsonl"
GOLDEN = Path(__file__).parent / "golden" / "alerts.json"


def test_alerts_are_deterministic_and_match_golden():
    from dataclasses import asdict

    events = [asdict(e) for e in DatasetSource(dataset_id="fixture", path=FIXTURE).events()]
    alerts = run_all(events)
    digest = [
        {k: a[k] for k in ("rule_id", "ts", "src_ip", "details_json", "dataset_id")}
        for a in alerts
    ]
    GOLDEN.parent.mkdir(exist_ok=True)
    if GOLDEN.exists():
        assert digest == json.loads(GOLDEN.read_text()), "detection output changed — regenerate golden if intentional"
    else:
        GOLDEN.write_text(json.dumps(digest, indent=2))
        raise AssertionError("golden file created — re-run once to verify stability")


def test_second_run_identical():
    from dataclasses import asdict

    events = [asdict(e) for e in DatasetSource(dataset_id="fixture", path=FIXTURE).events()]
    assert run_all(events) == run_all(events)
```

- [ ] **Step 2: Run — first run creates golden, second passes**

Run: `python -m pytest tests/test_golden.py -v` (expect: create + fail), then again (expect: PASS, 2 tests).

- [ ] **Step 3: Inspect the golden file by eye**

Read `tests/golden/alerts.json` — confirm rule IDs, timestamps and IPs are plausible for the fixture (DOWNLOAD_ATTEMPT expected; others may or may not fire on 3 logins). This is a human gate: if something nonsensical is in there, fix rules, delete golden, regenerate.

- [ ] **Step 4: Commit golden**

```bash
git add tests/test_golden.py tests/golden/alerts.json
git commit -m "test: golden determinism test for detection output"
```

- [ ] **Step 5: CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI
on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: python -m pip install -e ".[dev]"
      - run: python -m ruff check src tests
      - run: python -m pytest -v
```

- [ ] **Step 6: Local verify of CI commands**

Run: `python -m ruff check src tests` and `python -m pytest -v`
Expected: clean + green. Fix any lint findings before committing.

- [ ] **Step 7: Update README local-dev section and commit**

README additions:

```markdown
## Local development

    python -m pip install -e ".[dev]"
    python -m honeyglobe.ingest <dataset_id> data/datasets/<file>
    uvicorn honeyglobe.api:create_dev_app --factory --reload

(create_dev_app is added below.)
```

Also add to `api.py` at module level:

```python
def create_dev_app() -> FastAPI:
    """Factory for `uvicorn honeyglobe.api:create_dev_app --factory`."""
    from pathlib import Path as _P
    return create_app(_P("data/honeyglobe.db"))
```

Run: `python -m pytest -v` (still green), then:

```bash
git add .github/workflows/ci.yml README.md src/honeyglobe/api.py
git commit -m "chore: CI workflow + local dev instructions"
```

---

### Task 8: End-to-end smoke test on real data

**Files:**
- Create: `scripts/smoke.py`
- Modify: `README.md` (usage section)

**Interfaces:**
- Consumes: full pipeline + API.
- Produces: one-command verification story for the README and interviews.

- [ ] **Step 1: Write the smoke script**

`scripts/smoke.py`:

```python
"""End-to-end smoke: ingest a dataset, start the app, hit every endpoint, replay over WS.

Usage: python scripts/smoke.py <dataset_id> <path>
"""

import asyncio
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from honeyglobe.api import create_app
from honeyglobe.enrich import Enricher
from honeyglobe.ingest import run
from honeyglobe.sources.dataset import DatasetSource
from honeyglobe.storage import Storage


def main() -> None:
    dataset_id, path = sys.argv[1], sys.argv[2]
    db = Path("data/smoke.db")
    if db.exists():
        db.unlink()
    storage = Storage(db)
    enricher = Enricher(storage, geo_db=None, abuse_client=None)
    summary = run(DatasetSource(dataset_id, Path(path)), storage, enricher, dataset_id)
    print(f"ingest: {summary}")
    assert summary["events"] > 1000, "expected a real dataset, got tiny input"

    client = TestClient(create_app(db))
    assert client.get("/api/health").json() == {"status": "ok"}
    stats = client.get("/api/stats/summary").json()
    assert stats["total_events"] == summary["events"]
    assert stats["unique_ips"] > 10
    alerts = client.get("/api/alerts").json()
    print(f"alerts: {len(alerts)} across rules "
          f"{sorted({a['rule_id'] for a in alerts})}")
    sessions = client.get("/api/events", params={"page_size": 1}).json()["items"]
    if sessions and sessions[0].get("session_id"):
        assert client.get(f"/api/sessions/{sessions[0]['session_id']}").status_code == 200

    with client.websocket_connect("/ws") as ws:
        ws.send_json({"action": "play", "speed": 3600})
        n = 0
        while True:
            msg = ws.receive_json()
            if msg["type"] == "done":
                break
            n += len(msg["events"])
    assert n == summary["events"], f"WS replay emitted {n}, expected {summary['events']}"
    print(f"ws replay: {n} events streamed in order — OK")
    print("SMOKE PASS")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it on the real dataset**

Run: `python scripts/smoke.py <dataset_id> data/datasets/<file>`
Expected: prints ingest summary, alert count/rule IDs, `SMOKE PASS`. WS replay count must equal inserted events (deterministic replay invariant).

- [ ] **Step 3: README usage section + commit**

```markdown
## Verify the whole pipeline

    python scripts/smoke.py <dataset_id> data/datasets/<file>
    # → SMOKE PASS
```

```bash
git add scripts/smoke.py README.md
git commit -m "feat: end-to-end smoke script over real dataset"
```

---

## Post-plan tasks (NOT in this plan — sequenced next)

- **Plan 2 — Frontend:** Three.js globe, live feed, dashboards, session replay viewer, alerts view (spec §Frontend). Consumes this plan's REST + WS interfaces verbatim.
- **Plan 3 — Static export & GitHub Pages:** `data.json` export, client-side replay loop, CI badge, deployment (spec §Static export, §Testing).
- `LiveSource` adapter: defined interface only (spec §Roadmap phase 6).

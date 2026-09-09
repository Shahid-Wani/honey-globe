# HoneyGlobe — Design Spec

**Date:** 2026-09-09
**Status:** Approved (brainstorming session with Shahid)
**Repo:** `honey-globe/` (new project)

## One-liner

A live-feeling 3D globe that visualizes **real SSH honeypot attacks** (from published research datasets), with geolocation enrichment, a rule-based detection engine, attacker session replay, and time controls — deployable as a free static demo on GitHub Pages.

## Purpose & resume story

Target role: **blue team / SOC / detection engineering**. The project demonstrates, end to end:

- Data pipeline engineering (ingest → normalize → enrich → store)
- Detection engineering (rules over real attack telemetry, with tests)
- Visualization/frontend craft (Three.js globe, live-feeling replay)
- Public, verifiable artifact (GitHub Pages demo + CI)

Interview line: "I built a detection and visualization pipeline over tens of thousands of real honeypot attacks, wrote tested detection rules, and published a live-replay demo — architecture is live-feed ready."

## Goals

1. Ingest real honeypot attack data (published datasets) with provenance
2. Normalize into a single event schema regardless of source
3. Enrich attacker IPs with country, ASN, and threat-intel confidence
4. Run rule-based detections producing alerts
5. Visualize attacks as animated arcs on a 3D globe with time controls (play/pause/speed)
6. Provide dashboards (top countries, top credentials, attack timeline)
7. Provide terminal-style attacker session replay
8. Export a fully static demo for GitHub Pages (zero hosting cost)
9. Keep a `LiveSource` adapter interface so a real honeypot can plug in later unchanged

## Non-goals (v1)

- No live honeypot deployment (no VPS budget; future phase)
- No user accounts / auth / multi-tenancy
- No Postgres/ClickHouse — SQLite is sufficient at this scale
- No ML anomaly detection (possible future phase)
- No mobile-specific UI

## Architecture

```
[Public honeypot datasets]        (future, when hosting exists:)
  (research captures of            [Live Cowrie honeypot]
   real SSH attacks)                        │
       │                                    │
       ▼                                    ▼
  ┌─ Source adapters (same interface) ──────────────┐
  │  DatasetSource — parses & replays dataset files │
  │  LiveSource   — future drop-in, same interface  │
  └──────────────┬───────────────────────────────────┘
                 ▼
   Normalized events → SQLite (honeyglobe.db)
                 ▼
   FastAPI: REST (stats/events/sessions/alerts) + WebSocket (replay stream)
                 ▼
   Three.js globe frontend (arcs, feed, dashboards, alerts, session replay)

   Build step: `export_static` → data.json + static site → GitHub Pages
```

### Two run modes

1. **Full stack (local dev):** FastAPI serves REST + WS; frontend connects to localhost. The replay engine runs server-side: it walks dataset events by timestamp and pushes them over WS at the chosen speed.
2. **Static export (public demo):** a build step precomputes events, sessions, alerts, and stats into `data.json`. The same frontend runs in static mode: identical replay logic executed client-side against `data.json`. No backend needed on GitHub Pages.

The replay engine lives in one shared module with two drivers (server-push WS / client-side loop) so behavior is identical in both modes.

## Components

### 1. Source adapters

- Interface: each source yields normalized events (dicts) with a `dataset_id` provenance tag.
- `DatasetSource`: reads local copies of published honeypot datasets (JSON-lines preferred). Malformed lines are counted and skipped, never crash.
- `LiveSource` (future, stub only in v1): same interface; documented in README.

### 2. Event schema (normalized)

```json
{
  "event_type": "login_attempt | login_success | command | download_attempt | session_open | session_close",
  "ts": "ISO-8601",
  "src_ip": "1.2.3.4",
  "src_port": 51234,
  "protocol": "ssh",
  "session_id": "abc123",
  "username": "root",
  "password": "123456",
  "command": "cat /etc/passwd",
  "url": "http://... ",
  "dataset_id": "kaggle-ssh-2023"
}
```

Fields are nullable per event_type (e.g. `command` only for `command` events). Enrichment is stored on separate columns/tables keyed by `src_ip` (not re-derived per event).

### 3. Enrichment

- **GeoLite2** (MaxMind, free with license key): country + ASN. GeoLite2 DBs are vendored locally; missing DB ⇒ events stored unenriched, enrichment backfills later — never blocks ingest.
- **AbuseIPDB** (free tier): confidence score per IP. Results cached in DB per IP per day; rate limits respected; key lives in `.env`.
- Historical-IP caveat documented in README: old dataset IPs may have different owners today; enrichment reflects current state.

### 4. Detection engine

Rule-based, evaluated **at ingest time** (batch, in dataset-timestamp order) so alerts are precomputed and stored in the DB — the replay UI simply surfaces them at the right moment, and determinism is guaranteed (same dataset in ⇒ same alerts out). Each rule has a stable ID, parameters, and pytest coverage. Initial rules:

| ID | Rule | Default params |
|---|---|---|
| `CRED_BURST` | Login attempts from one IP in a time window | ≥10 attempts / 10 min |
| `FIRST_COUNTRY` | Attacker country not seen before in dataset history | informational |
| `PERSISTENT_IP` | Same IP seen on ≥3 distinct days | ≥3 days |
| `POPULAR_CRED` | Username in top X% of attempts (default-cred campaigns) | ≥5% of attempts |
| `DOWNLOAD_ATTEMPT` | Session attempted to fetch a URL | always alert; URL displayed as text only |

Rules are pure functions over event windows where possible (testable without the server).

### 5. API (FastAPI)

- `GET /api/stats/summary` — totals, top countries, top usernames/passwords, per-hour timeline buckets
- `GET /api/events?from=&to=&page=` — paginated history
- `GET /api/sessions/{id}` — ordered session events for the replay viewer
- `GET /api/alerts` — detection output
- `WS /ws` — replay stream; client sends `{action: play|pause|seek, speed: 1|10|60|3600}` control messages; server pushes events in dataset-time order. Replay is deterministic: state derives from (dataset, cursor, speed).

### 6. Frontend (Three.js + vanilla JS)

Views (single-page, tabbed):

1. **Globe** (default): 3D earth, animated attack arcs from attacker country to home marker; click arc/event ⇒ details panel
2. **Live feed**: scrolling event list (attacker-controlled strings rendered as text, escaped)
3. **Dashboards**: top countries, top usernames/passwords tried, attacks-per-hour chart
4. **Session replay**: terminal-style player stepping through one attacker's recorded commands with timings
5. **Alerts**: detection engine output with rule IDs

WS disconnect ⇒ auto-reconnect with backoff; replay state (cursor, speed) survives reconnect. In static mode, the same UI reads `data.json`.

### 7. Static export

`make export` (or script) produces `dist/` — precomputed `data.json` (events, sessions, alerts, summary stats) + built frontend. Deployed to GitHub Pages.

## Security hygiene

- Attacker-controlled strings (usernames, passwords, commands, URLs) are **escaped before any DOM insertion** — XSS via dataset content is the primary threat model here
- URLs from attack data are displayed as text and **never fetched**
- `.env` (AbuseIPDB/MaxMind keys) gitignored; `.env.example` committed
- Dataset licenses verified in phase 1 and attributed in README
- No endpoint accepts user-supplied SQL/JSON-path expressions

## Testing & verification

- **pytest**: adapters parse fixture files in real dataset formats; detection rules get event-window fixtures; API gets endpoint tests
- **Determinism golden-file test**: replaying dataset X always produces identical alert list (CI-enforced via GitHub Actions)
- **Headless frontend verification**: screenshots + DOM assertions before any "done" claim (established personal workflow)
- CI runs: lint (ruff), pytest, determinism check, static build

## Tech stack

- Python 3.12+, FastAPI, pytest, ruff — backend, adapters, detection
- SQLite — storage
- Three.js + vanilla JS (Vite for bundling) — frontend, reusing patterns from agency-galaxy
- GitHub Actions — CI; GitHub Pages — demo hosting

## Dataset selection criteria (phase 1 task)

Candidate sources: published Cowrie/SSH honeypot datasets on Kaggle and GitHub, research-group honeypot captures (e.g. Stratosphere Labs), SANS DShield feeds as a secondary source. Selection criteria, in order:

1. License permits educational/portfolio use with attribution
2. Contains source IPs and timestamps (required for geo + timeline)
3. Prefer JSON/JSON-lines; ≥10,000 events
4. Includes login attempts and (ideally) recorded commands/sessions

Exact dataset(s) are chosen and recorded in `docs/data-sources.md` during phase 1, with license notes. If no single dataset has everything, combine: one for volume (logins) + one for session depth (commands).

## Roadmap

| Phase | Delivers | Rough size |
|---|---|---|
| 1 | Dataset curation + `DatasetSource` + SQLite + event schema + provenance | weekend |
| 2 | FastAPI (REST + WS replay engine) + minimal globe with animated arcs | 1–2 weeks |
| 3 | GeoLite2 + AbuseIPDB enrichment + dashboards | 1 week |
| 4 | Detection engine + alerts view + session replay viewer | 1–2 weeks |
| 5 | Static export + GitHub Pages demo + README with real stats + CI | 1 week |
| 6 | *(future)* `LiveSource` adapter when hosting exists | sized then |

## Success criteria

- ≥10,000 real events ingested with provenance, replayed deterministically
- ≥3 detection rules firing on real dataset content, unit-tested
- Session replay viewer plays at least one full attacker session
- Public GitHub Pages demo with working time controls
- README with real aggregate stats (top countries/credentials) and architecture diagram
- CI green: lint + tests + determinism check + static build

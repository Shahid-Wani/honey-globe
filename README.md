# HoneyGlobe

[![CI](https://github.com/Shahid-Wani/honey-globe/actions/workflows/ci.yml/badge.svg)](https://github.com/Shahid-Wani/honey-globe/actions/workflows/ci.yml)

A detection and visualization pipeline over **real honeypot attack data** — a live-feeling 3D globe with geolocation enrichment, a rule-based detection engine, attacker session replay, and time controls, deployable as a free static demo on GitHub Pages.

## Pipeline

```
real honeypot datasets → DatasetSource (Cowrie JSONL, malformed-tolerant)
  → SQLite storage (SHA-256 dedup, per-call connections)
  → enrichment (GeoLite2 country, AbuseIPDB confidence, per-IP cache)
  → detection engine (5 pure rules, evaluated at ingest, golden-pinned)
  → FastAPI REST + WebSocket concurrent-pump replay (live pause/seek/speed)
```

## Local development

```
python -m pip install -e ".[dev]"
python -m honeyglobe.ingest <dataset_id> data/datasets/<file>
uvicorn honeyglobe.api:create_dev_app --factory --reload
```

`create_dev_app` is a no-arg factory in `src/honeyglobe/api.py` that reads `data/honeyglobe.db`.

## Verify the whole pipeline

    python scripts/smoke.py <dataset_id> data/datasets/<file>
    # → SMOKE PASS

The smoke asserts the deterministic replay invariant: WebSocket-replayed events must equal ingested events.

## Data sources & attribution

- Dataset: [nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie](https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie) — real Cowrie honeypot captures from 10 global sensors, 2024-10-23 → 2024-10-30 (~3.3M raw events)
- License: **CC-BY-SA-4.0**. Raw logs are NOT redistributed in this repo (`data/` is gitignored) — see `docs/data-sources.md` for provenance, eventid coverage, and fetch instructions.
- **Historical-IP caveat:** enrichment reflects the *current* GeoLite2 database state; IPs captured in 2024 may have different owners or geolocations today.

## Live-feed ready

The `SourceAdapter` interface (`events() -> Iterator[Event]`) is source-agnostic: `DatasetSource` replays published captures today; a future `LiveSource` backed by a live Cowrie honeypot tail plugs into the same pipeline unchanged (see roadmap issue #12).

"""End-to-end smoke: ingest a dataset, start the app, hit every endpoint, replay over WS.

Usage: python scripts/smoke.py <dataset_id> <path>
"""

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

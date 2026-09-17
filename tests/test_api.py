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

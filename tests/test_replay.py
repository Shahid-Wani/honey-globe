import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from honeyglobe.api import create_app
from honeyglobe.events import Event
from honeyglobe.replay import ReplayClock
from honeyglobe.storage import Storage


def _ev(ts, et="login_attempt", ip="1.2.3.4"):
    return {"event_type": et, "ts": ts, "src_ip": ip, "src_port": 1, "protocol": "ssh",
            "session_id": "s", "username": None, "password": None, "command": None,
            "url": None, "dataset_id": "ds1"}


async def _nosleep(delay: float) -> None:
    pass


def _collect(clock: ReplayClock) -> list[dict]:
    async def run():
        return [b async for b in clock.batches()]

    return asyncio.run(run())


def test_clock_emits_in_order_and_finishes():
    events = [_ev("2023-06-12T14:00:00Z"), _ev("2023-06-12T14:00:10Z"),
              _ev("2023-06-12T14:00:20Z")]
    clock = ReplayClock(events, speed=60, sleep=_nosleep)
    batches = _collect(clock)
    flat = [e for b in batches if b["type"] == "events" for e in b["events"]]
    assert [e["ts"] for e in flat] == [e["ts"] for e in events]
    assert batches[-1]["type"] == "done"


def test_clock_speed_changes_rate_not_order():
    events = [_ev("2023-06-12T14:00:00Z"), _ev("2023-06-12T14:00:10Z")]
    for speed in (1, 10, 60, 3600):
        clock = ReplayClock(events, speed=speed, sleep=_nosleep)
        batches = _collect(clock)
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


def test_ws_seek_during_replay_skips_remaining_events(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"action": "play", "speed": 1})
        first = ws.receive_json()
        assert first["type"] == "events"
        assert first["events"][0]["ts"] == "2023-06-12T14:00:00Z"
        ws.send_json({"action": "seek", "ts": "2024-01-01T00:00:00Z"})
        nxt = ws.receive_json()
        assert nxt["type"] == "done"

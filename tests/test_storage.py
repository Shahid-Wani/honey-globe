from pathlib import Path

import pytest

from honeyglobe.events import Event
from honeyglobe.storage import Storage


def _event(**overrides):
    base = {
        "event_type": "login_attempt", "ts": "2023-06-12T14:00:03.000Z",
        "src_ip": "203.0.113.5", "src_port": 51234, "protocol": "ssh",
        "session_id": "aa11", "username": "root", "password": "123456",
        "command": None, "url": None, "dataset_id": "ds1",
    }
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

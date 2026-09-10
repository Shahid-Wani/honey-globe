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

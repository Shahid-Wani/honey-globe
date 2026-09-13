from honeyglobe.detect.engine import run_all


def test_run_all_concatenates_and_sorts_by_ts():
    events = [
        {
            "event_type": "download_attempt", "ts": "2023-06-12T16:00:00Z", "src_ip": "5.5.5.5",
            "src_port": 1, "protocol": "ssh", "session_id": "s", "username": None, "password": None,
            "command": None, "url": "http://x.invalid/a", "dataset_id": "ds1",
        },
        {
            "event_type": "login_attempt", "ts": "2023-06-12T14:00:00Z", "src_ip": "1.2.3.4",
            "src_port": 1, "protocol": "ssh", "session_id": "s", "username": "root", "password": "x",
            "command": None, "url": None, "dataset_id": "ds1",
        },
    ]
    # give the first event 9 more attempts to trigger CRED_BURST too
    events += [
        {
            "event_type": "login_attempt", "ts": f"2023-06-12T14:0{i}:00Z", "src_ip": "1.2.3.4",
            "src_port": 1, "protocol": "ssh", "session_id": "s", "username": "root", "password": "x",
            "command": None, "url": None, "dataset_id": "ds1",
        }
        for i in range(1, 10)
    ]
    alerts = run_all(events)
    ids = [a["rule_id"] for a in alerts]
    assert "CRED_BURST" in ids and "DOWNLOAD_ATTEMPT" in ids
    assert alerts == sorted(alerts, key=lambda a: a["ts"])


def test_run_all_deterministic():
    events = [
        {
            "event_type": "login_attempt", "ts": "2023-06-12T14:00:00Z", "src_ip": "1.2.3.4",
            "src_port": 1, "protocol": "ssh", "session_id": "s", "username": "root", "password": "x",
            "command": None, "url": None, "dataset_id": "ds1",
        },
    ]
    assert run_all(events) == run_all(events)

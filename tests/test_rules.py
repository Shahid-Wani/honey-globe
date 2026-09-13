from honeyglobe.detect.rules import (
    CRED_BURST,
    DOWNLOAD_ATTEMPT,
    FIRST_COUNTRY,
    PERSISTENT_IP,
    POPULAR_CRED,
)


def _ev(ts, ip="1.2.3.4", et="login_attempt", user="root", pw="x", session="s1", **extra):
    e = {
        "event_type": et, "ts": ts, "src_ip": ip, "src_port": 1, "protocol": "ssh",
        "session_id": session, "username": user, "password": pw, "command": None,
        "url": None, "dataset_id": "ds1",
    }
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

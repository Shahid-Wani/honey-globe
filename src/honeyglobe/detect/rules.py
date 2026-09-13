import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=10)
CRED_BURST_THRESHOLD = 10
PERSISTENT_DAYS = 3
POPULAR_SHARE = 0.05


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


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

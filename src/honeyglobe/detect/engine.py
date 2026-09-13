from honeyglobe.detect.rules import RULES


def run_all(events: list[dict]) -> list[dict]:
    ordered = sorted(events, key=lambda e: (e["ts"], e.get("src_ip", "")))
    alerts = []
    for rule in RULES.values():
        alerts.extend(rule.evaluate(ordered))
    alerts.sort(key=lambda a: a["ts"])
    return alerts

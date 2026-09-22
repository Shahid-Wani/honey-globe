import json
from pathlib import Path

from honeyglobe.detect.engine import run_all
from honeyglobe.sources.dataset import DatasetSource

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cowrie.jsonl"
GOLDEN = Path(__file__).parent / "golden" / "alerts.json"


def test_alerts_are_deterministic_and_match_golden():
    from dataclasses import asdict

    events = [asdict(e) for e in DatasetSource(dataset_id="fixture", path=FIXTURE).events()]
    alerts = run_all(events)
    digest = [
        {k: a[k] for k in ("rule_id", "ts", "src_ip", "details_json", "dataset_id")}
        for a in alerts
    ]
    GOLDEN.parent.mkdir(exist_ok=True)
    if GOLDEN.exists():
        assert digest == json.loads(GOLDEN.read_text()), "detection output changed — regenerate golden if intentional"
    else:
        GOLDEN.write_text(json.dumps(digest, indent=2))
        raise AssertionError("golden file created — re-run once to verify stability")


def test_second_run_identical():
    from dataclasses import asdict

    events = [asdict(e) for e in DatasetSource(dataset_id="fixture", path=FIXTURE).events()]
    assert run_all(events) == run_all(events)

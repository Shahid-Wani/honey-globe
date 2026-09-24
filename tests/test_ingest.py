from pathlib import Path

from honeyglobe.enrich import Enricher
from honeyglobe.ingest import run
from honeyglobe.sources.dataset import DatasetSource
from honeyglobe.storage import Storage

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cowrie.jsonl"


class FakeGeoDB:
    def get(self, ip):
        return {"country": {"iso_code": "ZZ"}, "autonomous_system": {"number": 64500}}


def test_ingest_full_pipeline(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    source = DatasetSource(dataset_id="fixture", path=FIXTURE)
    summary = run(source, storage, enricher, dataset_id="fixture")
    # 10 valid events in fixture (15 lines, 5 malformed skipped — per test_dataset_source)
    assert summary["events"] == 10
    assert summary["skipped"] == 5
    assert summary["ips"] == 3
    assert summary["alerts"] >= 1  # DOWNLOAD_ATTEMPT fires on fixture download
    alerts = storage.get_alerts("fixture")
    assert any(a["rule_id"] == "DOWNLOAD_ATTEMPT" for a in alerts)
    # events retrievable in ts order with country annotation available via enrichment
    events = list(storage.all_events("fixture"))
    assert events[0]["event_type"] == "session_open"


def test_ingest_is_idempotent(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    source = DatasetSource(dataset_id="fixture", path=FIXTURE)
    first = run(source, storage, enricher, dataset_id="fixture")
    second = run(source, storage, enricher, dataset_id="fixture")
    assert second["events"] == 0  # dedup
    assert len(list(storage.all_events("fixture"))) == first["events"]
    assert len(storage.get_alerts("fixture")) == first["alerts"]  # no alert duplication

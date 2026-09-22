from pathlib import Path

from honeyglobe.enrich import Enricher
from honeyglobe.storage import Storage


class FakeGeoDB:
    def get(self, ip):
        if ip == "203.0.113.5":
            return {
                "country": {"iso_code": "AU"},
                "autonomous_system": {"number": 64496, "organization": "Example"},
            }
        return None


def test_enrich_ips_offline(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    result = enricher.enrich_ips(["203.0.113.5", "10.0.0.1"])
    assert result["203.0.113.5"]["country"] == "AU"
    assert result["203.0.113.5"]["asn"] == "AS64496"
    assert result["10.0.0.1"]["country"] is None


def test_enrichment_cached_in_storage(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    storage.insert_enrichment("203.0.113.5", "AU", "AS64496", 88)
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    calls = []
    orig = enricher.lookup

    def counting(ips):
        calls.extend(ips)
        return orig(ips)

    enricher.lookup = counting  # type: ignore[method-assign]
    result = enricher.enrich_ips(["203.0.113.5"])
    assert "203.0.113.5" not in calls  # served from cache, no fresh lookup
    assert result["203.0.113.5"]["abuse_confidence"] == 88


def test_miss_path_persists_fresh_lookup(tmp_path: Path):
    storage = Storage(tmp_path / "t.db")
    enricher = Enricher(storage, geo_db=FakeGeoDB(), abuse_client=None)
    result = enricher.enrich_ips(["203.0.113.5"])  # cache miss -> fresh lookup
    assert result["203.0.113.5"]["country"] == "AU"
    assert storage.get_enrichment("203.0.113.5")["country"] == "AU"  # persisted for next call

import sys
from pathlib import Path

from honeyglobe.detect.engine import run_all
from honeyglobe.enrich import Enricher, make_abuse_client
from honeyglobe.sources.base import SourceAdapter
from honeyglobe.sources.dataset import DatasetSource
from honeyglobe.storage import Storage

try:
    from geolite2 import geolite2  # maxminddb-geolite2
    _GEO = geolite2.reader()
except Exception:  # noqa: BLE001 — geo enrichment is optional, degrade to None
    _GEO = None


def run(source: SourceAdapter, storage: Storage, enricher: Enricher, dataset_id: str) -> dict:
    events = list(source.events())
    inserted = storage.insert_events(events)
    skipped = getattr(source, "skipped", 0)
    ip_set = sorted({e.src_ip for e in events if e.src_ip})
    enricher.enrich_ips(ip_set)
    enriched = {ip: (storage.get_enrichment(ip) or {}) for ip in ip_set}
    stored = list(storage.all_events(dataset_id))
    for e in stored:
        e["country"] = enriched.get(e["src_ip"], {}).get("country")
    storage.clear_alerts(dataset_id)  # re-ingest must not duplicate alerts
    alerts = run_all(stored)
    storage.insert_alerts(alerts)
    return {"events": inserted, "skipped": skipped, "alerts": len(alerts), "ips": len(ip_set)}


def main() -> None:
    dataset_id, path = sys.argv[1], sys.argv[2]
    storage = Storage(Path("data/honeyglobe.db"))
    enricher = Enricher(storage, geo_db=_GEO, abuse_client=make_abuse_client())
    source = DatasetSource(dataset_id=dataset_id, path=Path(path))
    print(run(source, storage, enricher, dataset_id))


if __name__ == "__main__":
    main()

import os

import httpx


class Enricher:
    def __init__(self, storage, geo_db=None, abuse_client=None) -> None:
        self.storage = storage
        self.geo_db = geo_db  # maxminddb reader-like or None
        self.abuse_client = abuse_client  # httpx.Client with auth header or None

    def enrich_ips(self, ips: list[str]) -> dict[str, dict]:
        result: dict[str, dict] = {}
        uncached: list[str] = []
        for ip in set(ips):
            cached = self.storage.get_enrichment(ip)
            if cached is not None:
                result[ip] = cached
            else:
                uncached.append(ip)
        if uncached:
            result.update(self.lookup(uncached))
        return result

    def lookup(self, ips: list[str]) -> dict[str, dict]:
        """Fresh geo/abuse lookups for uncached IPs; each result is persisted."""
        result: dict[str, dict] = {}
        for ip in ips:
            country, asn = self._geo(ip)
            abuse = self._abuse(ip)
            record = {"country": country, "asn": asn, "abuse_confidence": abuse}
            self.storage.insert_enrichment(ip, **record)
            result[ip] = record
        return result

    def _geo(self, ip: str) -> tuple[str | None, str | None]:
        if self.geo_db is None:
            return None, None
        try:
            match = self.geo_db.get(ip)
        except Exception:  # noqa: BLE001 — enrichment is best-effort, never fail ingest
            return None, None
        if not match:
            return None, None
        country = match.get("country", {}).get("iso_code")
        asn_obj = match.get("autonomous_system", {})
        asn = f"AS{asn_obj['number']}" if "number" in asn_obj else None
        return country, asn

    def _abuse(self, ip: str) -> int | None:
        if self.abuse_client is None:
            return None
        try:
            resp = self.abuse_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 30},
            )
            data = resp.json()["data"]["abuseConfidenceScore"]
            return int(data)
        except Exception:  # noqa: BLE001 — enrichment is best-effort, never fail ingest
            return None


def make_abuse_client() -> httpx.Client | None:
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    return httpx.Client(
        headers={"Key": key, "Accept": "application/json"}, timeout=10.0
    )

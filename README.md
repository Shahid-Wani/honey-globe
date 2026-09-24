# HoneyGlobe

CI badge — added Plan 3

A live-feeling 3D globe that visualizes **real SSH honeypot attacks** (from published research datasets), with geolocation enrichment, a rule-based detection engine, attacker session replay, and time controls — deployable as a free static demo on GitHub Pages.

## Local development

```
python -m pip install -e ".[dev]"
python -m honeyglobe.ingest <dataset_id> data/datasets/<file>
uvicorn honeyglobe.api:create_dev_app --factory --reload
```

`create_dev_app` is a no-arg factory in `src/honeyglobe/api.py` that reads `data/honeyglobe.db`.

## Verify the whole pipeline

    python scripts/smoke.py <dataset_id> data/datasets/<file>
    # → SMOKE PASS

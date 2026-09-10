# Data Sources

Candidate published honeypot datasets, evaluated for inclusion. Raw dataset files stay local (`data/datasets/` is gitignored — license + size); this page records how to fetch them.

## Selection criteria

A dataset is usable if it: (1) has a license permitting educational/portfolio use, (2) contains source IPs and timestamps, (3) has ≥10k events, and (4) is Cowrie JSON-lines with `eventid` fields.

| Dataset | License | Contains IPs+timestamps | Format | Event count | URL |
|---------|---------|------------------------|--------|-------------|-----|
| Global SSH and Telnet Honeypot Logs (Cowrie) — nlaha11 | CC-BY-SA-4.0 | Yes — `src_ip`, `src_port`, ISO-8601 `timestamp` | Cowrie JSON-lines, one event per line (`cowrie.json.YYYY-MM-DD`) | 3,308,028 JSONL lines total; 1,818,927 map to our 6 event types | https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie |

The first-pass candidate (Kaggle Cowrie captures) met all criteria, so the fallbacks (GitHub repos publishing raw `cowrie.json` logs; Stratosphere Labs honeypot captures) were not needed.

## Chosen dataset

- **Dataset id:** `nlaha11-cowrie-2024`
- **Source:** Kaggle — user `nlaha11`, "Global SSH and Telnet Honeypot Logs (Cowrie)"
- **URL:** https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie
- **License:** CC-BY-SA-4.0 (see quote below)
- **Format:** Cowrie JSON-lines — `cowrie.json.YYYY-MM-DD` files under `logs/<sensor-dir>/`; 10 sensor directories, 83 JSON files
- **Date range:** 2024-10-23 → 2024-10-30 (plus rolling `cowrie.json` current logs)
- **Volume:** 3,308,028 total JSONL lines across all sensors/days
- **Local path:** `data/datasets/nlaha11/logs/<sensor-dir>/cowrie.json.YYYY-MM-DD` (gitignored — never committed)
- **eventid coverage:** `cowrie.session.connect` (518,192), `cowrie.session.closed` (517,812), `cowrie.command.input` (289,789), `cowrie.login.success` (252,859), `cowrie.login.failed` (238,145), `cowrie.session.file_download` (2,130) — all six map to HoneyGlobe event types; all other eventids (`cowrie.client.kex`, `cowrie.session.params`, …) are skipped by the adapter by design.

### License quote

Creative Commons' summary of the BY-SA 4.0 license under which this dataset is published:

> "This license lets others remix, adapt, and build upon your work even for commercial purposes, as long as they credit you and license their new creations under the identical terms."

Full legal text: https://creativecommons.org/licenses/by-sa/4.0/legalcode

### Attribution

HoneyGlobe parses and visualizes logs from "Global SSH and Telnet Honeypot Logs (Cowrie)" by `nlaha11`, published on Kaggle at the URL above and licensed under [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/). The raw logs are **not** redistributed in this repository (`data/datasets/` is gitignored); only aggregate statistics and derived visualizations are produced. Credit for the underlying data belongs entirely to the dataset publisher.

### How to fetch

```bash
kaggle datasets download -d nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie
# unzip into data/datasets/nlaha11/ so that data/datasets/nlaha11/logs/<sensor-dir>/cowrie.json.* exist
```

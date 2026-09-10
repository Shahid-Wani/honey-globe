import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from honeyglobe.events import Event

COWRIE_MAP = {
    "cowrie.session.connect": "session_open",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download_attempt",
    "cowrie.session.closed": "session_close",
}


class DatasetSource:
    """Replays a Cowrie JSON-lines file as normalized Events."""

    def __init__(self, dataset_id: str, path: Path) -> None:
        self.dataset_id = dataset_id
        self.path = Path(path)

    def events(self) -> Iterator[Event]:
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line)
                if event is not None:
                    yield event

    def _parse_line(self, line: str) -> Event | None:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return None
        mapped = COWRIE_MAP.get(raw.get("eventid", ""))
        if mapped is None:
            return None
        ts = self._valid_ts(raw.get("timestamp"))
        src_ip = raw.get("src_ip")
        if ts is None or not src_ip:
            return None
        return Event(
            event_type=mapped,
            ts=ts or "",
            src_ip=src_ip or "",
            src_port=raw.get("src_port"),
            protocol="ssh",
            session_id=raw.get("session"),
            username=raw.get("username"),
            password=raw.get("password"),
            command=raw.get("input"),
            url=raw.get("url"),
            dataset_id=self.dataset_id,
        )

    @staticmethod
    def _valid_ts(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            datetime.fromisoformat(value)
        except ValueError:
            return None
        return value

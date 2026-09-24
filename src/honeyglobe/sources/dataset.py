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
        self.skipped = 0

    def events(self) -> Iterator[Event]:
        session_protocols: dict[str, str] = {}
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                event = self._parse_line(line, session_protocols)
                if event is not None:
                    yield event
                else:
                    self.skipped += 1

    def _parse_line(self, line: str, session_protocols: dict[str, str]) -> Event | None:
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(raw, dict):
            return None
        eventid = raw.get("eventid")
        if not isinstance(eventid, str):
            return None
        mapped = COWRIE_MAP.get(eventid)
        if mapped is None:
            return None
        ts = self._valid_ts(raw.get("timestamp"))
        src_ip = raw.get("src_ip")
        if ts is None or not src_ip:
            return None
        session_id = raw.get("session")
        if mapped == "session_open":
            protocol = raw.get("protocol")
            if isinstance(protocol, str) and protocol:
                if isinstance(session_id, str) and session_id:
                    session_protocols[session_id] = protocol
            else:
                protocol = "ssh"
        elif isinstance(session_id, str) and session_id:
            protocol = session_protocols.get(session_id, "ssh")
        else:
            protocol = "ssh"
        return Event(
            event_type=mapped,
            ts=ts,
            src_ip=src_ip,
            src_port=raw.get("src_port"),
            protocol=protocol,
            session_id=session_id,
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

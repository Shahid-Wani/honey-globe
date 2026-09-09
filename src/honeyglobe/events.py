from dataclasses import dataclass

EVENT_TYPES = frozenset(
    {"session_open", "login_attempt", "login_success",
     "command", "download_attempt", "session_close"}
)

@dataclass(slots=True)
class Event:
    event_type: str
    ts: str
    src_ip: str
    src_port: int | None
    protocol: str
    session_id: str | None
    username: str | None
    password: str | None
    command: str | None
    url: str | None
    dataset_id: str

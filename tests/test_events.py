from honeyglobe.events import EVENT_TYPES, Event


def test_event_holds_all_schema_fields():
    e = Event(
        event_type="login_attempt", ts="2023-01-01T00:00:00Z",
        src_ip="1.2.3.4", src_port=51234, protocol="ssh",
        session_id="abc", username="root", password="123456",
        command=None, url=None, dataset_id="kaggle-ssh-2023",
    )
    assert e.event_type == "login_attempt"
    assert e.username == "root"

def test_event_types_constant():
    assert set(EVENT_TYPES) == {
        "session_open", "login_attempt", "login_success",
        "command", "download_attempt", "session_close",
    }

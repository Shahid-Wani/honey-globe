from collections.abc import Iterator
from typing import Protocol

from honeyglobe.events import Event


class SourceAdapter(Protocol):
    """Any event source: dataset replay or (future) live honeypot."""

    def events(self) -> Iterator[Event]: ...

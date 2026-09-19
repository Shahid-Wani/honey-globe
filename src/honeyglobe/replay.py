import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime

MAX_DELAY = 2.0
MIN_DELAY = 0.01


class ReplayClock:
    """Deterministic replay over a ts-ordered event list.

    State derives only from (events, cursor, speed). Pause/seek/speed are
    safe to call while batches() is being consumed (single event loop).
    """

    def __init__(self, events: list[dict], speed: int = 1,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        self.events = sorted(events, key=lambda e: e["ts"])
        self.speed = speed
        self.cursor = 0
        self.paused = False
        self._sleep = sleep

    def play(self, speed: int | None = None) -> None:
        if speed is not None:
            self.speed = speed
        self.paused = False

    def pause(self) -> None:
        self.paused = True

    def seek(self, ts: str) -> None:
        target = datetime.fromisoformat(ts)
        self.cursor = 0
        for i, e in enumerate(self.events):
            if datetime.fromisoformat(e["ts"]) >= target:
                self.cursor = i
                break
        else:
            self.cursor = len(self.events)

    async def batches(self) -> AsyncIterator[dict]:
        last_ts: datetime | None = None
        while self.cursor < len(self.events):
            while self.paused:
                await self._sleep(0.05)
            e = self.events[self.cursor]
            now = datetime.fromisoformat(e["ts"])
            if last_ts is not None:
                gap = (now - last_ts).total_seconds()
                delay = max(MIN_DELAY, min(gap / max(self.speed, 1), MAX_DELAY))
                cursor_before = self.cursor
                await self._sleep(delay)
                if self.cursor != cursor_before or self.paused:
                    continue
            self.cursor += 1
            last_ts = now
            yield {"type": "events", "events": [e]}
        yield {"type": "done"}

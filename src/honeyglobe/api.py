import asyncio
import contextlib
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect

from honeyglobe.replay import ReplayClock
from honeyglobe.storage import Storage


def create_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="HoneyGlobe API")
    storage = Storage(db_path)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/stats/summary")
    def summary() -> dict:
        events = storage.all_events_enriched()
        countries = Counter(e["country"] for e in events if e.get("country"))
        usernames = Counter(e["username"] for e in events
                            if e["event_type"] == "login_attempt" and e["username"])
        passwords = Counter(e["password"] for e in events
                            if e["event_type"] == "login_attempt" and e["password"])
        hours = Counter(e["ts"][:13] for e in events)
        return {
            "total_events": len(events),
            "total_alerts": len(storage.get_alerts_all()),
            "unique_ips": len({e["src_ip"] for e in events}),
            "top_countries": countries.most_common(10),
            "top_usernames": usernames.most_common(10),
            "top_passwords": passwords.most_common(10),
            "timeline": [{"hour": h, "count": c} for h, c in sorted(hours.items())],
        }

    @app.get("/api/events")
    def events(page: int = Query(1, ge=1), page_size: int = Query(50, le=500),
               frm: str | None = Query(None, alias="from"),
               to: str | None = Query(None, alias="to")) -> dict:
        all_rows = storage.all_events_enriched()
        if frm:
            all_rows = [e for e in all_rows if e["ts"] >= frm]
        if to:
            all_rows = [e for e in all_rows if e["ts"] <= to]
        total = len(all_rows)
        start = (page - 1) * page_size
        return {"items": all_rows[start:start + page_size], "total": total}

    @app.get("/api/sessions/{session_id}")
    def session(session_id: str) -> dict:
        rows = [e for e in storage.all_events_enriched()
                if e.get("session_id") == session_id]
        if not rows:
            raise HTTPException(status_code=404, detail="session not found")
        return {"session_id": session_id, "events": rows}

    @app.get("/api/alerts")
    def alerts() -> list[dict]:
        return storage.get_alerts_all()

    @app.websocket("/ws")
    async def ws_replay(websocket: WebSocket) -> None:
        await websocket.accept()
        clock: ReplayClock | None = None
        pump: asyncio.Task | None = None

        async def run_pump(c: ReplayClock) -> None:
            try:
                async for batch in c.batches():
                    await websocket.send_json(batch)
            except (WebSocketDisconnect, RuntimeError):
                pass

        try:
            while True:
                msg = await websocket.receive_json()
                action = msg.get("action")
                if action == "play":
                    if clock is None or msg.get("reset"):
                        if pump is not None and not pump.done():
                            pump.cancel()
                            with contextlib.suppress(asyncio.CancelledError):
                                await pump
                        clock = ReplayClock(
                            storage.all_events_enriched(), speed=msg.get("speed", 1)
                        )
                        pump = asyncio.create_task(run_pump(clock))
                    else:
                        clock.play(speed=msg.get("speed"))
                elif action == "pause" and clock is not None:
                    clock.pause()
                elif action == "seek" and clock is not None:
                    clock.seek(msg.get("ts", "1970-01-01T00:00:00Z"))
        except WebSocketDisconnect:
            pass
        finally:
            if pump is not None and not pump.done():
                pump.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await pump

    return app


def create_dev_app() -> FastAPI:
    """Factory for `uvicorn honeyglobe.api:create_dev_app --factory`."""
    from pathlib import Path as _P
    return create_app(_P("data/honeyglobe.db"))

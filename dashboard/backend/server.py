"""
dashboard/backend/server.py — read-only SSE bridge
===================================================
Serves GhostNet events to the browser. It can start a GhostNet run, or
just observe one; it never computes a state, a reward or a mutation.

    GET /health     -> {"backend":"up","session":bool}
    GET /snapshot   -> events so far (for a browser that joins late)
    GET /events     -> text/event-stream, live
    GET /           -> the dashboard page

Bound to 127.0.0.1 by default: the project directory holds AWS
credentials and API keys, so this must not be exposed on a network.
"""

import asyncio
import json
import os

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from dashboard.backend.bus import bus

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "..", "frontend", "index.html")

app = FastAPI(title="GhostNet dashboard bridge")
STATE = {"session": False}


@app.get("/health")
def health():
    return {"backend": "up", "session": STATE["session"],
            "events": len(bus.history())}


@app.get("/snapshot")
def snapshot():
    return JSONResponse({"events": bus.history(), "session": STATE["session"]})


@app.get("/events")
async def events():
    q = bus.subscribe()

    async def gen():
        try:
            for ev in bus.history():
                yield f"data: {json.dumps(ev)}\n\n"
            while True:
                try:
                    ev = q.get_nowait()
                    yield f"data: {json.dumps(ev)}\n\n"
                except Exception:
                    await asyncio.sleep(0.12)
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/")
def page():
    if os.path.exists(PAGE):
        return FileResponse(PAGE)
    return JSONResponse({"error": "frontend/index.html not present"}, status_code=404)

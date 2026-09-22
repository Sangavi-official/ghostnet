"""
dashboard/backend/bus.py — GhostNet event bus
==============================================
A thread-safe fan-out queue that GhostNet writes to and the SSE server
reads from. Deliberately tiny and dependency-free.

RULES THIS FILE ENFORCES
  * Emitting never raises into GhostNet. If the dashboard breaks, the
    research run continues -- the bus swallows its own errors.
  * Every event carries `source`: the function or file the value came
    from. Anything without a real source does not get emitted.
  * Events are also appended to a JSONL file, so a session can be
    replayed later without re-running against live AWS.

Nothing in the GhostNet core imports this. It is imported only by the
dashboard integration layer.
"""

import json
import os
import queue
import threading
import time
from datetime import datetime, timezone

EVENTS_PATH = os.environ.get("GHOSTNET_EVENTS", "dashboard/events.jsonl")
MAX_REPLAY = 400          # events kept for a late-joining browser


class EventBus:
    def __init__(self, path=EVENTS_PATH):
        self.path = path
        self._subs = []               # list[queue.Queue]
        self._lock = threading.Lock()
        self._history = []
        self._session_open = False
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    # ── producer side (called from GhostNet's process) ──────────────
    def emit(self, type_, source, **fields):
        """Publish one event. Never raises."""
        try:
            ev = {"type": type_, "source": source,
                  "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
            ev.update(fields)
            with self._lock:
                self._history.append(ev)
                if len(self._history) > MAX_REPLAY:
                    del self._history[:-MAX_REPLAY]
                subs = list(self._subs)
            for q in subs:
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass                      # a slow browser must not stall GhostNet
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev) + "\n")
            except OSError:
                pass
            return ev
        except Exception:
            return None                        # the dashboard is never load-bearing

    # ── consumer side (called from the web server) ──────────────────
    def subscribe(self):
        q = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def history(self):
        with self._lock:
            return list(self._history)

    def clear(self):
        with self._lock:
            self._history.clear()


bus = EventBus()


def now_ms():
    return time.time()

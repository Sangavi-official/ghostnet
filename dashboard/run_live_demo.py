"""
dashboard/run_live_demo.py
===========================
Runs the REAL GhostNet demonstration and streams what it does to the
dashboard. This is a sibling of run_phase3.py, not a replacement:
run_phase3.py is untouched and still works on its own.

    python -m dashboard.run_live_demo              # 20 steps, real AWS + IoT
    python -m dashboard.run_live_demo --steps 10
    python -m dashboard.run_live_demo --no-cloud --no-iot   # env only
    python -m dashboard.run_live_demo --pause 4             # slower, for presenting

Open http://127.0.0.1:8765 while it runs.

The web server runs in a daemon thread. If it fails to start, the
GhostNet run proceeds anyway and prints normally -- the dashboard is
never allowed to be load-bearing.
"""

import argparse
import sys
import threading
import time

from stable_baselines3 import PPO

from dashboard.backend.bus import bus
from dashboard.integration.instrumented_env import InstrumentedEnvV3, ACTION_NAMES

HOST, PORT = "127.0.0.1", 8765


def serve():
    try:
        import uvicorn
        from dashboard.backend import server
        server.STATE["session"] = True
        uvicorn.run(server.app, host=HOST, port=PORT, log_level="warning")
    except Exception as e:
        print(f"  [DASH] server not started: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="ghostnet_smart")
    ap.add_argument("--steps", type=int, default=20)
    ap.add_argument("--no-cloud", action="store_true")
    ap.add_argument("--no-iot", action="store_true")
    ap.add_argument("--no-serve", action="store_true")
    ap.add_argument("--deterministic", action="store_true")
    ap.add_argument("--pause", type=float, default=0.4,
                    help="seconds to wait between steps (presentation pacing)")
    a = ap.parse_args()

    if not a.no_serve:
        threading.Thread(target=serve, daemon=True).start()
        time.sleep(1.0)
        print(f"  [DASH] dashboard on http://{HOST}:{PORT}")

    print("=" * 60)
    print("  GhostNet — live demonstration (instrumented)")
    print("=" * 60)

    model = PPO.load(a.model)
    bus.emit("session_start", "dashboard.run_live_demo",
             model=a.model, steps=a.steps,
             deterministic=bool(a.deterministic))

    env = InstrumentedEnvV3(use_live_feeds=True,
                            use_real_cloud=not a.no_cloud,
                            use_real_iot=not a.no_iot)
    obs, _ = env.reset()
    env.emit_surface()

    total = 0.0
    print(f"\n  {'Step':>4}  {'Action':<20}  {'Reward':>7}")
    print("  " + "-" * 40)
    for i in range(1, a.steps + 1):
        action, _ = model.predict(obs, deterministic=a.deterministic)
        obs, reward, done, _, _ = env.step(int(action))
        total += reward
        print(f"  {i:>4}  {ACTION_NAMES[int(action)]:<20}  {reward:>7.3f}")
        env.emit_surface()
        time.sleep(a.pause)
        if done:
            obs, _ = env.reset()

    env.emit_session_end()
    s = env.get_cloud_stats()
    print("  " + "-" * 40)
    print(f"  Total reward       : {total:.3f}")
    print(f"  Real AWS mutations : {s['real_mutations']}")
    print(f"  Failed mutations   : {s['failed_mutations']}")

    if not a.no_serve:
        print("\n  [DASH] run complete — dashboard still serving. Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main())

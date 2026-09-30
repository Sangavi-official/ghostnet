"""
gmcp_sim.py — offline evaluation of the coordination protocol
==============================================================
Compares three ways of relocating the device's rendezvous point, over a
simulated control channel that loses each message with probability p.
p stands for every way a control message fails in practice: dropped
connections, controller connect timeouts (the failure in
logs/e8b_announced_hop.txt), broker restarts, device reboots.

  naive      move the broker; no notice (the original hop)
  announced  one relocation notice on the old listener, then move and
             close the old listener (iot_mutator.py as deployed)
  gmcp       make-before-break: open the new listener, run a signed
             PREPARE/COMMIT exchange with retries (gmcp.py), confirm
             telemetry on the new listener, only then close the old one

The GMCP arm runs the real gmcp.Controller / gmcp.Device code.

Topic rotation is compared the same way (single unacknowledged control
message vs GMCP), and a security test replays the attacks an adversary
with publish access to the broker could mount.

Limits, stated plainly: this is a simulation of the control channel,
not a measurement on the EC2 deployment. Timing constants are taken
from the deployed code (restart 3 s, grace 5 s, telemetry every 5 s).

    python gmcp_sim.py
    python gmcp_sim.py --trials 5000
"""

import argparse
import json

import numpy as np

import gmcp

RESULTS        = "gmcp_sim_results.json"
LOSS_RATES     = (0.0, 0.05, 0.10, 0.20, 0.30, 0.50)
PORT_RANGE     = (8200, 8999)
FALLBACK_PORTS = (1883, 8319, 8888)   # device_v2.py
LATENCY        = 0.05                 # one-way control-message delay, s
RESTART        = 3.0                  # mosquitto restart, s (iot_mutator.py)
GRACE          = 5.0                  # relocation-notice grace, s
RECONNECT      = 1.0                  # device reconnect, s
TELEMETRY      = 5.0                  # pump publish period, s
VERIFY_WAIT    = 20.0                 # controller waits this long for telemetry
KEY            = b"per-device-key-provisioned-at-install"


class Clock:
    def __init__(self):
        self.t = 1_000.0
    def __call__(self):
        return self.t


def link(ctrl, device, p, rng, clock, on_effect):
    """Lossy controller <-> device channel for gmcp.run_transaction."""
    inbox = []

    def send(msg):
        clock.t += LATENCY
        if rng.random() >= p:                       # reached the device
            reply, effect = device.handle(msg)
            if effect:
                on_effect(effect)
            if reply is not None and rng.random() >= p:
                inbox.append(reply)                 # ACK reached the controller

    def recv(seq, status, timeout):
        for m in inbox:
            if ctrl.is_ack(m, seq, status):
                inbox.remove(m)
                clock.t += LATENCY
                return True
        clock.t += timeout
        return False

    return send, recv


def first_telemetry_wait(rng):
    """Time until the pump's next publish, given a random phase."""
    return rng.uniform(0, TELEMETRY)


# ─── broker relocation ─────────────────────────────────────────────────
def broker_move(scheme, p, rng):
    """Returns dict: outcome moved|unchanged|stranded, gap_s, msgs, time_s."""
    old = 1883
    new = int(rng.integers(PORT_RANGE[0], PORT_RANGE[1] + 1))

    if scheme == "naive":
        # Broker moves; device finds out only by losing its connection.
        if new in FALLBACK_PORTS:
            return {"outcome": "moved", "gap_s": RESTART + RECONNECT, "msgs": 0, "time_s": RESTART}
        return {"outcome": "stranded", "gap_s": None, "msgs": 0, "time_s": RESTART}

    if scheme == "announced":
        heard = rng.random() >= p
        t = GRACE + RESTART
        if heard or new in FALLBACK_PORTS:
            gap = RESTART + RECONNECT + first_telemetry_wait(rng)
            return {"outcome": "moved", "gap_s": gap, "msgs": 1, "time_s": t}
        return {"outcome": "stranded", "gap_s": None, "msgs": 1, "time_s": t}

    # gmcp: make before break
    clock = Clock()
    listeners = {old, new}                          # new listener opened first
    dev_state = {"port": old, "moved_at": None}
    ctrl = gmcp.Controller("pump1", KEY, clock)
    dev = gmcp.Device("pump1", KEY, clock)

    def on_effect(cmd):
        if cmd["action"] == "broker_move" and cmd["new_port"] in listeners:
            dev_state["port"] = cmd["new_port"]
            dev_state["moved_at"] = clock.t

    send, recv = link(ctrl, dev, p, rng, clock, on_effect)
    t0 = clock.t
    outcome, _, sent = gmcp.run_transaction(ctrl, send, recv,
                                            {"action": "broker_move", "new_port": new})
    # Ground truth decides, not the ACK: is telemetry arriving on the new port?
    if outcome in ("committed", "uncertain") and dev_state["port"] == new:
        listeners.discard(old)                      # break only after make
        gap = RECONNECT + first_telemetry_wait(rng)
        result = "moved"
    else:
        listeners.discard(new)                      # nothing changed
        gap, result = 0.0, "unchanged"
    if dev_state["port"] not in listeners:
        result, gap = "stranded", None
    return {"outcome": result, "gap_s": gap, "msgs": sent, "time_s": clock.t - t0}


# ─── topic rotation ────────────────────────────────────────────────────
def topic_rotation(scheme, p, rng):
    """Returns dict: outcome rotated|unchanged, msgs, time_s (to confirmation)."""
    if scheme == "single":
        if rng.random() >= p:
            return {"outcome": "rotated", "msgs": 1, "time_s": LATENCY + first_telemetry_wait(rng)}
        return {"outcome": "unchanged", "msgs": 1, "time_s": VERIFY_WAIT}

    clock = Clock()
    state = {"topic": "old"}
    ctrl = gmcp.Controller("pump1", KEY, clock)
    dev = gmcp.Device("pump1", KEY, clock)

    def on_effect(cmd):
        if cmd["action"] == "rotate_topic":
            state["topic"] = cmd["new_topic"]

    send, recv = link(ctrl, dev, p, rng, clock, on_effect)
    t0 = clock.t
    outcome, _, sent = gmcp.run_transaction(ctrl, send, recv,
                                            {"action": "rotate_topic", "new_topic": "new"})
    if state["topic"] == "new":
        return {"outcome": "rotated", "msgs": sent,
                "time_s": clock.t - t0 + first_telemetry_wait(rng)}
    return {"outcome": "unchanged", "msgs": sent, "time_s": clock.t - t0}


# ─── security ──────────────────────────────────────────────────────────
def naive_device_accepts(msg):
    """device_v2.py: any well-formed JSON with a known action is obeyed."""
    return isinstance(msg, dict) and msg.get("action") in ("rotate_topic", "broker_move")


def security_tests():
    """Each attack against the deployed scheme and against GMCP."""
    clock = Clock()
    ctrl = gmcp.Controller("pump1", KEY, clock)
    dev = gmcp.Device("pump1", KEY, clock)
    applied = []

    def deliver(msg):
        _, effect = dev.handle(msg)
        if effect:
            applied.append(effect)
        return effect is not None

    # A legitimate rotation, recorded by an eavesdropper on the broker.
    cmd = {"action": "rotate_topic", "new_topic": "hospital/icu/vitals/pk3x9a2"}
    seq = ctrl.new_seq()
    rec_prepare, rec_commit = ctrl.prepare(seq, cmd), ctrl.commit(seq)
    deliver(rec_prepare); deliver(rec_commit)
    # A cancelled rotation, also recorded.
    seq2 = ctrl.new_seq()
    ab_prepare = ctrl.prepare(seq2, {"action": "rotate_topic", "new_topic": "t2"})
    ab_commit = ctrl.commit(seq2)
    deliver(ab_prepare); deliver(ctrl.abort(seq2))
    clock.t += 5

    evil = {"action": "rotate_topic", "new_topic": "attacker/collect"}
    forged = {"v": 1, "dev": "pump1", "seq": 99, "ts": clock(), "type": "prepare",
              "cmd": evil, "mac": "0" * 64}
    forged_commit = {**forged, "type": "commit"}
    tampered = {**rec_prepare, "cmd": evil, "seq": 50, "ts": clock()}
    tampered_commit = {**rec_commit, "seq": 50, "ts": clock()}

    tests = [
        ("forged command (no key)", evil, [forged, forged_commit]),
        ("replay of recorded rotation", cmd, [rec_prepare, rec_commit]),
        ("replay of cancelled rotation", evil, [ab_prepare, ab_commit]),
        ("tampered recorded command", evil, [tampered, tampered_commit]),
        ("broker-move to stranding port", {"action": "broker_move", "new_port": 8999},
         [{**forged, "cmd": {"action": "broker_move", "new_port": 8999}}, forged_commit]),
    ]
    rows = []
    for name, naive_msg, gmcp_msgs in tests:
        before = len(applied)
        for m in gmcp_msgs:
            deliver(m)
        rows.append({"attack": name,
                     "deployed_scheme": "ACCEPTED" if naive_device_accepts(naive_msg) else "rejected",
                     "gmcp": "ACCEPTED" if len(applied) > before else "rejected"})
    return rows, dict(dev.rejected)


# ─── main ──────────────────────────────────────────────────────────────
def summarise(rows, key_ok):
    n = len(rows)
    out = {}
    for o in sorted({r["outcome"] for r in rows} | {key_ok}):
        out[f"pct_{o}"] = 100 * sum(r["outcome"] == o for r in rows) / n
    gaps = [r["gap_s"] for r in rows if r.get("gap_s") is not None and r["outcome"] == key_ok]
    if gaps:
        out["mean_gap_s"] = float(np.mean(gaps))
    out["mean_msgs"] = float(np.mean([r["msgs"] for r in rows]))
    out["mean_time_s"] = float(np.mean([r["time_s"] for r in rows]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    a = ap.parse_args()
    results = {"trials": a.trials, "broker_move": {}, "topic_rotation": {}}

    print("=" * 86)
    print(f"  Broker relocation, {a.trials} trials per cell "
          f"(% stranded = device lost with no reachable broker)")
    print("=" * 86)
    print(f"  {'loss p':<8}" + "".join(f"{s:>26}" for s in ("naive", "announced", "gmcp")))
    print(f"  {'':<8}" + "".join(f"{'moved/unch/STRANDED %':>26}" for _ in range(3)))
    for p in LOSS_RATES:
        line = f"  {p:<8.2f}"
        for scheme in ("naive", "announced", "gmcp"):
            rng = np.random.default_rng(1000 + int(100 * p))
            s = summarise([broker_move(scheme, p, rng) for _ in range(a.trials)], "moved")
            results["broker_move"].setdefault(scheme, {})[str(p)] = s
            line += (f"{s.get('pct_moved', 0):>10.1f}/{s.get('pct_unchanged', 0):>5.1f}/"
                     f"{s.get('pct_stranded', 0):>7.1f}  ")
        print(line)
    g = results["broker_move"]["gmcp"]["0.2"]
    print(f"\n  gmcp at p=0.2: mean telemetry gap {g.get('mean_gap_s', 0):.2f} s when moved, "
          f"{g['mean_msgs']:.1f} control messages, {g['mean_time_s']:.1f} s per attempt")

    print("\n" + "=" * 86)
    print(f"  Topic rotation, {a.trials} trials per cell (% rotated; the rest stay unchanged)")
    print("=" * 86)
    print(f"  {'loss p':<8}{'single message':>22}{'gmcp':>22}")
    for p in LOSS_RATES:
        line = f"  {p:<8.2f}"
        for scheme in ("single", "gmcp"):
            rng = np.random.default_rng(2000 + int(100 * p))
            s = summarise([topic_rotation(scheme, p, rng) for _ in range(a.trials)], "rotated")
            results["topic_rotation"].setdefault(scheme, {})[str(p)] = s
            line += f"{s.get('pct_rotated', 0):>15.1f}% {s['mean_time_s']:>4.1f}s"
        print(line)
    print("  (time = mean seconds until the controller knows the outcome)")

    print("\n" + "=" * 86)
    print("  Attacks by an adversary who can publish on the broker")
    print("=" * 86)
    rows, rejected = security_tests()
    print(f"  {'attack':<34}{'deployed scheme':>18}{'GMCP':>12}")
    for r in rows:
        print(f"  {r['attack']:<34}{r['deployed_scheme']:>18}{r['gmcp']:>12}")
    print(f"  GMCP device rejection counters: {rejected}")
    results["security"] = rows

    with open(RESULTS, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Written to {RESULTS}")


if __name__ == "__main__":
    main()

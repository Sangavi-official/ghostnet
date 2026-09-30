"""
eval_seeds.py — repeated-seed evaluation with confidence intervals
===================================================================
phase5_eval.py reports a single run. A single run cannot show whether a
difference between policies is real or chance. This script repeats the
whole evaluation across N independent seeds and reports, for each
policy, the mean and a 95% confidence interval, plus a Mann-Whitney U
test of GhostNet against each baseline.

No retraining. Inference only. Uses the same environment, the same
kill chain and the same trained models as phase5_eval.py.

    python eval_seeds.py            # 10 seeds
    python eval_seeds.py --seeds 20
"""

import argparse
import json
import math
import os

import numpy as np
from stable_baselines3 import PPO

from phase5_eval import run_policy, KILL_CHAIN, STAGE_STEPS

RESULTS = "phase5_seeded_results.json"
METRICS = [("pct_steps_critical", "Critical", 100),
           ("kill_chain_precision", "Precision", 100),
           ("kill_chain_coverage", "Coverage", 100),
           ("mean_peak_exposure", "Peak exp.", 1),
           ("mean_reward", "Reward", 1)]


def ci95(v):
    """Mean and half-width of the 95% confidence interval."""
    v = np.asarray(v, dtype=float)
    if len(v) < 2:
        return float(v.mean()), 0.0
    return float(v.mean()), float(1.96 * v.std(ddof=1) / np.sqrt(len(v)))


def mannwhitney(a, b):
    """Two-sided Mann-Whitney U p-value (normal approximation, tie-corrected)."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    n1, n2 = len(a), len(b)
    allv = np.concatenate([a, b])
    order = allv.argsort()
    ranks = np.empty(len(allv), float)
    ranks[order] = np.arange(1, len(allv) + 1)
    # average ranks for ties
    _, inv, cnt = np.unique(allv, return_inverse=True, return_counts=True)
    for i, c in enumerate(cnt):
        if c > 1:
            ranks[inv == i] = ranks[inv == i].mean()
    r1 = ranks[:n1].sum()
    u1 = r1 - n1 * (n1 + 1) / 2
    u = min(u1, n1 * n2 - u1)
    mu = n1 * n2 / 2
    _, cnt2 = np.unique(allv, return_counts=True)
    tie = (cnt2 ** 3 - cnt2).sum()
    n = n1 + n2
    sd = np.sqrt(n1 * n2 / 12 * ((n + 1) - tie / (n * (n - 1))))
    if sd == 0:
        return 1.0
    z = abs(u - mu) / sd
    # two-sided normal tail
    p = math.erfc(z / math.sqrt(2))
    return float(min(1.0, p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--episodes", type=int, default=10)
    a = ap.parse_args()

    policies = [("Static (no defence)", None, True),
                ("Random mutation", lambda o, r: r.integers(0, 6), False),
                ("Round-robin MTD", "rr", False)]
    for tag, path, name in (("ppo_collapsed", "ghostnet_final.zip", "PPO collapsed (baseline)"),
                            ("ppo_ghostnet", "ghostnet_smart.zip", "PPO GhostNet")):
        if os.path.exists(path):
            m = PPO.load(path, device="cpu")
            policies.append((name, lambda o, r, m=m: m.predict(o, deterministic=True)[0], False))
        else:
            print(f"  [skip] {path} not found")
    policies.append(("Oracle (upper bound)", lambda o, r: int(np.argmax(o[:5])), False))

    print("=" * 84)
    print(f"  Seeded evaluation — {a.seeds} seeds x {a.episodes} episodes "
          f"x {len(KILL_CHAIN)*STAGE_STEPS} steps")
    print("=" * 84)

    raw = {}
    for label, pick, static in policies:
        per_seed = []
        for s in range(a.seeds):
            if pick == "rr":                     # fresh counter each seed
                st = {"i": 0}
                def fn(o, r, st=st):
                    v = st["i"] % 5; st["i"] += 1; return v
            else:
                fn = pick
            out = run_policy(label, fn, a.episodes, False, seed=s, static=static)
            per_seed.append(out["summary"])
        raw[label] = per_seed
        print(f"  [done] {label}")

    print()
    print("=" * 84)
    print(f"  {'Policy':<26}" + "".join(f"{n:>17}" for _, n, _ in METRICS[:3]))
    print("  " + "-" * 80)
    table = {}
    for label, rows in raw.items():
        cells, store = "", {}
        for key, _, scale in METRICS[:3]:
            v = [r[key] * scale for r in rows]
            m, h = ci95(v)
            store[key] = {"mean": round(m, 3), "ci95": round(h, 3), "values": v}
            cells += f"{m:>11.1f} ±{h:<4.1f}"
        table[label] = store
        print(f"  {label:<26}{cells}")

    print()
    print("  Mann-Whitney U, GhostNet vs each baseline (precision):")
    gn = [r["kill_chain_precision"] for r in raw.get("PPO GhostNet", [])]
    stats = {}
    if gn:
        for label, rows in raw.items():
            if label == "PPO GhostNet":
                continue
            p = mannwhitney(gn, [r["kill_chain_precision"] for r in rows])
            stats[label] = p
            print(f"    vs {label:<28} p = {p:.5f}  {'significant' if p < 0.05 else 'not significant'}")

    with open(RESULTS, "w") as f:
        json.dump({"seeds": a.seeds, "episodes": a.episodes,
                   "table": table, "mannwhitney_precision_vs_ghostnet": stats}, f, indent=2)
    print(f"\n  Written to {RESULTS}")


if __name__ == "__main__":
    main()

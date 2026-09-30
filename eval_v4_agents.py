"""
eval_v4_agents.py — every trained agent vs the rule baselines, v4 world
========================================================================
Every policy plays the SAME test games: the AIIMS kill chain, test seeds
0..N-1 (same starting state and threat feeds per seed). No agent saw the
AIIMS chain during training.

Groups (found automatically in models/v4/, named <variant>_seed<k>.zip)
  ppo           GhostNet (main model)
  dqn, a2c      rival learning algorithms
  ppo-nofeeds   ablation: threat-feed inputs hidden
  ppo-nohold    ablation: must mutate every step
  ppo-fwrand    robust training (firewall strength random during training;
                tested in the same fixed world as everyone else)
  plus the original v2 model ghostnet_smart.zip, run unchanged in the v4
  world (6 actions, never holds). It was trained in a different world,
  so it is a reference point, not a fair rival.

Reported
  1. Per-model results, with a COLLAPSE CHECK: a model that uses one
     action in more than 90% of steps is flagged, never hidden.
  2. Each group averaged across its models (95% CI across training
     seeds), next to the rules (95% CI across test games).
  3. Paired comparisons. For each test game: value(A) - value(B), where a
     group's value is its mean over models. A bootstrap over test games
     gives a 95% CI of the difference. CI excluding 0 -> "real".

    python eval_v4_agents.py
    python eval_v4_agents.py --episodes 100
"""

import argparse
import glob
import json
import os
import re
from collections import defaultdict

import numpy as np
import torch
from stable_baselines3 import A2C, DQN, PPO

from eval_v4 import run, static, rand, round_robin, greedy, threshold
from ghostnet_env_v4 import ACTION_NAMES
from train_v4 import TRAIN_ONLY, VARIANTS

RESULTS   = "eval_v4_agents.json"
MODEL_DIR = os.path.join("models", "v4")
V2_MODEL  = "ghostnet_smart.zip"
TAU       = 0.3              # threshold tuned on training chains by eval_v4.py
COLLAPSE  = 0.90             # one action in more than 90% of steps
MAIN      = "ppo"

METRICS = [("attacks", "Attacks"), ("succeeded", "Breaches"),
           ("pct_inside", "Inside %"), ("mutations", "Mutations"),
           ("disruption", "Disruption"), ("reward", "Reward")]
COMPARE = ("attacks", "succeeded", "pct_inside", "mutations", "disruption", "reward")

# two-sided 95% t critical values, df = n - 1
T95 = {1: 12.71, 2: 4.30, 3: 3.18, 4: 2.78, 5: 2.57, 6: 2.45, 7: 2.36,
       8: 2.31, 9: 2.26, 10: 2.23, 14: 2.14, 19: 2.09, 29: 2.05}


def ci(values):
    v = np.asarray(values, float)
    if len(v) < 2:
        return float(v.mean()), 0.0
    t = T95.get(len(v) - 1, 1.96)
    return float(v.mean()), float(t * v.std(ddof=1) / np.sqrt(len(v)))


def bootstrap_diff(diff, n_boot=10_000, seed=0):
    """Mean of paired differences and its 95% bootstrap CI."""
    diff = np.asarray(diff, float)
    rng = np.random.default_rng(seed)
    means = rng.choice(diff, (n_boot, len(diff)), replace=True).mean(axis=1)
    return float(diff.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def agent_policy(model):
    def pick(o, r, st):
        return int(model.predict(o, deterministic=True)[0])
    return pick


def find_models():
    """{variant: [paths sorted by seed]}"""
    groups = defaultdict(list)
    for p in glob.glob(os.path.join(MODEL_DIR, "*_seed*.zip")):
        m = re.match(r"(.+)_seed(\d+)\.zip$", os.path.basename(p))
        if m and m.group(1) in VARIANTS:
            groups[m.group(1)].append((int(m.group(2)), p))
    return {v: [p for _, p in sorted(ps)] for v, ps in groups.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=50)
    a = ap.parse_args()
    torch.set_num_threads(1)
    seeds = range(a.episodes)
    loaders = {PPO: PPO.load, DQN: DQN.load, A2C: A2C.load}

    groups = find_models()
    if not groups:
        raise SystemExit(f"No models in {MODEL_DIR}. Run train_v4.py first.")
    order = [v for v in VARIANTS if v in groups]

    # 1. Each trained model -------------------------------------------------
    print(f"  AIIMS chain, {a.episodes} test games per model\n")
    print(f"  {'model':<22}{'Breaches':>10}{'Inside %':>10}{'Mutations':>11}"
          f"{'Reward':>9}   most-used action")
    per_model = {}                       # name -> summary
    per_game = defaultdict(list)         # group -> [rows per model]

    def evaluate(group, name, model, env_kw):
        rows = run(agent_policy(model), "aiims", seeds, **env_kw)
        acts = np.sum([[r[f"act_{i}"] for i in range(7)] for r in rows], axis=0)
        top = int(acts.argmax()); share = acts[top] / acts.sum()
        m = {k: float(np.mean([r[k] for r in rows])) for k, _ in METRICS}
        m["action_share"] = (acts / acts.sum()).round(3).tolist()
        m["collapsed"] = bool(share > COLLAPSE)
        per_model[name] = m
        per_game[group].append(rows)
        flag = "  <-- COLLAPSED" if m["collapsed"] else ""
        print(f"  {name:<22}{m['succeeded']:>10.2f}{m['pct_inside']:>10.1f}"
              f"{m['mutations']:>11.1f}{m['reward']:>9.1f}   "
              f"{ACTION_NAMES[top]} {100 * share:.0f}%{flag}")

    for v in order:
        algo, _, env_kw = VARIANTS[v]
        env_kw = {k: x for k, x in env_kw.items() if k not in TRAIN_ONLY}
        for p in groups[v]:
            evaluate(v, os.path.basename(p)[:-4], loaders[algo](p, device="cpu"), env_kw)
    if os.path.exists(V2_MODEL):
        evaluate("ppo-v2-original", "ghostnet_smart (v2)", PPO.load(V2_MODEL, device="cpu"), {})

    # 2. Groups vs rules -------------------------------------------------------
    rules = [("Static (no defence)", static), ("Random", rand),
             ("Round-robin", round_robin), ("Greedy (every step)", greedy),
             (f"Threshold (tau={TAU})", threshold(TAU))]
    for n, p in rules:
        per_game[n] = [run(p, "aiims", seeds)]

    def label(g):
        k = len(per_game[g])
        return f"{g} ({k} seeds)" if g in VARIANTS else g

    print(f"\n  {'Policy':<26}" + "".join(f"{n:>15}" for _, n in METRICS))
    print("  " + "-" * (26 + 15 * len(METRICS)))
    table = {}
    for g in [n for n, _ in rules] + order + ["ppo-v2-original"]:
        if g not in per_game:
            continue
        runs = per_game[g]
        if len(runs) == 1:           # rule or single model: CI across games
            row = {k: ci([r[k] for r in runs[0]]) for k, _ in METRICS}
        else:                        # trained group: CI across training seeds
            row = {k: ci([np.mean([r[k] for r in rows]) for rows in runs]) for k, _ in METRICS}
        table[label(g)] = row
        print(f"  {label(g):<26}" + "".join(f"{row[k][0]:>9.2f} ±{row[k][1]:<4.2f}" for k, _ in METRICS))
    print("  (rules and single models: CI across test games; groups: CI across training seeds)")

    # 3. Paired comparisons ---------------------------------------------------
    def game_values(g, k):
        return np.mean([[r[k] for r in rows] for rows in per_game[g]], axis=0)

    pairs = [(MAIN, "Greedy (every step)"), (MAIN, f"Threshold (tau={TAU})"),
             (MAIN, "Round-robin")]
    pairs += [(v, MAIN) for v in order if v != MAIN]
    pairs += [("ppo-v2-original", MAIN)]

    print("\n  Paired differences A - B over test games, mean [95% CI]")
    print("  (lower is better for attacks, breaches, inside %, disruption; higher for reward)")
    comps = {}
    for A, B in pairs:
        if A not in per_game or B not in per_game:
            continue
        comps[f"{A} vs {B}"] = {}
        print(f"\n    {A}  vs  {B}")
        for k in COMPARE:
            mean, lo, hi = bootstrap_diff(game_values(A, k) - game_values(B, k))
            verdict = "real" if (lo > 0 or hi < 0) else "could be luck"
            comps[f"{A} vs {B}"][k] = {"mean": mean, "ci95": [lo, hi], "verdict": verdict}
            print(f"      {k:<11} {mean:+9.3f}  [{lo:+.3f}, {hi:+.3f}]  {verdict}")

    with open(RESULTS, "w") as f:
        json.dump({"episodes": a.episodes, "models": per_model,
                   "table": table, "paired": comps}, f, indent=2)
    print(f"\n  Written to {RESULTS}")


if __name__ == "__main__":
    main()

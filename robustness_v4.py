"""
robustness_v4.py — do the conclusions survive a different world?
=================================================================
The v4 world settings are modelling assumptions, frozen before training.
This script re-tests the SAME trained agents (no retraining) and the
rule baselines when one assumption at a time is changed:

  firewall weaker    FIREWALL_CUT 0.10 / 0.05 / 0.0
                     (the live firewall only helps when the AbuseIPDB
                     blocklist changes, so the trained value may be
                     optimistic; 0.0 = the firewall does nothing at all)
  attacker speed     PRESSURE_RATE 0.20 / 0.35
  IDS blur           OBS_NOISE 0.0 / 0.20
  exploit time       EXPLOIT_STEPS 2

The first row, "as trained", must reproduce eval_v4_agents.py exactly.

    python robustness_v4.py
    python robustness_v4.py --episodes 30 --jobs 4
"""

import argparse
import glob
import json
import os
from concurrent.futures import ProcessPoolExecutor

import numpy as np

SETTINGS = [
    ("as trained",           {}),
    ("firewall cut 0.10",    {"FIREWALL_CUT": 0.10}),
    ("firewall cut 0.05",    {"FIREWALL_CUT": 0.05}),
    ("firewall does nothing", {"FIREWALL_CUT": 0.0}),
    ("attacker slower 0.20", {"PRESSURE_RATE": 0.20}),
    ("attacker faster 0.35", {"PRESSURE_RATE": 0.35}),
    ("perfect view (no blur)", {"OBS_NOISE": 0.0}),
    ("blurrier view 0.20",   {"OBS_NOISE": 0.20}),
    ("exploit takes 2 steps", {"EXPLOIT_STEPS": 2}),
]
GROUPS = ("ppo", "dqn", "ppo-fwrand")    # a group is skipped if it has no models
METRICS = ("succeeded", "pct_inside", "disruption")
RESULTS = "robustness_v4.json"


def evaluate_setting(args):
    """Runs in a worker process: apply overrides, evaluate everyone."""
    name, overrides, episodes = args
    import torch
    torch.set_num_threads(1)
    import ghostnet_env_v4
    for k, v in overrides.items():
        setattr(ghostnet_env_v4, k, v)
    from stable_baselines3 import DQN, PPO
    from eval_v4 import greedy, round_robin, run, threshold
    from eval_v4_agents import TAU, agent_policy

    seeds = range(episodes)
    per_game = {}
    for label, pol in (("Round-robin", round_robin), ("Greedy", greedy),
                       (f"Threshold {TAU}", threshold(TAU))):
        per_game[label] = [run(pol, "aiims", seeds)]
    loaders = {"ppo": PPO.load, "dqn": DQN.load, "ppo-fwrand": PPO.load}
    for g in GROUPS:
        paths = sorted(glob.glob(os.path.join("models", "v4", f"{g}_seed*.zip")))
        if paths:
            per_game[g.upper()] = [run(agent_policy(loaders[g](p, device="cpu")), "aiims", seeds)
                                   for p in paths]
    # per-game values (mean over models for groups)
    out = {}
    for label, runs in per_game.items():
        out[label] = {k: np.mean([[r[k] for r in rows] for rows in runs], axis=0).tolist()
                      for k in METRICS}
    return name, overrides, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=50)
    ap.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()
    from eval_v4_agents import bootstrap_diff

    tasks = [(n, o, a.episodes) for n, o in SETTINGS]
    with ProcessPoolExecutor(max_workers=a.jobs) as pool:
        results = list(pool.map(evaluate_setting, tasks))

    store = {}
    for metric, title in (("succeeded", "Breaches per game"),
                          ("pct_inside", "% of time the attacker is inside"),
                          ("disruption", "Disruption to the hospital")):
        print(f"\n  {title} (AIIMS chain, {a.episodes} games; PPO/DQN = mean of 10 models)")
        labels = list(results[0][2])
        print(f"  {'setting':<24}" + "".join(f"{l:>14}" for l in labels)
              + "     PPO - Greedy [95% CI]")
        print("  " + "-" * (24 + 14 * len(labels) + 40))
        for name, overrides, out in results:
            means = {l: float(np.mean(out[l][metric])) for l in labels}
            d, lo, hi = bootstrap_diff(np.array(out["PPO"][metric]) - np.array(out["Greedy"][metric]))
            verdict = "real" if (lo > 0 or hi < 0) else "could be luck"
            print(f"  {name:<24}" + "".join(f"{means[l]:>14.2f}" for l in labels)
                  + f"     {d:+.2f} [{lo:+.2f}, {hi:+.2f}] {verdict}")
            store.setdefault(name, {"overrides": overrides})[metric] = {
                "means": means, "ppo_minus_greedy": {"mean": d, "ci95": [lo, hi], "verdict": verdict}}

    with open(RESULTS, "w") as f:
        json.dump({"episodes": a.episodes, "settings": store}, f, indent=2)
    print(f"\n  Written to {RESULTS}")


if __name__ == "__main__":
    main()

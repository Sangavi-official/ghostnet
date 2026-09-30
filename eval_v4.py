"""
eval_v4.py — rule-based players in the v4 practice world
=========================================================
Before training anything, check the world is fair: a policy that does
nothing must lose, sensible rules must do better, and the metrics must
be able to tell different policies apart.

Players
  Static          never mutates (hold every step)
  Random          uniform over all 7 actions
  Round-robin     cycles actions 0-4, one mutation every step
  Greedy          always moves the most-exposed surface
  Threshold       moves the most-exposed surface only if it is above tau,
                  otherwise holds. tau is tuned on TRAINING chains/seeds,
                  never on the test chain.

Test set: the AIIMS kill chain, feeds sampled per episode, seeds 0..N-1.
Tuning set: random chains, seeds 10_000+ (disjoint from test).

    python eval_v4.py
    python eval_v4.py --episodes 50
    python eval_v4.py --pressure 0.20      # attacker-speed sensitivity
"""

import argparse
import json

import numpy as np

import ghostnet_env_v4
from ghostnet_env_v4 import GhostNetEnvV4, HOLD, N_SURFACES

RESULTS = "eval_v4_rules.json"


def run(policy, chain, seeds, **env_kwargs):
    env = GhostNetEnvV4(chain=chain, **env_kwargs)
    rows = []
    for seed in seeds:
        obs, _ = env.reset(seed=int(seed))
        rng = np.random.default_rng(seed)
        state = {"i": 0}
        tot = {"reward": 0.0, "hot": 0, "inside": 0, "mut": 0, "disr": 0.0}
        acts = np.zeros(7, int)
        done = False
        while not done:
            a = int(policy(obs, rng, state))
            acts[a] += 1
            obs, rew, done, _, info = env.step(a)
            tot["reward"] += rew
            tot["hot"]    += info["n_hot"] > 0
            tot["inside"] += info["n_compromised"] > 0
            tot["mut"]    += info["mutated"]
            tot["disr"]   += info["disruption"]
        n, atk = env.max_steps, info["attack"]
        rows.append({"reward": tot["reward"],
                     "attacks": atk["launched"],
                     "succeeded": atk["succeeded"],
                     # share of launched exploits that landed (0 if none launched)
                     "success_pct": 100 * atk["succeeded"] / max(1, atk["launched"]),
                     # share of steps with the attacker holding a foothold
                     "pct_inside": 100 * tot["inside"] / n,
                     # steps until the first foothold (episode length if never)
                     "t_first": atk["first_compromise"] or n,
                     "pct_hot": 100 * tot["hot"] / n,
                     "mutations": tot["mut"],
                     "disruption": tot["disr"],
                     **{f"act_{i}": int(c) for i, c in enumerate(acts)}})
    return rows


def static(o, r, st):  return HOLD
def rand(o, r, st):    return int(r.integers(0, 7))
def greedy(o, r, st):  return int(np.argmax(o[:N_SURFACES]))

def round_robin(o, r, st):
    a = st["i"] % N_SURFACES
    st["i"] += 1
    return a

def threshold(tau):
    def pick(o, r, st):
        i = int(np.argmax(o[:N_SURFACES]))
        return i if o[i] > tau else HOLD
    return pick


def summary(rows):
    out = {}
    for k in rows[0]:
        v = np.array([x[k] for x in rows], float)
        out[k] = (float(v.mean()), float(1.96 * v.std(ddof=1) / np.sqrt(len(v))))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--episodes", type=int, default=30)
    ap.add_argument("--pressure", type=float, default=None,
                    help="override attacker speed (PRESSURE_RATE)")
    a = ap.parse_args()
    if a.pressure is not None:
        ghostnet_env_v4.PRESSURE_RATE = a.pressure
    print(f"  attacker speed (PRESSURE_RATE) = {ghostnet_env_v4.PRESSURE_RATE}")

    # Tune tau on training conditions only
    tune_seeds = range(10_000, 10_000 + a.episodes)
    best_tau, best = None, -1e9
    for tau in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7):
        m = np.mean([x["reward"] for x in run(threshold(tau), "random", tune_seeds)])
        if m > best:
            best_tau, best = tau, m
    print(f"  tuned threshold on random chains: tau = {best_tau}")

    players = [("Static (no defence)", static),
               ("Random", rand),
               ("Round-robin", round_robin),
               ("Greedy (every step)", greedy),
               (f"Threshold (tau={best_tau})", threshold(best_tau))]

    test_seeds = range(a.episodes)
    cols = [("attacks", "Attacks"), ("succeeded", "Breaches"),
            ("success_pct", "Success %"), ("pct_inside", "Inside %"),
            ("mutations", "Mutations"), ("disruption", "Disruption"),
            ("reward", "Reward")]
    print(f"\n  AIIMS kill chain, {a.episodes} episodes, mean ± 95% CI")
    print("  " + f"{'Player':<24}" + "".join(f"{n:>15}" for _, n in cols))
    print("  " + "-" * (24 + 15 * len(cols)))
    results = {}
    for name, pol in players:
        s = summary(run(pol, "aiims", test_seeds))
        results[name] = s
        print("  " + f"{name:<24}" + "".join(f"{s[k][0]:>9.1f} ±{s[k][1]:<4.1f}" for k, _ in cols))

    with open(RESULTS, "w") as f:
        json.dump({"tau": best_tau, "episodes": a.episodes,
                   "pressure": ghostnet_env_v4.PRESSURE_RATE,
                   "results": results}, f, indent=2)
    print(f"\n  Written to {RESULTS}")


if __name__ == "__main__":
    main()

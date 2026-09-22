"""
phase5_eval.py — GhostNet Phase 5: Adversarial Evaluation (corrected)
======================================================================
Evaluates the defence policy against a staged ATT&CK kill chain.

WHAT CHANGED AND WHY
  1. MODEL_PATH was best_model/best_model.zip, falling back to
     ghostnet_final.zip -- both are the COLLAPSED policy (one action for
     every state). Now defaults to ghostnet_smart.zip.
  2. The "static defence" baseline used action 0, which is
     rotate_cloud_ip -- a real mutation. It is now a true no-defence
     control: surfaces are never reduced.
  3. mutation_ct counted `action != 0`, silently discarding every
     action-0 mutation. All six actions now count.
  4. attack_success_rate tested obs[11] as "ransomware risk". Index 11
     is attck_score. Attack pressure is now measured on the five real
     attack surfaces (indices 0-4).
  5. The kill chain advanced on WALL-CLOCK time in a background thread
     while env steps ran at CPU speed, so stage alignment varied run to
     run. Stages now advance on STEP COUNT: deterministic and
     reproducible.
  6. Evaluation runs OFFLINE by default. The previous configuration
     (3 scenarios x 10 episodes x 200 steps, use_real_cloud=True) meant
     ~6000 live AWS calls. Real-infrastructure behaviour is demonstrated
     separately by run_phase3.py.

Run:
    python phase5_eval.py                  # offline, reproducible
    python phase5_eval.py --live-feeds     # real threat feeds
"""

import json
import sys

import numpy as np
from stable_baselines3 import PPO

from caldera_ttp_map import (KILL_CHAIN, TTP_BOOST_MAP, TTP_NAMES,
                             STATE_LABELS, apply_injection, expected_action)
from ghostnet_env_v2 import GhostNetEnvV2

STAGE_STEPS   = 6            # env steps per kill-chain stage
HALF_LIFE     = 12.0         # steps for a TTP's influence to halve
NUM_EPISODES  = 10
RESULTS_FILE  = "phase5_results.json"
SURFACES      = slice(0, 5)
CRITICAL      = 0.70

ACTION_NAMES = ["rotate_cloud_ip", "close_open_port", "rotate_api_path",
                "rotate_iot_ip", "rotate_mqtt_topic", "update_firewall"]


def injection_at(step):
    """Accumulated, step-decayed boosts from every TTP fired so far."""
    stage_now = min(step // STAGE_STEPS, len(KILL_CHAIN) - 1)
    inj = {}
    for k in range(stage_now + 1):
        age = step - k * STAGE_STEPS
        decay = 0.5 ** (age / HALF_LIFE)
        if decay < 0.05:
            continue
        for dim, boost in TTP_BOOST_MAP[KILL_CHAIN[k]].items():
            if dim == 9:
                continue
            inj[dim] = min(1.0, inj.get(dim, 0.0) + boost * decay)
    return inj, KILL_CHAIN[stage_now]


def stage_scores(step_log):
    """
    Two measures per stage:
      hit       -- did the agent EVER take the correct action in the stage?
      precision -- what SHARE of its actions in that stage were correct?

    `hit` alone flatters any cycling policy: round-robin visits all five
    actions inside a six-step stage, so it scores near-perfect without
    responding to the attack at all. Precision separates targeting from
    exhaustive cycling.
    """
    rows, correct, precisions = [], 0, []
    for k, ttp in enumerate(KILL_CHAIN):
        want = expected_action(TTP_BOOST_MAP[ttp])
        taken = [s["action"] for s in step_log
                 if s["stage"] == k and s["action"] is not None]
        hit = want is not None and want in taken
        prec = (sum(a == want for a in taken) / len(taken)) if taken and want is not None else 0.0
        correct += hit
        precisions.append(prec)
        rows.append({"stage": k, "ttp": ttp, "name": TTP_NAMES[ttp],
                     "expected": want, "taken": taken,
                     "hit": bool(hit), "precision": round(prec, 3)})
    return rows, correct, float(np.mean(precisions)) if precisions else 0.0


def run_policy(label, pick, episodes, live_feeds, seed=0, static=False):
    """
    static=True is the true no-defence control: the attack proceeds and
    no surface is ever mutated.
    """
    env = GhostNetEnvV2(use_live_feeds=live_feeds)
    rng = np.random.default_rng(seed)
    total_steps = len(KILL_CHAIN) * STAGE_STEPS
    eps = []

    for ep in range(episodes):
        obs, _ = env.reset(seed=int(rng.integers(1e6)))
        ep_reward, mutations, log = 0.0, 0, []

        for step in range(total_steps):
            inj, ttp = injection_at(step)
            obs_inj = np.array(apply_injection(obs, inj), dtype=np.float32)
            surfaces = obs_inj[SURFACES]

            if static:
                action = None
                # No mutation. Only the environment's own drift applies.
                obs = obs.copy()
                obs[8] = min(1.0, obs[8] + rng.uniform(0, 0.03))
                reward = 0.0
            else:
                action = int(pick(obs_inj, rng))
                mutations += 1
                obs, reward, done, _, _ = env.step(action)

            ep_reward += float(reward)
            log.append({"step": step, "stage": step // STAGE_STEPS, "ttp": ttp,
                        "action": action,
                        "peak_surface": float(surfaces.max()),
                        "mean_surface": float(surfaces.mean())})

        rows, correct, prec = stage_scores(log)
        peaks = [s["peak_surface"] for s in log]
        eps.append({
            "episode": ep,
            "episode_reward": round(ep_reward, 2),
            "mutations": mutations,
            "mean_peak_exposure": round(float(np.mean(peaks)), 4),
            "pct_steps_critical": round(float(np.mean([p > CRITICAL for p in peaks])), 4),
            "stages_correct": correct,
            "stage_precision": round(prec, 4),
            "stage_detail": rows,
        })

    summary = {
        "policy": label,
        "mean_reward": round(float(np.mean([e["episode_reward"] for e in eps])), 2),
        "mean_peak_exposure": round(float(np.mean([e["mean_peak_exposure"] for e in eps])), 4),
        "pct_steps_critical": round(float(np.mean([e["pct_steps_critical"] for e in eps])), 4),
        "kill_chain_coverage": round(float(np.mean([e["stages_correct"] for e in eps])) / len(KILL_CHAIN), 4),
        "kill_chain_precision": round(float(np.mean([e["stage_precision"] for e in eps])), 4),
        "mean_mutations": round(float(np.mean([e["mutations"] for e in eps])), 1),
    }
    print(f"  {label:<30}    {summary['mean_peak_exposure']:.3f}   "
          f"    {100*summary['pct_steps_critical']:5.1f}%   "
          f"cover {100*summary['kill_chain_coverage']:5.1f}%   "
          f"precision {100*summary['kill_chain_precision']:5.1f}%   "
          f"  {summary['mean_reward']:8.2f}")
    return {"summary": summary, "episodes": eps}


def main():
    live = "--live-feeds" in sys.argv
    print("=" * 100)
    print(f"  GhostNet Phase 5 — kill-chain evaluation "
          f"({len(KILL_CHAIN)} stages x {STAGE_STEPS} steps, {NUM_EPISODES} episodes)")
    print(f"  Threat feeds: {'LIVE' if live else 'simulated (reproducible)'}")
    print("=" * 100)
    print(f"  {'policy':<30} {'exposure':>9}  {'critical':>9}  {'coverage':>9}  "
          f"{'precision':>10}  {'reward':>8}")
    print("  " + "-" * 96)

    results = {}
    results["no_defence"] = run_policy("Static (no defence)", None,
                                       NUM_EPISODES, live, static=True)
    results["random"] = run_policy("Random mutation",
                                   lambda o, r: r.integers(0, 6), NUM_EPISODES, live)
    rr = {"i": 0}
    def round_robin(o, r):
        a = rr["i"] % 5; rr["i"] += 1; return a
    results["round_robin"] = run_policy("Round-robin MTD", round_robin,
                                        NUM_EPISODES, live)

    import os
    for tag, path in (("ppo_collapsed", "ghostnet_final.zip"),
                      ("ppo_ghostnet", "ghostnet_smart.zip")):
        if not os.path.exists(path):
            print(f"  [skip] {path} not found")
            continue
        m = PPO.load(path, device="cpu")
        name = "PPO collapsed (baseline)" if tag == "ppo_collapsed" else "PPO GhostNet (smart)"
        results[tag] = run_policy(name,
                                  lambda o, r, m=m: m.predict(o, deterministic=True)[0],
                                  NUM_EPISODES, live)

    results["oracle"] = run_policy("Oracle (most-exposed)",
                                   lambda o, r: int(np.argmax(o[:5])), NUM_EPISODES, live)

    with open(RESULTS_FILE, "w") as f:
        json.dump({k: v["summary"] for k, v in results.items()}, f, indent=2)

    if "ppo_ghostnet" in results:
        print("\n  Per-stage response — PPO GhostNet, episode 0")
        print("  " + "-" * 96)
        print(f"  {'stage':<7}{'TTP':<8}{'technique':<36}{'expected':<12}{'taken':<16}{'hit':<6}prec")
        for r in results["ppo_ghostnet"]["episodes"][0]["stage_detail"]:
            exp = f"{r['expected']}:{ACTION_NAMES[r['expected']][:9]}" if r['expected'] is not None else "-"
            taken = ",".join(str(a) for a in sorted(set(r["taken"])))
            print(f"  {r['stage']:<7}{r['ttp']:<8}{r['name'][:34]:<36}{exp:<12}{taken:<16}"
                  f"{'YES' if r['hit'] else 'no':<6}{r['precision']:.2f}")
    print(f"\n  Results written to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
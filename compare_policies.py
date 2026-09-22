"""
GhostNet — compare_policies.py
Experiment E9: the PPO policy against non-learning MTD baselines.
This is the baseline comparison the project previously lacked.

Run from the project root (needs ghostnet_env_v2.py + the model zips):
    python compare_policies.py
Simulated feeds => fully reproducible, no AWS and no API keys needed.
"""
import os
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from stable_baselines3 import PPO
from ghostnet_env_v2 import GhostNetEnvV2

EPISODES = 20
STEPS    = 200


def evaluate(pick, label, seed=0):
    env = GhostNetEnvV2(use_live_feeds=False)
    rng = np.random.default_rng(seed)
    returns, hits, steps = [], 0, 0
    for _ in range(EPISODES):
        obs, _ = env.reset(seed=int(rng.integers(1e6)))
        total, done = 0.0, False
        while not done:
            a = pick(obs, rng)
            hits += (a == int(np.argmax(obs[:5])))
            steps += 1
            obs, r, done, _, _ = env.step(a)
            total += r
        returns.append(total)
    mean, std = float(np.mean(returns)), float(np.std(returns))
    print(f"  {label:<32} {mean:8.2f} +/- {std:5.2f}   {mean / STEPS:7.3f}   "
          f"{100 * hits / steps:5.1f}%")
    return mean


def main():
    print("=" * 86)
    print(f"  Policy comparison — {EPISODES} episodes x {STEPS} steps, "
          f"exposure-weighted TADR")
    print("=" * 86)
    print(f"  {'policy':<32} {'return/ep':>8}          {'r/step':>7}   hot-hit")
    print("  " + "-" * 82)

    evaluate(lambda o, r: int(r.integers(0, 6)), "Random mutation")

    counter = {"i": 0}
    def round_robin(obs, rng):
        a = counter["i"] % 5
        counter["i"] += 1
        return a
    evaluate(round_robin, "Round-robin (fixed schedule MTD)")

    evaluate(lambda o, r: 5, "Always-firewall (broad)")

    for name in ("ghostnet_final", "ghostnet_smart"):
        path = f"{name}.zip"
        if os.path.exists(path):
            m = PPO.load(path, device="cpu")
            tag = "PPO collapsed" if name == "ghostnet_final" else "PPO fixed reward"
            evaluate(lambda o, r, m=m: int(m.predict(o, deterministic=True)[0]),
                     f"{tag} ({name})")

    evaluate(lambda o, r: int(np.argmax(o[:5])), "Oracle (always most-exposed)")
    print("  " + "-" * 82)
    print("  Oracle is the upper bound a perfect targeting policy could reach.")


if __name__ == "__main__":
    main()

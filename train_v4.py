"""
train_v4.py — train agents in the v4 world, one model per seed
===============================================================
One training run can be lucky or unlucky. We train several independent
runs (seeds) and report the spread across them.

Rules:
  - Training uses RANDOM kill chains. The AIIMS chain used for testing is
    never seen during training.
  - PPO hyperparameters are those of the original ghostnet_smart model
    (lr 3e-4, n_steps 2048, batch 64, gamma 0.99, ent_coef 0.02).
  - Rival algorithms (DQN, A2C) use Stable-Baselines3 defaults with the
    same gamma and the same step budget. None is tuned on the test chain.
  - The model at the END of training is kept. No best-checkpoint
    selection, so the test set cannot leak into model choice.

Variants
  ppo           GhostNet (main model)
  dqn, a2c      rival learning algorithms
  ppo-nofeeds   ablation: threat-feed inputs hidden from the agent
  ppo-nohold    ablation: no hold action, must mutate every step

    python train_v4.py                       # ppo, seeds 0-9, 300k steps
    python train_v4.py --variant dqn
    python train_v4.py --variant all         # every variant except ppo
    python train_v4.py --seeds 3 --steps 50000
    python train_v4.py --jobs 3              # fewer parallel runs (slower PC)
"""

import argparse
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import torch
from stable_baselines3 import A2C, DQN, PPO

from ghostnet_env_v4 import GhostNetEnvV4

OUT_DIR = os.path.join("models", "v4")


PPO_KW = dict(learning_rate=3e-4, n_steps=2048, batch_size=64,
              gamma=0.99, ent_coef=0.02)

# variant -> (algorithm, algorithm kwargs, environment kwargs)
VARIANTS = {
    "ppo":         (PPO, PPO_KW, {}),
    "dqn":         (DQN, dict(gamma=0.99), {}),
    "a2c":         (A2C, dict(gamma=0.99), {}),
    "ppo-nofeeds": (PPO, PPO_KW, {"mask_feeds": True}),
    "ppo-nohold":  (PPO, PPO_KW, {"allow_hold": False}),
}


def train_one(variant, seed, steps):
    torch.set_num_threads(1)     # tiny network: one thread is fastest, and
                                 # lets several seeds train in parallel
    algo, algo_kw, env_kw = VARIANTS[variant]
    env = GhostNetEnvV4(chain="random", **env_kw)
    model = algo("MlpPolicy", env, seed=seed, verbose=0, device="cpu", **algo_kw)
    model.learn(total_timesteps=steps)
    path = os.path.join(OUT_DIR, f"{variant}_seed{seed}")
    model.save(path)
    return path + ".zip"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="ppo",
                    choices=list(VARIANTS) + ["all"])
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--first-seed", type=int, default=0)
    ap.add_argument("--steps", type=int, default=300_000)
    ap.add_argument("--jobs", type=int, default=5, help="seeds trained in parallel")
    a = ap.parse_args()
    os.makedirs(OUT_DIR, exist_ok=True)

    variants = [v for v in VARIANTS if v != "ppo"] if a.variant == "all" else [a.variant]
    seeds = list(range(a.first_seed, a.first_seed + a.seeds))
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=a.jobs) as pool:
        futures = {pool.submit(train_one, v, s, a.steps): (v, s)
                   for v in variants for s in seeds}
        for f in as_completed(futures):
            v, s = futures[f]
            print(f"  {v} seed {s}: done after {time.time() - t0:5.0f} s -> {f.result()}", flush=True)


if __name__ == "__main__":
    main()

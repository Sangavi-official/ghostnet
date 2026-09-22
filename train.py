"""
GhostNet Training Script — Final, Corrected
==============================================
Trains the PPO agent on the corrected 12-dimension state vector.

Usage:
    python train.py          trains with live threat feeds
    python train.py --sim    trains with simulated data only
"""

import os
import argparse
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor
from ghostnet_env_v2 import GhostNetEnvV2

parser = argparse.ArgumentParser()
parser.add_argument("--sim", action="store_true",
                    help="Train with simulated threat data only")
args = parser.parse_args()

use_live = not args.sim

print("=" * 55)
print("  GhostNet — Hospital Network Moving Target Defense")
print("  Training Run (Final, Corrected State Vector)")
print("=" * 55)
print(f"  State dimensions : 12")
print(f"  Live threat feeds: {'ENABLED' if use_live else 'DISABLED'}")
print(f"  Algorithm        : PPO")
print(f"  Total steps      : 100,000")
print("=" * 55 + "\n")

os.makedirs("logs",       exist_ok=True)
os.makedirs("best_model", exist_ok=True)

train_env = GhostNetEnvV2(use_live_feeds=use_live)
eval_env  = GhostNetEnvV2(use_live_feeds=False)

env      = Monitor(train_env, "logs/")
eval_env = Monitor(eval_env)

eval_cb = EvalCallback(
    eval_env,
    best_model_save_path="./best_model/",
    log_path="./logs/",
    eval_freq=5000,
    n_eval_episodes=10,
    verbose=1
)

model = PPO(
    "MlpPolicy", env,
    verbose=1,
    learning_rate=3e-4,
    n_steps=2048,
    batch_size=64,
    gamma=0.99,
    ent_coef=0.02
)

print("  Training started.\n")
model.learn(total_timesteps=100_000, callback=eval_cb)
model.save("ghostnet_smart")

print("\n" + "=" * 55)
print("  Training complete.")
print("  Saved : ghostnet_smart.zip")
print("  Best  : best_model/best_model.zip")
print("=" * 55)
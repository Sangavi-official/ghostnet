"""
GhostNet — Phase 3 Demonstration
===================================
Loads the trained agent and executes 20 decision steps against
real AWS infrastructure, using the corrected 12-dimension state
vector and independent live threat signals.
"""

from stable_baselines3 import PPO
from ghostnet_env_v3 import GhostNetEnvV3
import time

print("=" * 60)
print("  GhostNet — Phase 3 Demonstration")
print("  Hospital ICU Pipeline -> Cloud Pharmacy Defense")
print("=" * 60)

model  = PPO.load("ghostnet_smart")
env    = GhostNetEnvV3(use_live_feeds=True, use_real_cloud=True, use_real_iot=True)
obs, _ = env.reset()

action_names = [
    "Rotate cloud IP    ", "Close open port    ",
    "Rotate API path    ", "Rotate IoT gateway ",
    "Rotate MQTT topic  ", "Update firewall    "
]

effect_description = [
    "Cloud identity tag rotated — prior reconnaissance invalidated",
    "Port closed on live AWS infrastructure",
    "API endpoint path rotated — prior mapping rendered void",
    "IoT gateway address rotated (Phase 4 hardware target)",
    "MQTT topic namespace rotated (Phase 4 hardware target)",
    "Firewall ruleset reviewed against current exposure"
]

total_reward = 0
print(f"\n  {'Step':>4}  {'Action':<22}  {'Reward':>7}  Effect")
print("  " + "-" * 78)

for step in range(1, 21):
    action, _ = model.predict(obs, deterministic=False)
    obs, reward, done, _, _ = env.step(int(action))
    total_reward += reward
    print(f"  {step:>4}  {action_names[action]}  "
          f"{reward:>7.3f}  {effect_description[action]}")
    time.sleep(0.4)
    if done:
        obs, _ = env.reset()

print("  " + "-" * 78)
stats = env.get_cloud_stats()
print(f"\n  Total reward         : {total_reward:.3f}")
print(f"  Real AWS mutations   : {stats['real_mutations']}")
print(f"  Failed mutations     : {stats['failed_mutations']}")
combined_log = stats["cloud_log"] + stats["iot_log"]


print("\n  Mutation audit log (most recent 10 entries):")
for entry in combined_log[-10:]:
    status = "OK  " if entry["success"] else "FAIL"
    print(f"  [{status}] {entry['action']:<20} {entry['details']}")

print("\n" + "=" * 60)
print("  Demonstration complete.")
print("=" * 60)

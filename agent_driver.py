"""Slice 4: trained PPO agent chooses the mutation.
   Uses ghostnet_smart — the threat-aware agent that targets the exposed surface.
   Placeholder mutation for now — swap in Sangavi's real function when Phase 4 lands."""
from stable_baselines3 import PPO
from ghostnet_env_v2 import GhostNetEnvV2

MODEL = "ghostnet_smart"   # the fixed, threat-aware agent

ACTION_NAMES = ["rotate_cloud_ip", "close_open_port", "rotate_api_path",
                "rotate_iot_ip", "rotate_mqtt_topic", "update_firewall"]

def placeholder_mutation(action):
    # TEMP — becomes iot_mutator.rotate_topic() / port hop once they verify at target
    print(f"[AGENT] chose action {action} ({ACTION_NAMES[action]}) -> (real mutation fires here)")

def run(steps=10):
    env = GhostNetEnvV2(use_live_feeds=False)
    model = PPO.load(MODEL)
    obs, _ = env.reset()
    for _ in range(steps):
        action, _ = model.predict(obs, deterministic=True)
        placeholder_mutation(int(action))     # <-- the single line that becomes Sangavi's call
        obs, r, done, trunc, _ = env.step(action)
        if done or trunc:
            obs, _ = env.reset()

if __name__ == "__main__":
    run()
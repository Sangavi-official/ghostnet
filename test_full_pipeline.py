from stable_baselines3 import PPO
from ghostnet_env_v2 import GhostNetEnvV2
from caldera_bridge import CalderaBridge
import numpy as np, threading, time
from alert_system import evaluate_and_alert

names = ["rotate_cloud_ip","close_port","rotate_api","rotate_iot_ip","rotate_mqtt","firewall"]

model = PPO.load("ghostnet_smart")
env = GhostNetEnvV2(use_live_feeds=False)
obs, _ = env.reset()

bridge = CalderaBridge()
bridge.start_operation()
t = threading.Thread(target=bridge.simulate_attack_sequence, kwargs={"delay_seconds": 2.0})
t.start()

for i in range(10):
    time.sleep(3)
    injection = bridge.get_threat_injection()
    attacked_obs = obs.copy()
    for dim, boost in injection.items():
        attacked_obs[dim] = min(1.0, attacked_obs[dim] + boost)
    action, _ = model.predict(attacked_obs, deterministic=True)
    evaluate_and_alert(int(action), injection, attacked_obs, bridge.get_active_ttps())
    print(f"[t={i*3}s] TTPs={bridge.get_active_ttps()}")
    print(f"         agent defends -> action {int(action)} ({names[int(action)]})\n")

t.join()
bridge.stop_operation()
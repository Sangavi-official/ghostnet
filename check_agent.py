from stable_baselines3 import PPO
from ghostnet_env_v2 import GhostNetEnvV2
import numpy as np

model = PPO.load("ghostnet_smart")
env = GhostNetEnvV2(use_live_feeds=False)

# indices: 0=cloud_ip 1=ports 2=api 3=iot_ip 4=mqtt 5=cve 6=shodan 7=traffic 8=recon 9=since 10=abuse 11=attck
names = ["rotate_cloud_ip","close_port","rotate_api","rotate_iot_ip","rotate_mqtt","firewall"]

scenarios = {
    "API is the exposed surface":      [0.1,0.1,0.9,0.1,0.1, 0.3,0.0,0.3,0.1,0.0, 0.2,0.0],
    "MQTT is the exposed surface":     [0.1,0.1,0.1,0.1,0.9, 0.3,0.0,0.3,0.1,0.0, 0.2,0.0],
    "IoT gateway is exposed":          [0.1,0.1,0.1,0.9,0.1, 0.3,0.0,0.3,0.1,0.0, 0.2,0.0],
    "Ports exposed + high CVE":        [0.1,0.9,0.1,0.1,0.1, 0.9,0.0,0.3,0.1,0.0, 0.2,0.0],
    "Everything calm, high abuse":     [0.2,0.2,0.2,0.2,0.2, 0.2,0.0,0.3,0.1,0.0, 0.9,0.0],
}

for desc, s in scenarios.items():
    obs = np.array(s, dtype=np.float32)
    action, _ = model.predict(obs, deterministic=True)
    print(f"{desc:32s} -> action {int(action)} ({names[int(action)]})")
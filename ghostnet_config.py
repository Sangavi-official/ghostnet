"""
ghostnet_config.py — single source of machine-specific configuration
=====================================================================
Every value that differs between team members' laptops lives HERE and
nowhere else. Previously EC2_HOST and KEY_PATH were hardcoded inside
iot_mutator.py pointing at one member's machine, so the IoT layer only
ran for that one person.

Each value can be overridden with an environment variable, so nobody has
to edit source to run the project:

    setx GHOSTNET_EC2_HOST 13.200.1.2
    setx GHOSTNET_KEY_PATH "C:\\Users\\you\\ghostnet-iot-key.pem"

PROTECTED_PORTS is a safety interlock: GhostNet must never close SSH or
the broker's own listeners, or it severs its own control channel and the
patient telemetry path.
"""

import os

# ─── AWS ────────────────────────────────────────────────────────────
AWS_REGION        = os.getenv("GHOSTNET_AWS_REGION", "ap-south-1")
SECURITY_GROUP_ID = os.getenv("GHOSTNET_SG_ID", "sg-011b5416a5dfa61b8")

# ─── EC2 / IoT host ─────────────────────────────────────────────────
EC2_HOST = os.getenv("GHOSTNET_EC2_HOST", "13.206.71.17")   # changes on stop/start
EC2_USER = os.getenv("GHOSTNET_EC2_USER", "ubuntu")
KEY_PATH = os.getenv("GHOSTNET_KEY_PATH",
                     r"C:\Users\nazee\OneDrive\Documents\capstone-project\ghostnet-iot-key.pem")

# ─── MQTT ───────────────────────────────────────────────────────────
MQTT_PORT      = int(os.getenv("GHOSTNET_MQTT_PORT", "1883"))
MQTT_WS_PORT   = int(os.getenv("GHOSTNET_MQTT_WS_PORT", "9001"))
TELEMETRY_TOPIC = "hospital/icu/vitals/patient1"
CONTROL_TOPIC   = "ghostnet/control/pump1"
BROKER_CONF     = "/etc/mosquitto/conf.d/ghostnet.conf"

# ─── Mutation surface bounds ────────────────────────────────────────
# GhostNet may only open/close ports in this range. Anything outside is
# refused, so a bad action can never touch SSH or the live broker.
MUTABLE_PORT_RANGE = (8200, 8999)
PROTECTED_PORTS    = {22, 443, MQTT_PORT, MQTT_WS_PORT}

CIDR = os.getenv("GHOSTNET_CIDR", "0.0.0.0/0")   # lab only; scope this for real use


def describe():
    print("  " + "-" * 58)
    print(f"  region {AWS_REGION} | sg {SECURITY_GROUP_ID}")
    print(f"  ec2    {EC2_USER}@{EC2_HOST}")
    print(f"  key    {KEY_PATH}")
    print(f"  mutable ports {MUTABLE_PORT_RANGE} | protected {sorted(PROTECTED_PORTS)}")
    print("  " + "-" * 58)


if __name__ == "__main__":
    describe()
    if not os.path.exists(KEY_PATH):
        print(f"  WARNING: key not found at {KEY_PATH} -- set GHOSTNET_KEY_PATH")

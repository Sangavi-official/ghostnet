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

import json
import os

# ─── AWS ────────────────────────────────────────────────────────────
AWS_REGION        = os.getenv("GHOSTNET_AWS_REGION", "ap-south-1")
SECURITY_GROUP_ID = os.getenv("GHOSTNET_SG_ID", "sg-011b5416a5dfa61b8")


def _ledger_host():
    """Public IP recorded by the last VERIFIED cloud-IP rotation (action 0)."""
    try:
        with open(os.getenv("GHOSTNET_LEDGER", "mutation_ledger.json")) as f:
            return json.load(f).get("config", {}).get("ec2_host")
    except Exception:
        return None


# ─── EC2 / IoT host ─────────────────────────────────────────────────
# Precedence: the ledger (written only after action 0 verifies a new
# Elastic IP) > GHOSTNET_EC2_HOST > default. Every module reads
# cfg.EC2_HOST at call time, so a rotation is followed everywhere.
# With an Elastic IP attached the address also survives stop/start.
EC2_HOST = _ledger_host() or os.getenv("GHOSTNET_EC2_HOST", "13.206.71.17")
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

# ─── Broker relocation interlock ────────────────────────────────────
# Moving the broker relocates the rendezvous point for EVERY device on
# the network. In a 20-step agent loop that is self-inflicted denial of
# service: each hop costs a telemetry outage, and devices that cannot
# follow are stranded. It is a controlled experiment, not a routine
# defensive action, so it is DISABLED unless explicitly enabled:
#     $env:GHOSTNET_ALLOW_BROKER_HOP = "1"
ALLOW_BROKER_HOP = os.getenv("GHOSTNET_ALLOW_BROKER_HOP", "0") == "1"

# ─── Cloud IP rotation interlock (action 0) ─────────────────────────
# A real Elastic IP swap changes the address every external client uses
# and briefly drops their connections (the pump runs on the host and is
# not affected). Like the broker hop it is opt-in:
#     $env:GHOSTNET_ALLOW_IP_ROTATION = "1"
# When disabled, action 0 falls back to the old Security Group TAG
# rotation, which is reported as PARTIAL.
ALLOW_IP_ROTATION = os.getenv("GHOSTNET_ALLOW_IP_ROTATION", "0") == "1"

# ─── Live API gateway (action 2) ────────────────────────────────────
# nginx on the EC2 serves the demo clinical API at a secret path that
# action 2 rotates. Must be open in the Security Group and outside the
# mutable port range (so cleanup never closes it).
API_PORT = int(os.getenv("GHOSTNET_API_PORT", "80"))


def describe():
    print("  " + "-" * 58)
    print(f"  region {AWS_REGION} | sg {SECURITY_GROUP_ID}")
    print(f"  ec2    {EC2_USER}@{EC2_HOST}")
    print(f"  key    {KEY_PATH}")
    print(f"  mutable ports {MUTABLE_PORT_RANGE} | protected {sorted(PROTECTED_PORTS)}")
    print(f"  broker hop: {'ENABLED' if ALLOW_BROKER_HOP else 'disabled (experiment only)'}")
    print(f"  ip rotation: {'ENABLED (Elastic IP swap)' if ALLOW_IP_ROTATION else 'disabled (tag only)'}"
          f"{' | host from ledger' if _ledger_host() else ''}")
    print(f"  api gateway: nginx on :{API_PORT}")
    print("  " + "-" * 58)


if __name__ == "__main__":
    describe()
    if not os.path.exists(KEY_PATH):
        print(f"  WARNING: key not found at {KEY_PATH} -- set GHOSTNET_KEY_PATH")
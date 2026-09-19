"""
device_v2.py — GhostNet simulated infusion pump
Runs ON the EC2 instance (or a Raspberry Pi later).

Publishes ICU vitals every 5 s and accepts live topic rotation from
BOTH control channels, so it works with either mutation path:
  1. MQTT control topic  ghostnet/control/pump1   (iot_mutator.rotate_iot_topic)
  2. control file        /tmp/new_topic.txt       (SSH-written)

A 10-second dual-publish overlap keeps subscribers from losing data
during the cutover -- the availability-preservation property GhostNet
claims for hospital telemetry.

    python3 device_v2.py
"""
import json
import os
import random
import time

import paho.mqtt.client as mqtt

BROKER       = "localhost"
PORT         = 1883
CONTROL_FILE = "/tmp/new_topic.txt"
CONTROL_TOPIC = "ghostnet/control/pump1"
DEFAULT_TOPIC = "hospital/icu/vitals/patient1"
OVERLAP_SECONDS = 10

state = {"topic": DEFAULT_TOPIC, "overlap_topic": None, "overlap_until": 0.0}


def _mqtt_client(client_id=""):
    """
    paho-mqtt 2.x requires the callback API version explicitly; 1.x does
    not have the enum at all. This keeps both working and silences the
    DeprecationWarning.
    """
    try:
        ver = mqtt.CallbackAPIVersion.VERSION1
        return mqtt.Client(ver, client_id) if client_id else mqtt.Client(ver)
    except AttributeError:
        return mqtt.Client(client_id) if client_id else mqtt.Client()



def switch_topic(new_topic, source):
    if not new_topic or new_topic == state["topic"]:
        return
    state["overlap_topic"] = state["topic"]
    state["overlap_until"] = time.time() + OVERLAP_SECONDS
    state["topic"] = new_topic
    print(f"[DEVICE] topic rotated via {source} -> {new_topic} "
          f"({OVERLAP_SECONDS}s overlap with {state['overlap_topic']})")


def on_connect(client, userdata, flags, rc):
    client.subscribe(CONTROL_TOPIC)
    print(f"[DEVICE] connected (rc={rc}), listening on {CONTROL_TOPIC}")


def on_message(client, userdata, msg):
    """Channel 1: MQTT control message from iot_mutator.rotate_iot_topic()."""
    try:
        cmd = json.loads(msg.payload.decode())
    except Exception:
        return
    if cmd.get("action") == "rotate_topic":
        switch_topic(cmd.get("new_topic"), "MQTT control")


def check_control_file():
    """Channel 2: SSH-written control file."""
    if not os.path.exists(CONTROL_FILE):
        return
    try:
        with open(CONTROL_FILE) as f:
            switch_topic(f.read().strip(), "control file")
    except Exception as e:
        print(f"[DEVICE] control-file read error: {e}")


def build_payload():
    return json.dumps({
        "pump_id":      "pump1",
        "heart_rate":   random.randint(60, 100),
        "spo2":         random.randint(95, 100),
        "flow_rate":    round(random.uniform(1.0, 5.0), 2),
        "pressure":     round(random.uniform(0.8, 1.4), 2),
        "battery":      random.randint(70, 100),
        "alarm_active": False,
        "timestamp":    round(time.time(), 2),
        "source":       "device_v2",
    })


def main():
    client = _mqtt_client("ghostnet-pump1")
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    print(f"[DEVICE] starting, initial topic: {state['topic']}")

    try:
        while True:
            check_control_file()
            payload = build_payload()
            client.publish(state["topic"], payload)
            print(f"[DEVICE] -> {state['topic']}  {payload}")

            if state["overlap_topic"]:
                if time.time() < state["overlap_until"]:
                    client.publish(state["overlap_topic"], payload)
                    print(f"[DEVICE] dual-publish (handoff window) "
                          f"-> {state['overlap_topic']}")
                else:
                    print(f"[DEVICE] overlap closed, retiring "
                          f"{state['overlap_topic']}")
                    state["overlap_topic"] = None
            time.sleep(5)
    except KeyboardInterrupt:
        client.loop_stop()
        print("\n[DEVICE] stopped.")


if __name__ == "__main__":
    main()
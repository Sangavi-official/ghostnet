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
import sys
import time

import paho.mqtt.client as mqtt

BROKER       = os.getenv("GHOSTNET_BROKER", "localhost")
PORT         = int(sys.argv[1]) if len(sys.argv) > 1 else 1883

# Ports the pump will try, in order, if it loses the broker without
# having been told where it moved. Without this a broker relocation
# strands the device permanently.
FALLBACK_PORTS = [1883, 8319, 8888]
CONTROL_FILE = "/tmp/new_topic.txt"
CONTROL_TOPIC = "ghostnet/control/pump1"
DEFAULT_TOPIC = "hospital/icu/vitals/patient1"
OVERLAP_SECONDS = 10

state = {"topic": DEFAULT_TOPIC, "overlap_topic": None, "overlap_until": 0.0,
         "port": PORT, "pending_port": None, "move_at": 0.0}


def _mqtt_client(client_id=""):
    """
    Build a paho client across paho-mqtt 1.x and 2.x.

    paho 2.x deprecates the v1 callback API; v2 adds `properties` to
    on_connect and passes a ReasonCode instead of an int rc. The
    callbacks below take those as optional trailing arguments, so the
    same function works under either API and no warning is emitted.
    """
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id or None)
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


def on_connect(client, userdata, flags, rc=0, properties=None):
    client.subscribe(CONTROL_TOPIC)
    print(f"[DEVICE] connected (rc={rc}), listening on {CONTROL_TOPIC}")


def on_message(client, userdata, msg, properties=None):
    """Channel 1: MQTT control message from iot_mutator.rotate_iot_topic()."""
    try:
        cmd = json.loads(msg.payload.decode())
    except Exception:
        return
    action = cmd.get("action")
    if action == "rotate_topic":
        switch_topic(cmd.get("new_topic"), "MQTT control")
    elif action == "broker_move":
        # The broker cannot announce its relocation AFTER it moves --
        # the control channel lives on the broker itself. So the mutator
        # sends this notice on the OLD listener, with a grace period,
        # and the device reconnects when the window opens.
        new_port = int(cmd.get("new_port", 0))
        grace    = float(cmd.get("grace", 5))
        if new_port:
            state["pending_port"] = new_port
            state["move_at"] = time.time() + grace
            print(f"[DEVICE] broker relocation notice: {state['port']} -> "
                  f"{new_port} in {grace}s")


def check_control_file():
    """Channel 2: SSH-written control file."""
    if not os.path.exists(CONTROL_FILE):
        return
    try:
        with open(CONTROL_FILE) as f:
            switch_topic(f.read().strip(), "control file")
    except Exception as e:
        print(f"[DEVICE] control-file read error: {e}")


def connect_client(client, port, tries=3):
    """Connect to the broker on `port`, retrying briefly."""
    for attempt in range(tries):
        try:
            client.connect(BROKER, port, 60)
            state["port"] = port
            return True
        except Exception as e:
            print(f"[DEVICE] connect to :{port} failed ({e}) "
                  f"[attempt {attempt + 1}/{tries}]")
            time.sleep(2)
    return False


def relocate(client):
    """Follow the broker to its new listener, reporting the outage gap."""
    new_port = state["pending_port"]
    state["pending_port"] = None
    print(f"[DEVICE] relocating to broker port {new_port}")
    t0 = time.time()
    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass
    if connect_client(client, new_port):
        client.loop_start()
        gap = time.time() - t0
        print(f"[DEVICE] RECONNECTED on :{new_port} -- telemetry gap {gap:.2f}s")
        return True
    # Never told where it went, or the move failed: try known listeners.
    for p in FALLBACK_PORTS:
        if connect_client(client, p, tries=1):
            client.loop_start()
            print(f"[DEVICE] recovered via fallback port :{p}")
            return True
    print("[DEVICE] BROKER LOST -- no reachable listener")
    return False


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
    if not connect_client(client, PORT):
        print(f"[DEVICE] cannot reach broker on :{PORT}, trying fallbacks")
        if not any(connect_client(client, p, tries=1) for p in FALLBACK_PORTS):
            raise SystemExit("[DEVICE] no broker reachable")
    client.loop_start()
    print(f"[DEVICE] starting on :{state['port']}, topic: {state['topic']}")

    try:
        while True:
            if state["pending_port"] and time.time() >= state["move_at"]:
                relocate(client)
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
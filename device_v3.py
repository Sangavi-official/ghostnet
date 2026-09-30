"""
device_v3.py — GhostNet simulated infusion pump, GMCP edition
==============================================================
Runs ON the EC2 instance. device_v2.py is kept unchanged for the
original experiments.

Differences from device_v2:
  - Control commands must be GMCP messages (gmcp.py): signed with the
    per-device key, fresh, and in sequence. Unsigned, forged, tampered or
    replayed commands are rejected and logged.
  - Every accepted step is acknowledged on ACK_TOPIC, so the controller
    knows what happened instead of guessing.
  - Broker moves are make-before-break: the controller opens the new
    listener first, so the device moves immediately on COMMIT. If the
    new listener cannot be reached the device returns to the old one,
    which is still open.
  - The unauthenticated control-file channel of device_v2 is removed.
  - The last committed sequence number is saved to STATE_FILE, so a
    rebooted pump still rejects replays.

Needs gmcp.py next to it, and the same key as the controller:
    export GHOSTNET_GMCP_KEY=<64 hex chars>
    export GHOSTNET_MQTT_USER=pump1 GHOSTNET_MQTT_PASS=...   (if broker auth is on)
    python3 -u device_v3.py 1883
"""
import json
import os
import random
import sys
import time

import paho.mqtt.client as mqtt

import gmcp

BROKER          = os.getenv("GHOSTNET_BROKER", "localhost")
PORT            = int(sys.argv[1]) if len(sys.argv) > 1 else 1883
DEVICE_ID       = "pump1"
CONTROL_TOPIC   = f"ghostnet/control/{DEVICE_ID}"
ACK_TOPIC       = f"ghostnet/ack/{DEVICE_ID}"
DEFAULT_TOPIC   = "hospital/icu/vitals/patient1"
OVERLAP_SECONDS = 10
STATE_FILE      = os.path.expanduser("~/.ghostnet_gmcp_state.json")

KEY_HEX = os.getenv("GHOSTNET_GMCP_KEY", "")
if len(KEY_HEX) < 32:
    raise SystemExit("[DEVICE] set GHOSTNET_GMCP_KEY (hex, same value as the controller)")
KEY = bytes.fromhex(KEY_HEX)

state = {"topic": DEFAULT_TOPIC, "overlap_topic": None, "overlap_until": 0.0,
         "port": PORT, "pending_port": None}


def load_last_seq():
    try:
        with open(STATE_FILE) as f:
            return int(json.load(f)["last_seq"])
    except Exception:
        return 0


def save_last_seq(seq):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"last_seq": seq}, f)
    os.replace(tmp, STATE_FILE)


PROTO = gmcp.Device(DEVICE_ID, KEY, time.time, last_seq=load_last_seq())


def _mqtt_client(client_id=""):
    try:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id or None)
    except AttributeError:
        c = mqtt.Client(client_id) if client_id else mqtt.Client()
    user = os.getenv("GHOSTNET_MQTT_USER")
    if user:
        c.username_pw_set(user, os.getenv("GHOSTNET_MQTT_PASS", ""))
    return c


def switch_topic(new_topic):
    if not new_topic or new_topic == state["topic"]:
        return
    state["overlap_topic"] = state["topic"]
    state["overlap_until"] = time.time() + OVERLAP_SECONDS
    state["topic"] = new_topic
    print(f"[DEVICE] topic rotated -> {new_topic} "
          f"({OVERLAP_SECONDS}s overlap with {state['overlap_topic']})")


def on_connect(client, userdata, flags, rc=0, properties=None):
    client.subscribe(CONTROL_TOPIC, qos=1)
    print(f"[DEVICE] connected on :{state['port']} (rc={rc}), listening on {CONTROL_TOPIC}")


def on_message(client, userdata, msg, properties=None):
    try:
        cmd = json.loads(msg.payload.decode())
    except Exception:
        return
    before = dict(PROTO.rejected)
    reply, effect = PROTO.handle(cmd)
    if reply is None:
        why = [k for k in PROTO.rejected if PROTO.rejected[k] != before.get(k)]
        print(f"[DEVICE] REJECTED control message ({', '.join(why) or 'invalid'})")
        return
    if effect is not None:
        save_last_seq(PROTO.last_committed)
        if effect["action"] == "rotate_topic":
            switch_topic(effect.get("new_topic"))
        elif effect["action"] == "broker_move":
            state["pending_port"] = int(effect["new_port"])
            print(f"[DEVICE] broker move committed -> :{state['pending_port']}")
    elif reply.get("status") == "aborted":
        save_last_seq(PROTO.last_seq)
    client.publish(ACK_TOPIC, json.dumps(reply), qos=1)


def connect_client(client, port, tries=3):
    for attempt in range(tries):
        try:
            client.connect(BROKER, port, 60)
            state["port"] = port
            return True
        except Exception as e:
            print(f"[DEVICE] connect to :{port} failed ({e}) [attempt {attempt + 1}/{tries}]")
            time.sleep(2)
    return False


def relocate(client):
    """Move to the new listener; fall back to the old one (still open)."""
    new_port, old_port = state["pending_port"], state["port"]
    state["pending_port"] = None
    t0 = time.time()
    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass
    if connect_client(client, new_port):
        client.loop_start()
        print(f"[DEVICE] RECONNECTED on :{new_port} -- telemetry gap {time.time() - t0:.2f}s")
        return True
    if connect_client(client, old_port):
        client.loop_start()
        print(f"[DEVICE] new listener :{new_port} unreachable -- back on :{old_port}")
        return False
    print("[DEVICE] BROKER LOST -- neither listener reachable")
    return False


def build_payload():
    return json.dumps({
        "pump_id":      DEVICE_ID,
        "heart_rate":   random.randint(60, 100),
        "spo2":         random.randint(95, 100),
        "flow_rate":    round(random.uniform(1.0, 5.0), 2),
        "pressure":     round(random.uniform(0.8, 1.4), 2),
        "battery":      random.randint(70, 100),
        "alarm_active": False,
        "timestamp":    round(time.time(), 2),
        "source":       "device_v3",
    })


def main():
    client = _mqtt_client(f"ghostnet-{DEVICE_ID}")
    client.on_connect = on_connect
    client.on_message = on_message
    if not connect_client(client, PORT):
        raise SystemExit(f"[DEVICE] no broker reachable on :{PORT}")
    client.loop_start()
    print(f"[DEVICE] starting on :{state['port']}, topic {state['topic']}, "
          f"last_seq {PROTO.last_seq}")

    try:
        while True:
            if state["pending_port"]:
                relocate(client)
            payload = build_payload()
            client.publish(state["topic"], payload)
            print(f"[DEVICE] -> {state['topic']}  {payload}")
            if state["overlap_topic"]:
                if time.time() < state["overlap_until"]:
                    client.publish(state["overlap_topic"], payload)
                else:
                    print(f"[DEVICE] overlap closed, retiring {state['overlap_topic']}")
                    state["overlap_topic"] = None
            # sleep in short slices so a committed move is acted on quickly
            for _ in range(10):
                if state["pending_port"]:
                    break
                time.sleep(0.5)
    except KeyboardInterrupt:
        client.loop_stop()
        print("\n[DEVICE] stopped.")


if __name__ == "__main__":
    main()

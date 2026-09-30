"""
gmcp_live_attack.py — attack the live pump's control channel (lab test)
========================================================================
Plays an adversary who can publish and subscribe on the broker (for
example with leaked broker credentials). Run it against the lab EC2
only. Watch the pump log (device_v3.py): every attack must show
"REJECTED". Against device_v2.py the same commands are obeyed.

    python gmcp_live_attack.py --forge
        sends an unsigned command and a command with a fake signature

    python gmcp_live_attack.py --replay
        records the next real GMCP command, waits, then replays it.
        Start this first, then run  python iot_mutator.py --topic --gmcp
        in a second terminal.
"""

import json
import sys
import time

import ghostnet_config as cfg
from iot_mutator import _mqtt_client
from mutation_ledger import ledger

EVIL_TOPIC = "attacker/collect"


def connect():
    c = _mqtt_client("lab-attacker")
    c.connect(cfg.EC2_HOST, ledger.get_config("broker_port", cfg.MQTT_PORT), 60)
    c.loop_start()
    return c


def forge():
    c = connect()
    unsigned = {"action": "rotate_topic", "new_topic": EVIL_TOPIC}
    fake_sig = {"v": 1, "dev": "pump1", "seq": 10**6, "ts": time.time(), "type": "prepare",
                "cmd": unsigned, "mac": "0" * 64}
    for name, m in (("unsigned command", unsigned), ("fake signature", fake_sig),
                    ("fake signature commit", {**fake_sig, "type": "commit"})):
        c.publish(cfg.CONTROL_TOPIC, json.dumps(m), qos=1)
        print(f"  sent {name}: {json.dumps(m)[:80]}...")
        time.sleep(1)
    c.loop_stop(); c.disconnect()
    print("  Now check the pump log: each line should say REJECTED (bad_mac),")
    print(f"  and nothing should be published on {EVIL_TOPIC}.")


def replay(wait=10):
    captured = []
    c = connect()
    c.on_message = lambda cl, u, m, p=None: captured.append(m.payload)
    c.subscribe(cfg.CONTROL_TOPIC, qos=1)
    print("  listening for the next GMCP command... run  "
          "python iot_mutator.py --topic --gmcp  in another terminal")
    while not any(b'"commit"' in m for m in captured):
        time.sleep(0.5)
    time.sleep(1)
    print(f"  captured {len(captured)} messages; replaying them in {wait}s")
    time.sleep(wait)
    for m in captured:
        c.publish(cfg.CONTROL_TOPIC, m, qos=1)
        print(f"  replayed: {m[:80]}...")
        time.sleep(1)
    c.loop_stop(); c.disconnect()
    print("  Now check the pump log: the replayed PREPARE should say REJECTED (replay),")
    print("  and the pump's topic must NOT change back.")


if __name__ == "__main__":
    if "--forge" in sys.argv:
        forge()
    elif "--replay" in sys.argv:
        replay()
    else:
        print(__doc__)

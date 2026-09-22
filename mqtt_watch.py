"""
mqtt_watch.py — verification subscriber (replaces mosquitto_sub on Windows)

Subscribes to every topic on the broker and prints each message with its
topic, so you can SEE a topic rotation happen live. This is the
ground-truth check for IoT mutations -- do not trust the mutator's own
SUCCESS line.

    python mqtt_watch.py <EC2_PUBLIC_IP> [port]

Watch for the topic name in the left column changing after the agent
picks rotate_mqtt_topic.
"""
import sys
import time

import paho.mqtt.client as mqtt

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1883

seen_topics = {}


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



def on_connect(client, userdata, flags, rc):
    print(f"[WATCH] connected to {HOST}:{PORT} (rc={rc}) -- subscribing to '#'")
    client.subscribe("#")


def on_message(client, userdata, msg):
    topic = msg.topic
    if topic not in seen_topics:
        seen_topics[topic] = 0
        print(f"\n[WATCH] *** NEW TOPIC SEEN: {topic} ***\n")
    seen_topics[topic] += 1
    stamp = time.strftime("%H:%M:%S")
    body = msg.payload.decode(errors="replace")[:110]
    print(f"{stamp}  {topic:<42} {body}")


client = _mqtt_client("ghostnet-watch")
client.on_connect = on_connect
client.on_message = on_message
client.connect(HOST, PORT, 60)

try:
    client.loop_forever()
except KeyboardInterrupt:
    print("\n[WATCH] topics observed this session:")
    for t, n in seen_topics.items():
        print(f"   {n:>5} msgs   {t}")
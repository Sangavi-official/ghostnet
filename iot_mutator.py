"""
iot_mutator.py — GhostNet IoT domain executor (verified, rollback-safe)
========================================================================
Runs on your laptop. Mutates the real broker and the live pump:
  action 4 -> rotate_iot_topic()            (MQTT control channel)
  action 3 -> restart_broker_with_new_port() (broker listener hop)

FIXED IN THIS VERSION
  1. EC2_HOST / KEY_PATH were hardcoded to one team member's laptop, so
     this module only ran for her. Both now come from ghostnet_config.
  2. rotate_iot_topic() reported SUCCESS on publish. Publishing is not
     evidence. It now SUBSCRIBES to the new topic and waits for real
     telemetry before claiming success.
  3. restart_broker_with_new_port() edited /etc/mosquitto/mosquitto.conf
     with sed, while the listeners actually live in conf.d/ghostnet.conf
     -- so it silently did nothing, or half-applied and broke the broker.
     It now rewrites the GhostNet conf file deterministically.
  4. It chose ports 1884-1887, none of which are open in the Security
     Group -- the broker would move behind the firewall and ALL patient
     telemetry would stop. It now opens the SG port FIRST, verifies the
     broker is listening, and ROLLS BACK to the previous config if not.
  5. Every mutation is recorded in mutation_ledger with its old value.
"""

import json
import random
import string
import time

import paho.mqtt.client as mqtt
import paramiko

import ghostnet_config as cfg
from mutation_ledger import ledger

mutation_history = []


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


def log_mutation(action, details, success):
    entry = {"timestamp": time.time(), "action": action,
             "details": details, "success": success}
    mutation_history.append(entry)
    print(f"  [IOT] {'SUCCESS' if success else 'FAILED'} | {action} | {details}")
    return success


# ───────────────────────────────── ssh ──────────────────────────────
def open_ssh(timeout=15):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=cfg.EC2_HOST, username=cfg.EC2_USER,
                key_filename=cfg.KEY_PATH, timeout=timeout)
    return ssh


def _ssh_run(command, timeout=15):
    ssh = open_ssh(timeout)
    try:
        _, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        return stdout.read().decode(), stderr.read().decode()
    finally:
        ssh.close()


# ───────────────────────────── verification ─────────────────────────
def _parse_listen_ports(out):
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if ":" in local:
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except ValueError:
                pass
    return ports


def broker_running():
    """Is the mosquitto unit active? (systemd is the authority.)"""
    out, _ = _ssh_run("systemctl is-active mosquitto 2>/dev/null || true")
    return out.strip() == "active"


def broker_listening_ports():
    """
    Ground truth: which ports Mosquitto is actually listening on.

    NOTE: plain `ss -tlnp` hides the process name from non-root users, so
    grepping for "mosquitto" as the ubuntu user silently returns nothing.
    We try sudo first, then fall back to intersecting all listening ports
    with the ports declared in the GhostNet broker config.
    """
    try:
        out, _ = _ssh_run("sudo ss -tlnp 2>/dev/null | grep -i mosquitto || true")
        ports = _parse_listen_ports(out)
        if ports:
            return sorted(ports)

        # Fallback: declared ports that are genuinely bound right now.
        conf, _ = _ssh_run(f"cat {cfg.BROKER_CONF} 2>/dev/null || true")
        declared = set()
        for line in conf.splitlines():
            bits = line.split()
            if len(bits) >= 2 and bits[0] == "listener":
                try:
                    declared.add(int(bits[1]))
                except ValueError:
                    pass
        listening, _ = _ssh_run("ss -tln 2>/dev/null || true")
        return sorted(declared & _parse_listen_ports(listening))
    except Exception as e:
        print(f"  [IOT] could not read broker ports: {e}")
        return []


def get_iot_status():
    return {"active": broker_running(),
            "listening": broker_listening_ports(),
            "conf": _ssh_run(f"cat {cfg.BROKER_CONF} 2>/dev/null || true")[0].strip()}


def wait_for_topic(topic, host=None, port=None, timeout=20):
    """
    Real verification for topic rotation: subscribe to the NEW topic and
    wait for the pump to publish there. Returns True only on real data.
    """
    host = host or cfg.EC2_HOST
    port = port or ledger.get_config("broker_port", cfg.MQTT_PORT)
    seen = {"ok": False}

    def on_message(c, u, msg, properties=None):
        seen["ok"] = True

    c = _mqtt_client("ghostnet-verify")
    c.on_message = on_message
    try:
        c.connect(host, port, 60)
        c.subscribe(topic)
        c.loop_start()
        deadline = time.time() + timeout
        while time.time() < deadline and not seen["ok"]:
            time.sleep(0.5)
        c.loop_stop()
        c.disconnect()
    except Exception as e:
        print(f"  [IOT] verification subscribe failed: {e}")
    return seen["ok"]


# ─────────────────────────── agent actions ──────────────────────────
def rotate_iot_topic(verify=True, timeout=20):
    """
    Action 4 — rotate the live telemetry topic via the control channel,
    then CONFIRM the pump actually moved by subscribing to the new topic.
    """
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    new_topic = f"hospital/icu/vitals/p{suffix}"
    old_topic = ledger.get_config("telemetry_topic", cfg.TELEMETRY_TOPIC)
    port = ledger.get_config("broker_port", cfg.MQTT_PORT)

    try:
        m = _mqtt_client("ghostnet-control")
        m.connect(cfg.EC2_HOST, port, 60)
        m.publish(cfg.CONTROL_TOPIC,
                  json.dumps({"action": "rotate_topic", "new_topic": new_topic}))
        m.disconnect()
    except Exception as e:
        return log_mutation("rotate_mqtt_topic", f"control publish failed: {e}", False)

    entry = ledger.record("iot", "rotate_mqtt_topic", cfg.EC2_HOST,
                          old_topic, new_topic, config_key="telemetry_topic")

    if not verify:
        return log_mutation("rotate_mqtt_topic", f"-> {new_topic} [UNVERIFIED]", True)

    ok = wait_for_topic(new_topic, timeout=timeout)
    ledger.mark_verified(entry["id"], ok)
    if not ok:
        ledger.set_config("telemetry_topic", old_topic)
        return log_mutation("rotate_mqtt_topic",
                            f"published but no telemetry on {new_topic} "
                            f"within {timeout}s — pump may not be listening", False)
    return log_mutation("rotate_mqtt_topic",
                        f"{old_topic} -> {new_topic} | CONFIRMED live telemetry", True)


def _write_broker_conf(port, ws_port=None):
    ws_port = ws_port or cfg.MQTT_WS_PORT
    # Match the deployed conf format exactly (explicit bind address and
    # protocol lines) so a port hop never silently changes broker semantics.
    conf = (f"listener {port} 0.0.0.0\n"
            f"protocol mqtt\n\n"
            f"listener {ws_port} 0.0.0.0\n"
            f"protocol websockets\n\n"
            f"allow_anonymous true\n")
    cmd = (f"sudo tee {cfg.BROKER_CONF} > /dev/null << 'GHOSTNETEOF'\n"
           f"{conf}GHOSTNETEOF\n"
           f"sudo systemctl restart mosquitto")
    return _ssh_run(cmd, timeout=25)


def restart_broker_with_new_port(new_port=None, announce=True, grace=5.0, force=False):
    """
    Action 3 — broker listener hop, done safely:
      1. open the target port in the Security Group FIRST
      2. rewrite the GhostNet broker conf and restart Mosquitto
      3. verify the broker is really listening on the new port
      4. on failure, RESTORE the previous conf and reopen the old port
    Without step 4 a failed hop strands the broker behind the firewall
    and all patient telemetry stops.
    """
    if not cfg.ALLOW_BROKER_HOP and not force:
        # Interlock: see ghostnet_config.ALLOW_BROKER_HOP. Reported as a
        # skipped action, not a failure -- refusing an unsafe mutation is
        # correct behaviour, not a fault.
        return log_mutation("rotate_iot_ip",
                            "SKIPPED: broker relocation disabled "
                            "(set GHOSTNET_ALLOW_BROKER_HOP=1 for the experiment)",
                            True)

    lo, hi = cfg.MUTABLE_PORT_RANGE
    old_port = ledger.get_config("broker_port", cfg.MQTT_PORT)
    if new_port is None:
        new_port = random.randint(lo, hi)
        while new_port == old_port:
            new_port = random.randint(lo, hi)

    # 1. cloud side first — imported lazily so this module works without AWS
    try:
        from p3_cloud_mutator import open_port, close_port, verify_port
        if not open_port(new_port) or not verify_port(new_port, True):
            return log_mutation("rotate_iot_ip",
                                f"SG port {new_port} unavailable — hop refused", False)
    except Exception as e:
        return log_mutation("rotate_iot_ip", f"cloud pre-step failed: {e}", False)

    prev_conf = _ssh_run(f"cat {cfg.BROKER_CONF} 2>/dev/null || true")[0]
    entry = ledger.record("iot", "rotate_iot_ip", cfg.EC2_HOST,
                          old_port, new_port, config_key="broker_port")

    # ── Relocation notice ───────────────────────────────────────────
    # The control channel runs ON the broker, so the broker cannot
    # announce its own move after the fact. Devices are told on the OLD
    # listener, with a grace period, BEFORE the hop. Without this the
    # infrastructure mutation succeeds while severing patient telemetry.
    if announce:
        try:
            n = _mqtt_client("ghostnet-control")
            n.connect(cfg.EC2_HOST, old_port, 60)
            n.publish(cfg.CONTROL_TOPIC, json.dumps({
                "action": "broker_move", "new_port": new_port, "grace": grace}),
                qos=1)
            time.sleep(1)
            n.disconnect()
            print(f"  [IOT] relocation notice sent on :{old_port} "
                  f"-> :{new_port} (grace {grace}s)")
        except Exception as e:
            print(f"  [IOT] relocation notice failed ({e}) — "
                  f"devices may not follow the move")
        time.sleep(grace)

    # 2 + 3. apply, then verify against ss(8)
    try:
        _write_broker_conf(new_port)
        time.sleep(3)
        listening = broker_listening_ports()
        ok = new_port in listening
    except Exception as e:
        listening, ok = [], False
        print(f"  [IOT] hop error: {e}")

    if ok:
        ledger.mark_verified(entry["id"], True)
        try:
            if old_port not in cfg.PROTECTED_PORTS:
                close_port(old_port)
        except Exception:
            pass
        # Did the DEVICE follow? Infrastructure moving is not the same as
        # telemetry surviving -- this is the availability measurement.
        topic = ledger.get_config("telemetry_topic", cfg.TELEMETRY_TOPIC)
        t0 = time.time()
        resumed = wait_for_topic(topic, port=new_port, timeout=30)
        gap = time.time() - t0
        detail = (f"broker {old_port} -> {new_port} | listening: {listening} | "
                  f"telemetry {'RESUMED in %.1fs' % gap if resumed else 'NOT RESUMED in 30s'}")
        return log_mutation("rotate_iot_ip", detail, True)

    # 4. rollback
    print("  [IOT] verification FAILED — restoring previous broker config")
    try:
        if prev_conf.strip():
            cmd = (f"sudo tee {cfg.BROKER_CONF} > /dev/null << 'GHOSTNETEOF'\n"
                   f"{prev_conf}GHOSTNETEOF\nsudo systemctl restart mosquitto")
            _ssh_run(cmd, timeout=25)
        else:
            _write_broker_conf(old_port)
        time.sleep(3)
        restored = old_port in broker_listening_ports()
    except Exception as e:
        restored = False
        print(f"  [IOT] rollback error: {e}")

    ledger.mark_verified(entry["id"], False)
    ledger.set_config("broker_port", old_port if restored else new_port)
    return log_mutation("rotate_iot_ip",
                        f"hop to {new_port} failed | rolled back to {old_port} "
                        f"(restored={restored})", False)


def get_mutation_history():
    return mutation_history


if __name__ == "__main__":
    import sys
    print("=" * 60)
    print("  GhostNet IoT Mutator — verification run")
    print("=" * 60)
    cfg.describe()
    status = get_iot_status()
    print(f"  Broker service   : {'active' if status['active'] else 'NOT ACTIVE'}")
    print(f"  Broker listening : {status['listening']}")
    print(f"  GhostNet conf    :\n{status['conf'] or '    (none)'}\n")

    if "--topic" in sys.argv:
        rotate_iot_topic()
    elif "--port-hop" in sys.argv:
        # --no-announce reproduces the NAIVE hop, for the before/after result
        # --port-hop IS the controlled experiment, so it forces past the interlock
        restart_broker_with_new_port(announce="--no-announce" not in sys.argv, force=True)
    else:
        print("  Usage: python iot_mutator.py --topic | --port-hop [--no-announce]")
        print("  (no mutation performed — this module no longer acts on import)")
    ledger.summary()
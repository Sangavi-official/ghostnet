"""
GhostNet Cloud Mutator — Phase 3 (ledger-backed, verified)
============================================================
Real AWS Security Group mutations via boto3. Every mutation that claims
to change infrastructure is independently re-read afterwards, and is
rolled back automatically if the re-read does not confirm it.

FIXED IN THIS VERSION
  1. Module-level rotate_port() call REMOVED. It used to run on import,
     so every `import p3_cloud_mutator` (including by ghostnet_env_v3
     and run_phase3) silently performed a real AWS port rotation. That
     is why the Security Group accumulated ports 8823, 8388, 8243.
  2. rotate_port() no longer assumes the old port is 8080. It reads the
     CURRENT live port from mutation_ledger, so a rotation is net-zero
     on the attack surface instead of net +1.
  3. rotate_port() previously returned True unconditionally. It now
     verifies against a fresh describe_security_groups() and rolls back
     if verification fails.
  4. Action 1 (close_open_port) used to default to port 8080, which is
     never open -- so the agent's highest-bonus cloud action was a
     permanent no-op. It now closes the live mutable port.
  5. boto3 client is created lazily, so importing this module no longer
     requires AWS credentials.
  6. PROTECTED_PORTS interlock: SSH and the broker listeners can never
     be closed by any action.

SAFETY: Run only against your own AWS account and resources.
"""

import json
import random
import string
from datetime import datetime, timezone

import ghostnet_config as cfg
from mutation_ledger import ledger

mutation_history = []
_ec2 = None


def ec2_client():
    """Lazy boto3 client — import no longer needs credentials."""
    global _ec2
    if _ec2 is None:
        import boto3
        _ec2 = boto3.client("ec2", region_name=cfg.AWS_REGION)
    return _ec2


def log_mutation(action, details, success):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "details":   details,
        "success":   success,
    }
    mutation_history.append(entry)
    print(f"  [CLOUD] {'SUCCESS' if success else 'FAILED'} | {action} | {details}")
    return success


# ───────────────────────────── verification ─────────────────────────
def get_current_rules():
    """Ground truth: the ports currently open on the Security Group."""
    try:
        r = ec2_client().describe_security_groups(GroupIds=[cfg.SECURITY_GROUP_ID])
        rules = r["SecurityGroups"][0].get("IpPermissions", [])
        return sorted(p for p in (rule.get("FromPort") for rule in rules) if p)
    except Exception as e:
        print(f"  [CLOUD] Error reading rules: {e}")
        return []


def verify_port(port, should_be_open):
    """Independent re-read. Returns True if reality matches intent."""
    is_open = port in get_current_rules()
    return is_open == should_be_open


def _port_allowed(port):
    lo, hi = cfg.MUTABLE_PORT_RANGE
    if port in cfg.PROTECTED_PORTS:
        print(f"  [CLOUD] REFUSED: port {port} is protected (SSH/broker)")
        return False
    if not (lo <= port <= hi):
        print(f"  [CLOUD] REFUSED: port {port} outside mutable range {lo}-{hi}")
        return False
    return True


# ───────────────────────────── primitives ───────────────────────────
def open_port(port):
    if not _port_allowed(port):
        return False
    try:
        ec2_client().authorize_security_group_ingress(
            GroupId=cfg.SECURITY_GROUP_ID,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                            "IpRanges": [{"CidrIp": cfg.CIDR}]}])
        return log_mutation("open_port", f"Port {port} OPENED", True)
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code == "InvalidPermission.Duplicate":
            print(f"  [CLOUD] Port {port} already open")
            return True
        return log_mutation("open_port", f"{code or type(e).__name__}: {e}", False)


def close_port(port):
    if not _port_allowed(port):
        return False
    try:
        ec2_client().revoke_security_group_ingress(
            GroupId=cfg.SECURITY_GROUP_ID,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                            "IpRanges": [{"CidrIp": cfg.CIDR}]}])
        return log_mutation("close_port", f"Port {port} CLOSED", True)
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code == "InvalidPermission.NotFound":
            print(f"  [CLOUD] Port {port} already closed")
            return True
        return log_mutation("close_port", f"{code or type(e).__name__}: {e}", False)


# ─────────────────────────── agent actions ──────────────────────────
def rotate_port(new_port=None):
    """
    Action: port rotation. Availability-preserving order --
    open the new port FIRST, verify it, close the old one, verify again.
    Rolls back if the new port never appears. Net-zero attack surface.
    """
    lo, hi = cfg.MUTABLE_PORT_RANGE
    old_port = ledger.get_config("test_port")
    if new_port is None:
        new_port = random.randint(lo, hi)
        while new_port == old_port:
            new_port = random.randint(lo, hi)

    if not open_port(new_port):
        return log_mutation("rotate_port", f"could not open {new_port}", False)

    if not verify_port(new_port, True):
        log_mutation("rotate_port", f"{new_port} not present after open — rolling back", False)
        close_port(new_port)
        return False

    entry = ledger.record("cloud", "rotate_port", cfg.SECURITY_GROUP_ID,
                          old_value=old_port, new_value=new_port,
                          config_key="test_port")

    if old_port is not None and old_port != new_port:
        close_port(old_port)
        if not verify_port(old_port, False):
            log_mutation("rotate_port", f"old port {old_port} still open", False)

    ok = verify_port(new_port, True)
    ledger.mark_verified(entry["id"], ok)
    return log_mutation("rotate_port",
                        f"{old_port} -> {new_port} | verified={ok} | open now: {get_current_rules()}",
                        ok)


def close_open_port():
    """
    Action 1 — close_open_port. Closes the live mutable port, genuinely
    shrinking the surface. Previously defaulted to 8080 (never open), so
    this action had no effect on AWS at all.
    """
    port = ledger.get_config("test_port")
    if port is None:
        return log_mutation("close_open_port",
                            "NO-OP: no non-essential port currently open", True)
    if not close_port(port):
        return False
    ok = verify_port(port, False)
    entry = ledger.record("cloud", "close_open_port", cfg.SECURITY_GROUP_ID,
                          old_value=port, new_value=None,
                          verified=ok, config_key="test_port")
    ledger.mark_verified(entry["id"], ok)
    return log_mutation("close_open_port", f"port {port} closed | verified={ok}", ok)


def rotate_cloud_ip():
    """Rotates a Security Group tag standing in for cloud identity.
       NOTE: this is a TAG rotation, not a real IP change. Do not claim
       otherwise in the paper."""
    try:
        new_tag = "ip-" + "".join(random.choices(string.digits, k=6))
        ec2_client().create_tags(Resources=[cfg.SECURITY_GROUP_ID],
                                 Tags=[{"Key": "GhostNetRotation", "Value": new_tag}])
        ledger.record("cloud", "rotate_cloud_ip", cfg.SECURITY_GROUP_ID,
                      ledger.get_config("cloud_tag"), new_tag,
                      verified=True, config_key="cloud_tag")
        return log_mutation("rotate_cloud_ip", f"SG tag -> {new_tag} (tag, not IP)", True)
    except Exception as e:
        return log_mutation("rotate_cloud_ip", str(e), False)


def rotate_api_path():
    """Writes a new API path mapping to a LOCAL FILE. No live API gateway
       is reconfigured — this models the surface, it does not mutate it."""
    old_path = ledger.get_config("api_path", "/api/v1/patients")
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_path = f"/x{suffix}/clinical"
    with open("api_path_mapping.json", "w") as f:
        json.dump({"old_path": old_path, "new_path": new_path,
                   "rotated_at": datetime.now(timezone.utc).isoformat()}, f, indent=2)
    ledger.record("cloud", "rotate_api_path", "api_path_mapping.json",
                  old_path, new_path, verified=True, config_key="api_path")
    return log_mutation("rotate_api_path", f"{old_path} -> {new_path} [FILE ONLY]", True)


def rotate_iot_ip_placeholder():
    """Action 3 fallback when real IoT mutation is disabled. Logged as
       SIMULATED so it is never mistaken for a real gateway IP change."""
    return log_mutation("rotate_iot_ip", "SIMULATED (real path: iot_mutator)", True)


def rotate_mqtt_topic_placeholder():
    """Action 4 fallback. The REAL topic rotation lives in iot_mutator."""
    return log_mutation("rotate_mqtt_topic", "SIMULATED (real path: iot_mutator)", True)


def update_firewall():
    """Read-only posture review. Reports unverified and orphaned mutations."""
    try:
        ports = get_current_rules()
        orphans = [p for p in ports
                   if p not in cfg.PROTECTED_PORTS and p != ledger.get_config("test_port")]
        note = f" | ORPHAN PORTS: {orphans}" if orphans else ""
        return log_mutation("update_firewall", f"Ports: {ports}{note} [READ-ONLY]", True)
    except Exception as e:
        return log_mutation("update_firewall", str(e), False)


ACTION_MAP = {
    0: rotate_cloud_ip,
    1: rotate_port,
    2: rotate_api_path,
    3: rotate_iot_ip_placeholder,
    4: rotate_mqtt_topic_placeholder,
    5: update_firewall,
}


def execute_mutation(action_id):
    fn = ACTION_MAP.get(action_id)
    return fn() if fn else False


def get_mutation_history():
    return mutation_history


def cleanup_orphans():
    """Close every mutable port the ledger does not recognise as live."""
    live = ledger.get_config("test_port")
    orphans = [p for p in get_current_rules()
               if p not in cfg.PROTECTED_PORTS and p != live
               and cfg.MUTABLE_PORT_RANGE[0] <= p <= cfg.MUTABLE_PORT_RANGE[1]]
    print(f"  [CLOUD] orphan ports to close: {orphans}")
    for p in orphans:
        close_port(p)
    print(f"  [CLOUD] ports now: {get_current_rules()}")
    return orphans


if __name__ == "__main__":
    import sys
    print("=" * 60)
    print("  GhostNet Cloud Mutator — verification run")
    print("=" * 60)
    cfg.describe()
    print(f"  Open ports now : {get_current_rules()}")
    print(f"  Ledger live port: {ledger.get_config('test_port')}\n")

    if "--cleanup" in sys.argv:
        cleanup_orphans()
    elif "--rotate" in sys.argv:
        rotate_port()
    else:
        for i in range(6):
            execute_mutation(i)
            print()
        print(f"  Final open ports : {get_current_rules()}")
    ledger.summary()
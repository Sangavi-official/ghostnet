"""
host_firewall.py — action 5 (update_firewall) made real
========================================================
Before: update_firewall was a read-only posture review. It changed
nothing, yet the v4 agents use it for ~60% of their decisions.

Now: it blocks every high-confidence malicious IP address currently
reported by AbuseIPDB on the EC2 host firewall, and verifies the block
on the host itself.

Why the host firewall and not AWS:
  - Security Groups can only ALLOW traffic; they cannot deny a source.
  - Network ACLs can deny, but hold only ~20 rules per direction.
  - Linux ipset holds tens of thousands of addresses in one hash set,
    matched by a single iptables rule, at negligible cost.

How an update works (atomic, never leaves the host unprotected):
  1. Fetch the AbuseIPDB blacklist (confidence >= 90). The free plan
     allows ~5 downloads a day, so the list is cached locally and
     refreshed at most every CACHE_HOURS.
  2. Drop IPv6 entries and any PROTECTED source (the controller's own
     public IP), so GhostNet can never lock out its own operator.
  3. If the list is identical to the one already applied: NO CHANGE.
  4. Load the list into a fresh set, then SWAP it with the live set in
     one step, and make sure one iptables rule drops the live set.
  5. VERIFY on the host: entry count, sample membership, and that the
     iptables rule exists. Only then is the mutation recorded verified.

Undo everything:   python host_firewall.py --remove
Check state:       python host_firewall.py --status
Apply now:         python host_firewall.py --apply

One-time host setup (on the EC2):   sudo apt-get install -y ipset
"""

import hashlib
import ipaddress
import json
import os
import random
import sys
import time

import requests

import ghostnet_config as cfg
from mutation_ledger import ledger

CACHE_FILE  = "abuse_blocklist.json"
CACHE_HOURS = 6
SET_NAME    = "ghostnet-block"
TMP_SET     = "ghostnet-new"
REMOTE_FILE = "/tmp/ghostnet_block.restore"
RULE        = f"INPUT -m set --match-set {SET_NAME} src -j DROP"


# ─── threat feed ────────────────────────────────────────────────────────
def get_abuse_blocklist(max_age_hours=CACHE_HOURS):
    """IPv4 addresses from the AbuseIPDB blacklist, cached on disk.
    Returns (ips, fetched_at, source) where source is 'cache' or 'live'."""
    try:
        with open(CACHE_FILE) as f:
            cached = json.load(f)
        if time.time() - cached["fetched_at"] < max_age_hours * 3600:
            return cached["ips"], cached["fetched_at"], "cache"
    except Exception:
        cached = None

    from threat_feeds import ABUSEIPDB_API_KEY
    if not ABUSEIPDB_API_KEY:
        if cached:
            return cached["ips"], cached["fetched_at"], "cache (stale, no API key)"
        raise RuntimeError("GHOSTNET_ABUSEIPDB_KEY not set and no cached blocklist")
    r = requests.get("https://api.abuseipdb.com/api/v2/blacklist",
                     headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                     params={"confidenceMinimum": 90, "limit": 10000}, timeout=30)
    if r.status_code != 200:
        # A rejected request is NOT "no malicious IPs" -- fail loudly.
        if cached:
            return cached["ips"], cached["fetched_at"], f"cache (stale, API {r.status_code})"
        raise RuntimeError(f"AbuseIPDB request rejected: HTTP {r.status_code}")
    ips = []
    for row in r.json().get("data", []):
        try:
            ip = ipaddress.ip_address(row["ipAddress"])
        except (KeyError, ValueError):
            continue
        if ip.version == 4 and ip.is_global:
            ips.append(str(ip))
    ips = sorted(set(ips))
    with open(CACHE_FILE, "w") as f:
        json.dump({"fetched_at": time.time(), "ips": ips}, f)
    return ips, time.time(), "live"


def protected_sources():
    """Addresses that must never be blocked: this controller's public IP,
    plus anything in GHOSTNET_PROTECTED_IPS (comma-separated)."""
    keep = {s.strip() for s in os.getenv("GHOSTNET_PROTECTED_IPS", "").split(",") if s.strip()}
    try:
        keep.add(requests.get("https://checkip.amazonaws.com", timeout=5).text.strip())
    except Exception:
        pass
    return keep


def digest(ips):
    return hashlib.sha256("\n".join(sorted(ips)).encode()).hexdigest()[:16]


# ─── host side ──────────────────────────────────────────────────────────
def _ssh():
    from iot_mutator import open_ssh
    return open_ssh()


def _run(ssh, cmd, timeout=60):
    _, out, err = ssh.exec_command(cmd, timeout=timeout)
    code = out.channel.recv_exit_status()
    return code, out.read().decode(), err.read().decode()


def host_state(ssh):
    """Ground truth on the host: entries in the live set, rule present?"""
    code, out, _ = _run(ssh, f"sudo ipset list {SET_NAME} -t 2>/dev/null")
    count = None
    if code == 0:
        for line in out.splitlines():
            if line.startswith("Number of entries:"):
                count = int(line.split(":")[1])
    rule = _run(ssh, f"sudo iptables -C {RULE} 2>/dev/null")[0] == 0
    return {"set_exists": code == 0, "entries": count, "rule_active": rule}


def update_blocklist():
    """Action 5. Returns (success, detail, changed)."""
    try:
        ips, fetched_at, source = get_abuse_blocklist()
    except Exception as e:
        return False, f"no blocklist: {e}", False
    keep = protected_sources()
    ips = [ip for ip in ips if ip not in keep]
    if not ips:
        return False, "blocklist empty after filtering -- nothing applied", False
    new_digest = digest(ips)
    old_digest = ledger.get_config("blocklist_digest")
    age_h = (time.time() - fetched_at) / 3600

    try:
        ssh = _ssh()
    except Exception as e:
        return False, f"SSH to host failed: {e}", False
    try:
        if _run(ssh, "command -v ipset")[0] != 0:
            return False, "ipset not installed on host (sudo apt-get install -y ipset)", False

        state = host_state(ssh)
        if (new_digest == old_digest and state["rule_active"]
                and state["entries"] == len(ips)):
            return True, (f"blocklist already current: {len(ips)} IPs blocked "
                          f"({source}, {age_h:.1f} h old) [NO CHANGE]"), False

        # 4. load into a fresh set, swap atomically, ensure the drop rule
        restore = [f"create {TMP_SET} hash:ip family inet maxelem 131072 -exist",
                   f"flush {TMP_SET}"] + [f"add {TMP_SET} {ip}" for ip in ips]
        sftp = ssh.open_sftp()
        with sftp.file(REMOTE_FILE, "w") as f:
            f.write("\n".join(restore) + "\n")
        sftp.close()
        steps = (f"sudo ipset restore -! < {REMOTE_FILE} && "
                 f"sudo ipset create {SET_NAME} hash:ip family inet maxelem 131072 -exist && "
                 f"sudo ipset swap {TMP_SET} {SET_NAME} && "
                 f"sudo ipset destroy {TMP_SET} && "
                 f"(sudo iptables -C {RULE} 2>/dev/null || sudo iptables -I {RULE.replace('INPUT', 'INPUT 1', 1)}) && "
                 f"rm -f {REMOTE_FILE}")
        code, _, err = _run(ssh, steps, timeout=120)
        if code != 0:
            return False, f"host update failed, live set untouched: {err.strip()[:160]}", False

        # 5. verify on the host
        state = host_state(ssh)
        samples = random.sample(ips, min(5, len(ips)))
        members = all(_run(ssh, f"sudo ipset test {SET_NAME} {ip} 2>/dev/null")[0] == 0
                      for ip in samples)
        ok = state["rule_active"] and state["entries"] == len(ips) and members
    finally:
        ssh.close()

    entry = ledger.record("cloud", "update_firewall", cfg.EC2_HOST,
                          old_value=old_digest, new_value=new_digest,
                          config_key="blocklist_digest")
    ledger.mark_verified(entry["id"], ok)
    if not ok:
        ledger.set_config("blocklist_digest", old_digest)
    detail = (f"host firewall now blocks {state['entries']} AbuseIPDB IPs "
              f"({source}, {age_h:.1f} h old) | rule active={state['rule_active']} | "
              f"sample membership={members} | verified={ok}")
    return ok, detail, True


def remove_blocklist():
    """Undo: remove the drop rule and the set."""
    ssh = _ssh()
    try:
        _run(ssh, f"while sudo iptables -C {RULE} 2>/dev/null; do sudo iptables -D {RULE}; done; "
                  f"sudo ipset destroy {SET_NAME} 2>/dev/null; sudo ipset destroy {TMP_SET} 2>/dev/null; true")
        state = host_state(ssh)
    finally:
        ssh.close()
    ledger.set_config("blocklist_digest", None)
    return state


if __name__ == "__main__":
    if "--apply" in sys.argv:
        ok, detail, changed = update_blocklist()
        print(f"  [FIREWALL] {'SUCCESS' if ok else 'FAILED'} | {detail}")
    elif "--remove" in sys.argv:
        print(f"  [FIREWALL] removed. host state now: {remove_blocklist()}")
    elif "--status" in sys.argv:
        ssh = _ssh()
        try:
            print(f"  [FIREWALL] host state: {host_state(ssh)}")
        finally:
            ssh.close()
        print(f"  [FIREWALL] ledger digest: {ledger.get_config('blocklist_digest')}")
    else:
        print(__doc__)

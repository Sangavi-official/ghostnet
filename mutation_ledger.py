"""
mutation_ledger.py — GhostNet mutation lifecycle tracking
==========================================================
Every mutation GhostNet performs is recorded here with the value it
replaced, so the system can (a) know what the CURRENT live configuration
is instead of assuming a hardcoded default, and (b) restore a previous
known-good configuration when a mutation fails verification.

Motivation (observed, not theoretical): without a ledger, rotate_port()
assumed the old port was always 8080, so every rotation opened a new port
and closed nothing -- the Security Group grew by one open port per run.
An MTD system whose attack surface only grows is not a defence. The same
absence made the broker port hop unsafe, since nothing recorded the port
to fall back to.

Used by p3_cloud_mutator.py (cloud domain) and iot_mutator.py (IoT domain).
Self-test:  python mutation_ledger.py
"""

import json
import os
import time
from datetime import datetime, timezone

LEDGER_PATH = "mutation_ledger.json"


class MutationLedger:

    def __init__(self, path=LEDGER_PATH):
        self.path = path
        self._data = {"entries": [], "config": {}}
        self._load()

    # ---------------------------------------------------------------- io
    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"  [LEDGER] unreadable ({e}) -- starting a fresh ledger")
        self._data.setdefault("entries", [])
        self._data.setdefault("config", {})

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)          # atomic: never a half-written ledger

    # ------------------------------------------------- live configuration
    def get_config(self, key, default=None):
        """The CURRENT live value of a mutable property (e.g. test_port)."""
        return self._data["config"].get(key, default)

    def set_config(self, key, value):
        self._data["config"][key] = value
        self._save()

    # -------------------------------------------------------- recording
    def record(self, domain, action, target, old_value, new_value,
               verified=False, config_key=None):
        """
        Record one mutation. Returns the entry (with its id).

        verified=False means "applied but not yet confirmed at the target".
        Call mark_verified(entry_id, True/False) after the independent
        re-read. Anything left unverified is a rollback candidate.
        """
        entry = {
            "id":         len(self._data["entries"]) + 1,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "epoch":      round(time.time(), 2),
            "domain":     domain,           # "cloud" | "iot"
            "action":     action,           # e.g. "rotate_port"
            "target":     target,           # e.g. the security group id
            "old_value":  old_value,
            "new_value":  new_value,
            "verified":   verified,
            "rolled_back": False,
            "config_key": config_key,
        }
        self._data["entries"].append(entry)
        if config_key is not None:
            self._data["config"][config_key] = new_value
        self._save()
        return entry

    def mark_verified(self, entry_id, ok=True):
        for e in self._data["entries"]:
            if e["id"] == entry_id:
                e["verified"] = bool(ok)
                self._save()
                return e
        return None

    # --------------------------------------------------------- querying
    def entries(self, domain=None, limit=None):
        rows = self._data["entries"]
        if domain:
            rows = [e for e in rows if e["domain"] == domain]
        return rows[-limit:] if limit else rows

    def last(self, action=None, domain=None):
        for e in reversed(self._data["entries"]):
            if e["rolled_back"]:
                continue
            if action and e["action"] != action:
                continue
            if domain and e["domain"] != domain:
                continue
            return e
        return None

    def unverified(self):
        return [e for e in self._data["entries"]
                if not e["verified"] and not e["rolled_back"]]

    # -------------------------------------------------------- rollback
    def rollback(self, entry, restore_fn):
        """
        Reverse one mutation. restore_fn(old_value, new_value) must perform
        the actual undo and return True on success.

        Returns True if the target was restored.
        """
        if entry is None:
            print("  [LEDGER] nothing to roll back")
            return False
        if entry["rolled_back"]:
            print(f"  [LEDGER] entry {entry['id']} already rolled back")
            return False

        print(f"  [LEDGER] rolling back #{entry['id']} {entry['action']}: "
              f"{entry['new_value']} -> {entry['old_value']}")
        try:
            ok = bool(restore_fn(entry["old_value"], entry["new_value"]))
        except Exception as e:
            print(f"  [LEDGER] rollback FAILED: {e}")
            return False

        if ok:
            entry["rolled_back"] = True
            if entry.get("config_key") is not None:
                self._data["config"][entry["config_key"]] = entry["old_value"]
            self._save()
            print(f"  [LEDGER] restored {entry['action']} -> {entry['old_value']}")
        else:
            print(f"  [LEDGER] restore_fn reported failure for #{entry['id']}")
        return ok

    def rollback_unverified(self, restore_map):
        """
        Safety sweep: restore every mutation that never passed verification.
        restore_map maps an action name to its restore function.
        """
        restored = 0
        for entry in list(self.unverified()):
            fn = restore_map.get(entry["action"])
            if fn and self.rollback(entry, fn):
                restored += 1
        print(f"  [LEDGER] safety sweep restored {restored} unverified mutation(s)")
        return restored

    # ----------------------------------------------------------- report
    def summary(self):
        rows = self._data["entries"]
        ok = sum(1 for e in rows if e["verified"] and not e["rolled_back"])
        rb = sum(1 for e in rows if e["rolled_back"])
        un = len(self.unverified())
        print("  " + "-" * 62)
        print(f"  Mutation ledger: {len(rows)} total | {ok} verified | "
              f"{rb} rolled back | {un} unverified")
        print(f"  Live config: {self._data['config']}")
        print("  " + "-" * 62)
        return {"total": len(rows), "verified": ok,
                "rolled_back": rb, "unverified": un}


ledger = MutationLedger()        # shared instance for both mutators


if __name__ == "__main__":
    print("=" * 66)
    print("  mutation_ledger.py — self test (no AWS, no SSH)")
    print("=" * 66)

    lg = MutationLedger("ledger_selftest.json")
    fake_ports = [22, 443, 1883, 9001, 8243]

    def restore_port(old, new):
        if new in fake_ports:
            fake_ports.remove(new)
        if old not in fake_ports:
            fake_ports.append(old)
        return True

    print(f"  start ports        : {sorted(fake_ports)}")

    # good rotation: 8243 -> 8501, verified
    old = lg.get_config("test_port", 8243)
    fake_ports.append(8501)
    fake_ports.remove(old)
    e1 = lg.record("cloud", "rotate_port", "sg-test", old, 8501,
                   config_key="test_port")
    lg.mark_verified(e1["id"], True)
    print(f"  after verified hop : {sorted(fake_ports)}  (live={lg.get_config('test_port')})")

    # bad rotation: 8501 -> 8777, verification fails
    old = lg.get_config("test_port")
    fake_ports.append(8777)
    e2 = lg.record("cloud", "rotate_port", "sg-test", old, 8777,
                   config_key="test_port")
    lg.mark_verified(e2["id"], False)
    print(f"  after failed hop   : {sorted(fake_ports)}  (unverified={len(lg.unverified())})")

    lg.rollback_unverified({"rotate_port": restore_port})
    print(f"  after safety sweep : {sorted(fake_ports)}  (live={lg.get_config('test_port')})")
    lg.summary()

    assert 8777 not in fake_ports, "rollback failed to close the bad port"
    assert lg.get_config("test_port") == 8501
    print("  SELF TEST PASSED — surface restored, no orphan ports.")
    os.remove("ledger_selftest.json")

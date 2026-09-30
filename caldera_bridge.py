"""
caldera_bridge.py — GhostNet Phase 5
=====================================
Connects to a locally-running CALDERA server via its REST API.
Creates a healthcare-specific adversary, starts an operation, and
continuously polls for executed TTPs (ATT&CK techniques).

Each TTP is mapped to one or more threat dimensions in GhostNet's
12-dim state vector, producing a "threat injection" dict that
phase5_eval.py overlays on top of the normal threat-feed values.

WHAT IS REAL AND WHAT IS REPLAY (for the paper)
  - get_threat_injection() reads techniques that CALDERA actually
    executed (links with status 0) when an agent is deployed.
  - simulate_attack_sequence() / _inject_manual_ttp() inject the
    kill chain locally. That is deterministic REPLAY, not emulation.
  - The "Hospital-IoT-Ransomware" adversary is created without
    abilities, so it executes nothing by itself. The live evidence is a
    separate Discovery operation (T1033, T1087.001, T1057).

Usage (standalone test):
    python caldera_bridge.py

Usage (from eval):
    from caldera_bridge import CalderaBridge
    bridge = CalderaBridge()
    bridge.start_operation()
    injection = bridge.get_threat_injection()   # call each env step
    bridge.stop_operation()
"""

import os
import time
import logging
import requests
from typing import Dict, Optional

# ── Config ────────────────────────────────────────────────────────────────────
CALDERA_URL    = "http://localhost:8888"
# Lab server key from CALDERA's conf/local.yml. Override per machine:
#   setx GHOSTNET_CALDERA_KEY "..."
API_KEY        = os.getenv("GHOSTNET_CALDERA_KEY", "WhrGbb89JW60pJmCfli7U0Ir2ibMrX30QbpoTuJfORY")
OPERATION_NAME = "GhostNet-Phase5-Eval"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CALDERA] %(levelname)s: %(message)s"
)
log = logging.getLogger("caldera_bridge")

# ── TTP → GhostNet threat dimension mapping ──────────────────────────────────
# Single source of truth: caldera_ttp_map.py (the corrected mapping used by
# every evaluation). This file previously kept its own older copy, which
# disagreed with it (e.g. T1071 raised no attack surface at all), so the
# standalone test in logs/e11_caldera_bridge.txt used the OLD mapping.
from caldera_ttp_map import TTP_BOOST_MAP, KILL_CHAIN  # noqa: E402

# Adversary definition — healthcare-targeted hospital ransomware kill-chain
HEALTHCARE_ADVERSARY = {
    "name": "Hospital-IoT-Ransomware",
    "description": (
        "Simulates the AIIMS Delhi 2022-style ransomware kill-chain targeting "
        "hospital IoT and cloud infrastructure. Maps to MITRE ATT&CK techniques "
        "observed in healthcare sector incidents."
    ),
    # Technique IDs in kill-chain order (from caldera_ttp_map.KILL_CHAIN).
    # NOTE: CALDERA's atomic_ordering expects ABILITY ids, not technique
    # ids, and this adversary is created without abilities. Operations
    # started from it therefore execute nothing; the chain below is used
    # only by simulate_attack_sequence(), which is a REPLAY, not emulation.
    "atomic_ordering": list(KILL_CHAIN),
    "tags": ["healthcare", "ransomware", "iot", "ghostnet-eval"],
}


class CalderaBridge:
    """
    Manages CALDERA lifecycle and provides threat injection data
    to GhostNet's evaluation environment.
    """

    def __init__(self, caldera_url: str = CALDERA_URL, api_key: str = API_KEY):
        self.base_url    = caldera_url.rstrip("/")
        self.headers     = {
            "KEY": api_key,
            "Content-Type": "application/json",
        }
        self.operation_id: Optional[str] = None
        self._active_ttps: Dict[str, float] = {}  # TTP_ID -> activation_time
        self._injection_cache: Dict[int, float] = {}

        # Verify server is reachable
        self._verify_connection()

    # ── Connection ────────────────────────────────────────────────────────────

    def _verify_connection(self):
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/operations",
                headers=self.headers,
                timeout=5
            )
            r.raise_for_status()
            log.info("CALDERA server reachable at %s", self.base_url)
        except Exception as e:
            raise ConnectionError(
                f"Cannot reach CALDERA at {self.base_url}. "
                f"Is Docker running, and is API_KEY correct? Error: {e}"
            )

    # ── Adversary setup ───────────────────────────────────────────────────────

    def _get_or_create_adversary(self) -> str:
        """Return adversary ID, creating if it doesn't exist."""
        r = requests.get(
            f"{self.base_url}/api/v2/adversaries",
            headers=self.headers
        )
        r.raise_for_status()
        for adv in r.json():
            if adv.get("name") == HEALTHCARE_ADVERSARY["name"]:
                log.info("Adversary already exists: %s", adv["adversary_id"])
                return adv["adversary_id"]

        # Create new adversary
        payload = {
            "name":        HEALTHCARE_ADVERSARY["name"],
            "description": HEALTHCARE_ADVERSARY["description"],
            "tags":        HEALTHCARE_ADVERSARY["tags"],
        }
        r = requests.post(
            f"{self.base_url}/api/v2/adversaries",
            headers=self.headers,
            json=payload
        )
        r.raise_for_status()
        adv_id = r.json()["adversary_id"]
        log.info("Created adversary: %s", adv_id)
        return adv_id

    # ── Operation lifecycle ───────────────────────────────────────────────────

    def start_operation(self) -> str:
        """Create and start a CALDERA operation. Returns operation ID."""
        adv_id = self._get_or_create_adversary()

        payload = {
            "name":       OPERATION_NAME,
            "adversary":  {"adversary_id": adv_id},
            "planner":    {"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e31a"},  # atomic
            "auto_close": False,
            "state":      "running",
        }
        r = requests.post(
            f"{self.base_url}/api/v2/operations",
            headers=self.headers,
            json=payload
        )
        r.raise_for_status()
        self.operation_id = r.json()["id"]
        log.info("Operation started: %s", self.operation_id)
        return self.operation_id

    def stop_operation(self):
        """Gracefully close the CALDERA operation."""
        if not self.operation_id:
            return
        r = requests.patch(
            f"{self.base_url}/api/v2/operations/{self.operation_id}",
            headers=self.headers,
            json={"state": "finished"}
        )
        r.raise_for_status()
        log.info("Operation closed: %s", self.operation_id)
        self.operation_id = None

    # ── TTP polling ───────────────────────────────────────────────────────────

    def _poll_executed_links(self) -> list:
        """Fetch all executed links (TTPs) from the running operation."""
        if not self.operation_id:
            return []
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/operations/{self.operation_id}/links",
                headers=self.headers,
                timeout=5
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            log.warning("Failed to poll CALDERA links: %s", e)
            return []

    def _inject_manual_ttp(self, ttp_id: str):
        """
        Manually inject a TTP activation (used in headless/no-agent mode
        where CALDERA cannot execute against real infrastructure).
        Simulates attack progression through the kill-chain.
        """
        if ttp_id not in self._active_ttps:
            self._active_ttps[ttp_id] = time.time()
            log.info("TTP activated (manual injection): %s", ttp_id)

    def simulate_attack_sequence(self, delay_seconds: float = 2.0):
        """
        Headless mode: replay the healthcare kill-chain with delays
        between each TTP — simulates a real attacker progression.
        Call this in a background thread during evaluation.
        """
        log.info("Starting simulated attack kill-chain (%d TTPs)",
                 len(HEALTHCARE_ADVERSARY["atomic_ordering"]))
        for ttp in HEALTHCARE_ADVERSARY["atomic_ordering"]:
            self._inject_manual_ttp(ttp)
            time.sleep(delay_seconds)
        log.info("Kill-chain simulation complete")

    # ── Threat injection ──────────────────────────────────────────────────────

    def get_threat_injection(self) -> Dict[int, float]:
        """
        Returns a dict {state_dimension_index: boost_value} representing
        the current attacker pressure. phase5_eval.py adds this to
        the environment's base observation before feeding it to the agent.

        Boosts decay over time (30s half-life) so a stale TTP loses impact,
        forcing the agent to keep mutating rather than settling.
        """
        # Poll real CALDERA links (works when sandcat agent is deployed)
        for link in self._poll_executed_links():
            ability = link.get("ability", {})
            ttp_id  = ability.get("technique_id", "")
            status  = link.get("status", -1)
            if status == 0 and ttp_id:  # 0 = success
                if ttp_id not in self._active_ttps:
                    self._active_ttps[ttp_id] = time.time()

        # Build injection vector with time-decay
        injection: Dict[int, float] = {}
        now = time.time()
        HALF_LIFE = 30.0  # seconds

        for ttp_id, activation_time in list(self._active_ttps.items()):
            elapsed = now - activation_time
            decay   = 0.5 ** (elapsed / HALF_LIFE)

            if decay < 0.05:  # TTP influence effectively zero
                del self._active_ttps[ttp_id]
                continue

            boosts = TTP_BOOST_MAP.get(ttp_id, {})
            for dim, base_boost in boosts.items():
                injection[dim] = min(1.0, injection.get(dim, 0.0) + base_boost * decay)

        self._injection_cache = injection
        return injection

    def get_active_ttp_count(self) -> int:
        return len(self._active_ttps)

    def get_active_ttps(self) -> list:
        return list(self._active_ttps.keys())

    def reset(self):
        """Clear all active TTPs (call between evaluation episodes)."""
        self._active_ttps.clear()
        self._injection_cache.clear()


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import threading

    bridge = CalderaBridge()
    print("\n[TEST] Starting operation...")
    bridge.start_operation()

    print("[TEST] Injecting kill-chain in background (2s between TTPs)...")
    t = threading.Thread(target=bridge.simulate_attack_sequence, kwargs={"delay_seconds": 2.0})
    t.start()

    print("[TEST] Polling threat injection every 3s for 30s...\n")
    for _ in range(10):
        time.sleep(3)
        inj = bridge.get_threat_injection()
        ttps = bridge.get_active_ttps()
        print(f"  Active TTPs ({len(ttps)}): {ttps}")
        print(f"  Injection vector: { {k: round(v,3) for k,v in inj.items()} }\n")

    t.join()
    bridge.stop_operation()
    print("[TEST] Done.")
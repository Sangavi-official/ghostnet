"""
caldera_bridge.py — GhostNet Phase 5
=====================================
Connects to a locally-running CALDERA server via its REST API.
Creates a healthcare-specific adversary, starts an operation, and
continuously polls for executed TTPs (ATT&CK techniques).

Each TTP is mapped to one or more threat dimensions in GhostNet's
12-dim state vector, producing a "threat injection" dict that
phase5_eval.py overlays on top of the normal threat-feed values.

Usage (standalone test):
    python caldera_bridge.py

Usage (from eval):
    from caldera_bridge import CalderaBridge
    bridge = CalderaBridge()
    bridge.start_operation()
    injection = bridge.get_threat_injection()   # call each env step
    bridge.stop_operation()
"""

import time
import logging
import requests
from typing import Dict, Optional

# ── Config ────────────────────────────────────────────────────────────────────
CALDERA_URL    = "http://localhost:8888"
API_KEY        = "WhrGbb89JW60pJmCfli7U0Ir2ibMrX30QbpoTuJfORY"   # CHECK THIS — verify against conf/local.yml
OPERATION_NAME = "GhostNet-Phase5-Eval"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CALDERA] %(levelname)s: %(message)s"
)
log = logging.getLogger("caldera_bridge")

# ── TTP → GhostNet threat dimension mapping ──────────────────────────────────
# GhostNet 12-dim state (ACTUAL layout, from ghostnet_env_v2.py):
#   [0]  cloud_ip_exposure
#   [1]  open_ports
#   [2]  api_exposure
#   [3]  iot_ip_exposure
#   [4]  mqtt_exposure
#   [5]  cve_score            (live)
#   [6]  shodan_score         (live)
#   [7]  traffic_load
#   [8]  recon_attempts
#   [9]  time_since_mutation
#   [10] abuse_score          (live)
#   [11] attck_score          (live)
#
# Each ATT&CK technique ID maps to {dimension_index: boost_value}.
# Boost values are ADDED to existing env threat scores (clamped to 1.0).

TTP_BOOST_MAP: Dict[str, Dict[int, float]] = {
    # Initial Access
    "T1190": {2: 0.4, 1: 0.5, 5: 0.3},    # Exploit Public-Facing Application -> API + ports + CVE
    "T1133": {1: 0.3, 7: 0.3},             # External Remote Services -> ports + traffic
    "T1078": {10: 0.3, 11: 0.2},           # Valid Accounts (credential abuse) -> abuse + attck

    # Discovery
    "T1046": {1: 0.6, 8: 0.5, 7: 0.3},    # Network Service Discovery (port scan) -> ports + recon
    "T1082": {8: 0.2, 11: 0.15},           # System Information Discovery -> recon
    "T1083": {8: 0.2, 11: 0.15},           # File & Directory Discovery -> recon

    # Lateral Movement
    "T1021": {3: 0.6, 4: 0.4, 8: 0.3},    # Remote Services (SSH/RDP) -> IoT gateway + MQTT
    "T1563": {3: 0.5, 8: 0.25},            # Remote Service Session Hijacking

    # Command & Control
    "T1071": {10: 0.7, 7: 0.4, 11: 0.35}, # Application Layer Protocol (C2) -> abuse + traffic
    "T1095": {10: 0.5, 7: 0.3},            # Non-Application Layer Protocol
    "T1572": {10: 0.6, 11: 0.3},           # Protocol Tunneling (DNS/HTTPS C2)

    # Exfiltration
    "T1041": {4: 0.7, 7: 0.5, 11: 0.4},   # Exfiltration Over C2 Channel -> MQTT
    "T1048": {4: 0.8, 1: 0.3, 11: 0.45},  # Exfil Over Alternative Protocol

    # Impact — highest priority for hospital context
    "T1486": {0: 0.9, 5: 0.6, 10: 0.5},   # Data Encrypted for Impact (RANSOMWARE) -> cloud IP + CVE
    "T1489": {4: 0.7, 0: 0.5},             # Service Stop (disrupts infusion pump comms) -> MQTT
    "T1529": {0: 0.6, 5: 0.45},            # System Shutdown/Reboot
    "T1565": {4: 0.5, 8: 0.4, 11: 0.35},  # Data Manipulation (alter pump dosage data) -> MQTT
}

# Adversary definition — healthcare-targeted hospital ransomware kill-chain
HEALTHCARE_ADVERSARY = {
    "name": "Hospital-IoT-Ransomware",
    "description": (
        "Simulates the AIIMS Delhi 2022-style ransomware kill-chain targeting "
        "hospital IoT and cloud infrastructure. Maps to MITRE ATT&CK techniques "
        "observed in healthcare sector incidents."
    ),
    "atomic_ordering": [
        "T1046",  # scan for open ports / MQTT 1883
        "T1190",  # exploit public-facing EC2 / API
        "T1078",  # use stolen credentials
        "T1021",  # lateral movement via SSH
        "T1071",  # establish C2 channel
        "T1041",  # exfiltrate patient data
        "T1565",  # manipulate infusion pump telemetry
        "T1486",  # encrypt files (ransomware payload)
        "T1489",  # stop hospital services
    ],
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
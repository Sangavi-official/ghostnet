"""
caldera_ttp_map.py — ATT&CK technique -> GhostNet state boosts
================================================================
CORRECTED MAPPING.

The mapping previously embedded in caldera_bridge.py was written against
a state vector that does not exist in this project. It assumed:

    0 cvss | 1 abuseipdb | 2 attck | 3 port_exposure | 4 connection_rate
    5 mutation_count | 6 time_since_mutation | 7 threat_composite
    8 lateral_movement | 9 data_exfil | 10 c2 | 11 ransomware

The real vector (STATE_VECTOR_SPEC.txt, ghostnet_env_v2.py) is:

    [0]  cloud_ip_exposure     [6]  shodan_score   (live feed)
    [1]  open_ports            [7]  traffic_load
    [2]  api_exposure          [8]  recon_attempts
    [3]  iot_ip_exposure       [9]  time_since_mutation
    [4]  mqtt_exposure        [10]  abuse_score    (live feed)
    [5]  cve_score  (live)    [11]  attck_score    (live feed)

Every index disagreed, so adversary activity was injected into the wrong
dimensions. Any Phase 5 result produced with the old map is invalid.

DESIGN RULE for this table: a technique raises the exposure of the attack
surfaces it actually touches, so the correct defensive mutation is the
one that relocates that surface. Live-feed dimensions (5, 6, 10, 11) are
boosted only where the technique genuinely corresponds to that signal.
Index 9 is never boosted -- the environment resets it every step.
"""

STATE_LABELS = [
    "cloud_ip_exposure", "open_ports", "api_exposure", "iot_ip_exposure",
    "mqtt_exposure", "cve_score", "shodan_score", "traffic_load",
    "recon_attempts", "time_since_mutation", "abuse_score", "attck_score",
]

# Defensive action that SHOULD win for each surface (used for scoring the
# agent's kill-chain response in phase5_eval).
SURFACE_TO_ACTION = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4}

TTP_BOOST_MAP = {
    # ── Reconnaissance / Discovery ──────────────────────────────────
    "T1046": {1: 0.50, 8: 0.60, 6: 0.40, 11: 0.20},   # Network Service Discovery
    "T1082": {8: 0.30, 11: 0.15},                      # System Information Discovery
    "T1083": {2: 0.25, 8: 0.25},                       # File & Directory Discovery
    "T1057": {8: 0.30},                                # Process Discovery
    "T1033": {8: 0.25},                                # Owner/User Discovery
    "T1087": {8: 0.30, 10: 0.20},                      # Account Discovery

    # ── Initial Access ──────────────────────────────────────────────
    "T1190": {2: 0.60, 0: 0.30, 5: 0.30},              # Exploit Public-Facing App
    "T1133": {1: 0.40, 0: 0.30},                       # External Remote Services
    "T1078": {0: 0.25, 10: 0.35},                      # Valid Accounts

    # ── Lateral Movement ────────────────────────────────────────────
    "T1021": {3: 0.50, 1: 0.30, 7: 0.30},              # Remote Services (SSH/RDP)
    "T1563": {3: 0.40, 4: 0.30},                       # Session Hijacking

    # ── Command & Control ───────────────────────────────────────────
    "T1071": {4: 0.60, 7: 0.40, 11: 0.30},             # Application Layer Protocol
    "T1095": {4: 0.40, 7: 0.30},                       # Non-Application Layer
    "T1572": {2: 0.40, 7: 0.30},                       # Protocol Tunneling

    # ── Exfiltration ────────────────────────────────────────────────
    "T1041": {4: 0.50, 7: 0.60, 2: 0.30},              # Exfil Over C2 Channel
    "T1048": {2: 0.50, 1: 0.40, 7: 0.50},              # Exfil Alternative Protocol

    # ── Impact (hospital-critical) ──────────────────────────────────
    # Broad, multi-surface events: several surfaces hot at once is exactly
    # the condition under which update_firewall (action 5) should win.
    "T1486": {0: 0.45, 1: 0.45, 2: 0.45, 3: 0.50, 4: 0.50, 5: 0.40, 11: 0.40},
    "T1489": {4: 0.60, 3: 0.40, 11: 0.30},             # Service Stop (pump comms)
    "T1529": {3: 0.50, 4: 0.30},                       # System Shutdown/Reboot
    "T1565": {4: 0.70, 3: 0.30},                       # Data Manipulation (dosage)
}

# AIIMS-Delhi-style hospital ransomware kill chain, in execution order.
KILL_CHAIN = ["T1046", "T1190", "T1078", "T1021", "T1071",
              "T1041", "T1565", "T1486", "T1489"]

TTP_NAMES = {
    "T1046": "Network Service Discovery", "T1082": "System Info Discovery",
    "T1083": "File & Directory Discovery", "T1057": "Process Discovery",
    "T1033": "System Owner Discovery", "T1087": "Account Discovery",
    "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
    "T1078": "Valid Accounts", "T1021": "Remote Services",
    "T1563": "Session Hijacking", "T1071": "Application Layer Protocol (C2)",
    "T1095": "Non-Application Layer Protocol", "T1572": "Protocol Tunneling",
    "T1041": "Exfiltration Over C2", "T1048": "Exfil Over Alt Protocol",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop",
    "T1529": "System Shutdown/Reboot", "T1565": "Data Manipulation",
}


def apply_injection(state, boosts, clamp=1.0):
    """Add TTP boosts to a copy of the state vector, clamped to [0, 1]."""
    s = list(state)
    for idx, boost in boosts.items():
        if idx == 9:                       # env resets this every step
            continue
        s[idx] = min(clamp, float(s[idx]) + float(boost))
    return s


def expected_action(boosts):
    """
    The defensively correct action for a technique: relocate the surface
    it raised most. If three or more surfaces are raised together, the
    broad action (5, update_firewall) is the appropriate response.
    """
    surface_boosts = {i: b for i, b in boosts.items() if i in SURFACE_TO_ACTION}
    if not surface_boosts:
        return None
    if len(surface_boosts) >= 3:
        return 5
    return SURFACE_TO_ACTION[max(surface_boosts, key=surface_boosts.get)]


def describe_chain():
    print(f"  {'TTP':<8}{'technique':<38}{'surfaces raised':<34}expected")
    print("  " + "-" * 92)
    for ttp in KILL_CHAIN:
        b = TTP_BOOST_MAP[ttp]
        surfaces = ", ".join(f"{STATE_LABELS[i]}+{v:.2f}"
                             for i, v in b.items() if i in SURFACE_TO_ACTION)
        exp = expected_action(b)
        print(f"  {ttp:<8}{TTP_NAMES[ttp][:36]:<38}{surfaces[:32]:<34}"
              f"action {exp}")


if __name__ == "__main__":
    print("=" * 96)
    print("  GhostNet — corrected ATT&CK to state mapping")
    print("=" * 96)
    describe_chain()
    print("\n  Sanity check: no boost targets index 9, all indices in range 0-11")
    bad = [(t, i) for t, b in TTP_BOOST_MAP.items() for i in b
           if i == 9 or not 0 <= i <= 11]
    print(f"  Violations: {bad if bad else 'none'}")

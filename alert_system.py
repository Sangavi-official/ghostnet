"""
alert_system.py — GhostNet Alerting
=====================================
Fires an alert when a mutation is triggered by genuine suspicious
activity (CALDERA-detected TTPs or high live threat-feed scores),
as opposed to routine/preventive mutation.

Desktop notifications require: pip install win10toast-click --user
"""

import time
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ALERT] %(levelname)s: %(message)s"
)
log = logging.getLogger("ghostnet_alerts")

# ── Desktop notification setup ───────────────────────────────────────────────
try:
    from win10toast_click import ToastNotifier
    toaster = ToastNotifier()
    DESKTOP_AVAILABLE = True
except ImportError:
    DESKTOP_AVAILABLE = False
    log.warning("win10toast_click not installed — desktop alerts disabled. "
                "Run: pip install win10toast-click --user")


def send_desktop_alert(action_name, reasons):
    """Fire a Windows toast notification. Never crashes the pipeline if it fails."""
    if not DESKTOP_AVAILABLE:
        return
    try:
        toaster.show_toast(
            "GhostNet — Suspicious Activity Detected",
            f"Mutation triggered: {action_name}\n{'; '.join(reasons)}",
            duration=6,
            threaded=True   # non-blocking, keeps the pipeline running
        )
    except Exception as e:
        log.warning("Desktop alert failed: %s", e)


ACTION_NAMES = ["rotate_cloud_ip", "close_open_port", "rotate_api_path",
                "rotate_iot_ip", "rotate_mqtt_topic", "update_firewall"]

# Thresholds — tune these to your taste
SUSPICION_THRESHOLD = 0.5   # any injected dimension above this = suspicious
CVE_THRESHOLD       = 0.7   # live CVE score above this = suspicious even with no CALDERA activity
ABUSE_THRESHOLD     = 0.7

alert_log = []  # keeps a running record for the demo / report


def evaluate_and_alert(action, injection: dict, state, active_ttps=None):
    """
    Call this right after the agent picks an action.
      action       - int, the action the agent chose
      injection    - dict from bridge.get_threat_injection() (may be {})
      state        - the 12-dim state array (post-injection)
      active_ttps  - list of active TTP IDs from bridge.get_active_ttps() (optional)
    """
    active_ttps = active_ttps or []

    reasons = []

    # Reason 1: CALDERA detected active attack techniques
    if active_ttps:
        reasons.append(f"active ATT&CK techniques: {', '.join(active_ttps)}")

    # Reason 2: any injected dimension crossed the suspicion threshold
    if injection and max(injection.values(), default=0) >= SUSPICION_THRESHOLD:
        top_dim = max(injection, key=injection.get)
        reasons.append(f"threat injection spike on dim {top_dim} ({injection[top_dim]:.2f})")

    # Reason 3: live threat-feed scores are independently high
    if float(state[5]) >= CVE_THRESHOLD:
        reasons.append(f"critical CVE score ({state[5]:.2f})")
    if float(state[10]) >= ABUSE_THRESHOLD:
        reasons.append(f"high abuse/malicious-IP score ({state[10]:.2f})")

    is_suspicious = len(reasons) > 0
    action_name = ACTION_NAMES[action]

    entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action_name,
        "suspicious": is_suspicious,
        "reasons": reasons,
    }
    alert_log.append(entry)

    if is_suspicious:
        log.warning(
            "SUSPICIOUS ACTIVITY -> mutation triggered: %s | reasons: %s",
            action_name, "; ".join(reasons)
        )
        send_desktop_alert(action_name, reasons)
    else:
        log.info("Routine mutation: %s (no active threat signal)", action_name)

    return entry


def get_alert_history():
    return alert_log


def get_suspicious_count():
    return sum(1 for e in alert_log if e["suspicious"])
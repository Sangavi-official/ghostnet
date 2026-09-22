"""
dashboard/integration/instrumented_env.py
==========================================
Wraps GhostNetEnvV3 so a dashboard can observe a REAL run.

It is a subclass. It calls super().step() and reads what GhostNet
produced. It does not reimplement the state, the reward, the action
semantics, or any mutation. Delete this folder and GhostNet is
unchanged.

WHAT IT CAN SEE, AND FROM WHERE
  state          env.state                            (ghostnet_env_v2)
  reward         return value of step()               (ghostnet_env_v3)
  action         passed in by the runner              (PPO.predict)
  mutation       tail diff of the executors' own
                 mutation_history lists               (p3_cloud_mutator,
                                                       iot_mutator)
  verification   mutation_ledger.json delta           (mutation_ledger)
  surface        get_current_rules() / broker ports   (live re-read)

WHAT IT CANNOT SEE (emitted as null, never invented)
  * Raw threat-feed detail (CVE ids, service counts). threat_feeds
    PRINTS these and returns only the four scores.
  * A structured verification flag from the executors -- they return a
    bare bool; the evidence is inside a human-readable string. The
    ledger is used instead, and the raw string is passed through so the
    dashboard can show exactly what GhostNet said.
"""

import json
import os

from ghostnet_env_v3 import GhostNetEnvV3
import p3_cloud_mutator as cloud
import iot_mutator as iot

from dashboard.backend.bus import bus

# Canonical action semantics, from ghostnet_env_v2's own action_names.
ACTION_NAMES = ["rotate_cloud_ip", "close_open_port", "rotate_api_path",
                "rotate_iot_ip", "rotate_mqtt_topic", "update_firewall"]


def executor_for(action):
    """
    The function the cloud executor will ACTUALLY call for this action.
    Read from p3_cloud_mutator.ACTION_MAP rather than assumed, because
    ACTION_MAP[1] may be close_open_port or rotate_port depending on
    which revision is installed. The dashboard reports what runs, not
    what it expects to run.
    """
    try:
        fn = cloud.ACTION_MAP.get(action)
        return fn.__name__ if fn else None
    except Exception:
        return None

# Capability truth, verified against the code on 2026-09-20.
# Shown verbatim in the UI. Update here if the implementation changes.
ACTION_STATUS = {
    0: ("PARTIAL",  "Writes a Security Group tag. Not an EC2 public-IP replacement."),
    1: ("VERIFIED", "Real AWS port operation. The executor actually bound to "
                    "this action is reported per step in `executor`."),
    2: ("PARTIAL",  "Writes api_path_mapping.json. No live API gateway is reconfigured."),
    3: ("GATED",    "Broker relocation. Disabled unless GHOSTNET_ALLOW_BROKER_HOP=1."),
    4: ("VERIFIED", "Real MQTT control message, confirmed by telemetry on the new topic."),
    5: ("PARTIAL",  "Read-only posture review in the cloud executor."),
}

LEDGER_PATH = os.environ.get("GHOSTNET_LEDGER", "mutation_ledger.json")


def _ledger_entries():
    try:
        with open(LEDGER_PATH, encoding="utf-8") as f:
            return json.load(f).get("entries", [])
    except Exception:
        return []


class InstrumentedEnvV3(GhostNetEnvV3):
    """GhostNetEnvV3 + observation. No behavioural change."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._step_no = 0
        bus.emit("session_config", "dashboard.integration.instrumented_env",
                 use_real_cloud=self.use_real_cloud,
                 use_real_iot=self.use_real_iot,
                 action_status={str(k): {"status": v[0], "note": v[1]}
                                for k, v in ACTION_STATUS.items()})
        # The four feed scores GhostNet actually cached at construction.
        bus.emit("feeds", "threat_feeds.get_live_threat_state",
                 cve=float(self.cached_cve), shodan=float(self.cached_shodan),
                 abuse=float(self.cached_abuse), attck=float(self.cached_attck),
                 raw=None,                       # printed by threat_feeds, not returned
                 raw_note="Raw CVE ids and service counts are printed by "
                          "threat_feeds, not returned. Not exposed by backend.",
                 live=bool(self.use_live_feeds),
                 fetched="once at environment construction")

    def reset(self, **kw):
        obs, info = super().reset(**kw)
        bus.emit("state_update", "ghostnet_env_v2.state",
                 step=self._step_no, state=[float(x) for x in obs],
                 inert_dims=[6, 9, 10],
                 inert_note="6 Shodan and 10 AbuseIPDB are degenerate by "
                            "normalisation; 9 is reset every step.")
        return obs, info

    def step(self, action):
        action = int(action)
        self._step_no += 1
        st, note = ACTION_STATUS.get(action, ("UNKNOWN", ""))

        if action == 3 and self.use_real_iot:
            executor = "iot_mutator.restart_broker_with_new_port"
        elif action == 4 and self.use_real_iot:
            executor = "iot_mutator.rotate_iot_topic"
        elif self.use_real_cloud:
            fn = executor_for(action)
            executor = f"p3_cloud_mutator.{fn}" if fn else None
        else:
            executor = None      # simulated only: the env moved, infra did not

        bus.emit("action_selected", "PPO.predict (runner)",
                 step=self._step_no, action=action,
                 action_name=ACTION_NAMES[action],
                 executor=executor,
                 simulated_only=executor is None,
                 capability=st, capability_note=note)

        n_cloud = len(cloud.get_mutation_history())
        n_iot = len(iot.get_mutation_history())
        n_led = len(_ledger_entries())

        obs, reward, done, truncated, info = super().step(action)   # UNCHANGED CORE

        # What the executors themselves recorded during that call.
        new_cloud = cloud.get_mutation_history()[n_cloud:]
        new_iot = iot.get_mutation_history()[n_iot:]
        for entry in new_cloud + new_iot:
            bus.emit("mutation_result",
                     "p3_cloud_mutator.mutation_history" if entry in new_cloud
                     else "iot_mutator.mutation_history",
                     step=self._step_no, action=action,
                     domain="cloud" if entry in new_cloud else "iot",
                     name=entry.get("action"), success=bool(entry.get("success")),
                     details=entry.get("details"))

        # Structured verification, from the ledger the executors write.
        for e in _ledger_entries()[n_led:]:
            bus.emit("verification", "mutation_ledger.json",
                     step=self._step_no, ledger_id=e.get("id"),
                     mutation=e.get("action"), domain=e.get("domain"),
                     verified=bool(e.get("verified")),
                     rolled_back=bool(e.get("rolled_back")),
                     old_value=e.get("old_value"), new_value=e.get("new_value"))

        bus.emit("state_update", "ghostnet_env_v2.state",
                 step=self._step_no, state=[float(x) for x in obs],
                 inert_dims=[6, 9, 10])
        bus.emit("reward", "ghostnet_env_v3.step",
                 step=self._step_no, value=float(reward),
                 note="TADR training signal (includes the v3 +0.05/-0.02 "
                      "real-execution adjustment). Not a security score.")
        return obs, reward, done, truncated, info

    def emit_surface(self):
        """Live re-read of both surfaces. Fields are null when unreadable."""
        ports = None
        try:
            if self.use_real_cloud:
                ports = [int(p) for p in cloud.get_current_rules()]
        except Exception:
            ports = None
        broker = None
        try:
            if self.use_real_iot:
                broker = [int(p) for p in iot.broker_listening_ports()]
        except Exception:
            broker = None
        bus.emit("surface", "describe_security_groups + ss(8)",
                 ports_open=ports, broker_ports=broker,
                 protected=[22, 443, 1883, 9001])

    def emit_session_end(self):
        s = self.get_cloud_stats()
        bus.emit("session_end", "ghostnet_env_v3.get_cloud_stats",
                 real_mutations=s["real_mutations"],
                 failed_mutations=s["failed_mutations"])

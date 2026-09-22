# GhostNet — Complete Project Handoff (v2)

**Written:** 20 September 2026
**Purpose:** Full context transfer. The reader (human or AI) has NO memory of
the working session that produced this. Everything needed to finish the
project is in this file.

**Project:** GhostNet — Deep Reinforcement Learning driven Moving Target
Defense for hospital IoT and cloud infrastructure
**Team:** Suha N, Meghana N, Sangavi S
**Guide:** Dr. Mithun D Souza
**Working machine:** `C:\Users\nazee\OneDrive\Documents\capstone-project`
**Status:** All five phases implemented, evaluated, and demonstrated end to
end with a clean full-pipeline run (20/20 real mutations verified, 0 failures
— §4.4). Code work is COMPLETE. **The paper and project report are NOT
written.** That is the only remaining work.

---

## 0. TL;DR for whoever picks this up

1. The system works. Every headline claim is backed by a log file in `logs/`.
2. The single most important trap: **`ghostnet_smart.zip` is the good model.
   `ghostnet_final.zip` is a COLLAPSED model that looks fine and is useless.**
   Several scripts historically loaded the wrong one.
3. Don't rewrite anything. The architecture is sound; a long list of
   peripheral bugs was fixed on 19–20 Sept and all fixes are described below.
4. The remaining work is writing, not coding. The full pipeline has been
   demonstrated cleanly (§4.4) — `logs/e7_full_pipeline_clean.txt`.
5. If something breaks during a demo, read §9 (Troubleshooting) before
   changing code. Most failures are shell/config issues, not GhostNet bugs.

---

## 1. What GhostNet is

A hospital network has two attack surfaces that matter: cloud infrastructure
(AWS — APIs, ports, addresses) and medical IoT (infusion pumps publishing
vitals over MQTT). Moving Target Defense (MTD) defends by continuously
relocating those surfaces so an attacker's reconnaissance goes stale.

The research question: **can a reinforcement learning agent decide *which*
surface to relocate and *when*, using live threat intelligence, better than a
fixed rotation schedule?**

GhostNet answers yes, with a measured margin (§6).

### 1.1 Architecture

```
  Live threat feeds (NIST CVE, Shodan, AbuseIPDB, MITRE ATT&CK)
            │
            ▼
  12-dimension state vector  ──►  PPO policy (Stable-Baselines3)
            ▲                              │
            │                              ▼
            │                     one of 6 mutation actions
            │                              │
            │            ┌─────────────────┴──────────────────┐
            │            ▼                                    ▼
            │   Cloud executor (boto3)              IoT executor (SSH + MQTT)
            │   p3_cloud_mutator.py                 iot_mutator.py
            │   - AWS Security Group ports          - MQTT topic rotation
            │   - SG identity tag                   - broker port relocation
            │   - API path mapping (file)           │
            │            │                                    │
            │            ▼                                    ▼
            │     INDEPENDENT VERIFICATION           INDEPENDENT VERIFICATION
            │     describe_security_groups()         subscribe + await telemetry
            │            │                                    │
            └────────────┴────── mutation_ledger.py ──────────┘
                          (records old value, new value,
                           verified flag; rolls back failures)
```

**Core design principle, and the through-line of the paper:**
*A mutation is only claimed when something independent confirms it.*
Publishing a control message is not evidence. An API returning 200 is not
evidence. Re-reading the Security Group is evidence. Telemetry arriving on the
new topic is evidence.

### 1.2 State vector (LOCKED — do not renumber)

| Idx | Name | Source |
|-----|------|--------|
| 0 | cloud_ip_exposure | simulated |
| 1 | open_ports | simulated |
| 2 | api_exposure | simulated |
| 3 | iot_ip_exposure | simulated |
| 4 | mqtt_exposure | simulated |
| 5 | cve_score | **live** — NIST NVD, max CVSS / 10 |
| 6 | shodan_score | **live** — exposed services / 50000 |
| 7 | traffic_load | simulated |
| 8 | recon_attempts | simulated |
| 9 | time_since_mutation | reset to 0 every step (INERT — see §7) |
| 10 | abuse_score | **live** — AbuseIPDB, saturates at 1.0 (INERT) |
| 11 | attck_score | **live** — healthcare techniques / 30 |

Indices 0–4 are the five *attack surfaces*. Actions 0–4 each relocate one.

### 1.3 Action space

| ID | Action | What it really does |
|----|--------|---------------------|
| 0 | rotate_cloud_ip | Writes an SG **tag** (`GhostNetRotation`). NOT an IP change. |
| 1 | rotate_port | **Real** AWS: open new port, verify, close old, verify. |
| 2 | rotate_api_path | Writes `api_path_mapping.json`. **File only** — no live API gateway. |
| 3 | rotate_iot_ip | Relocates the Mosquitto broker's listening port. **Disabled by default** (§5.7). |
| 4 | rotate_mqtt_topic | **Real**: MQTT control message; pump switches topic; verified by subscription. |
| 5 | update_firewall | Broad defensive move; reduces all five surfaces modestly. |

**Be precise in the paper.** Actions 1 and 4 mutate live infrastructure.
Action 0 is a tag. Action 2 is a local file. Say so.

### 1.4 Reward — Traffic-Aware Dual-objective Reward (TADR)

```
exposure_before = state[action]                      # for actions 0-4
                + 0.3 if action == argmax(surfaces)  # precision bonus
                = mean(surfaces) - 0.1               # for action 5 (broad)

reward = exposure_before                  # reward mutating an EXPOSED surface
       - 0.3 * (1 - exposure_before)      # penalty for a wasted mutation
       - traffic_load * 0.05              # availability cost
       - 0.05                             # mutation cost
       + 0.2  if cve_score  > 0.7 and action in [1,2]   # LTSA bonus
       + 0.15 if abuse_score> 0.7 and action == 1       # LTSA bonus
       + 0.05 if traffic > 0.5 and handoff safe         # DESOLATER bonus
```

The key term is `exposure_before` — the value of the surface **before**
mutation. An earlier reward used the value *after* mutation, which is
constant by construction, gave no learning signal, and caused policy collapse
(§5.1).

---

## 2. Infrastructure (verify before any demo)

| Item | Value |
|------|-------|
| AWS region | `ap-south-1` |
| Security Group | `sg-011b5416a5dfa61b8` |
| EC2 public IP | `13.206.71.17` — **CHANGES ON STOP/START** |
| SSH user | `ubuntu` |
| Key | `C:\Users\nazee\OneDrive\Documents\capstone-project\ghostnet-iot-key.pem` |
| Broker | Mosquitto on the EC2, conf at `/etc/mosquitto/conf.d/ghostnet.conf` |
| Baseline broker port | 1883 (MQTT), 9001 (websockets) |
| Protected ports | 22, 443, 1883, 9001 — GhostNet may NEVER close these |
| Mutable port range | 8200–8999 |
| CALDERA | Docker, image `caldera:latest`, API on `localhost:8888` |
| CALDERA API key | `WhrGbb89JW60pJmCfli7U0Ir2ibMrX30QbpoTuJfORY` |

All machine-specific values live in **`ghostnet_config.py`** and can be
overridden by environment variables (`GHOSTNET_EC2_HOST`, `GHOSTNET_KEY_PATH`,
`GHOSTNET_SG_ID`, `GHOSTNET_ALLOW_BROKER_HOP`). Nothing else should hardcode
them.

---

## 3. File inventory

### 3.1 Current and correct

| File | Role |
|------|------|
| `ghostnet_config.py` | All machine-specific config + safety interlocks |
| `mutation_ledger.py` | Mutation lifecycle: record, verify, rollback. Self-tests with `python mutation_ledger.py` |
| `ghostnet_env_v2.py` | 12-dim Gym environment, TADR reward (FIXED version — see §5.2) |
| `ghostnet_env_v3.py` | Wraps v2, routes actions to real executors |
| `p3_cloud_mutator.py` | AWS executor, ledger-backed, verified |
| `iot_mutator.py` | IoT executor: topic rotation + broker relocation, verified, rollback |
| `device_v2.py` | Simulated infusion pump. Runs ON THE EC2. Follows broker relocation. |
| `mqtt_watch.py` | Subscriber for verifying telemetry by eye |
| `threat_feeds.py` | The four live feeds |
| `caldera_ttp_map.py` | ATT&CK technique → state boost mapping + expected-action ground truth |
| `caldera_bridge.py` | CALDERA REST integration |
| `phase5_eval.py` | Kill-chain evaluation (corrected — see §5.5) |
| `check_agent.py` | Collapse detection + scenario targeting (E3/E5) |
| `compare_policies.py` | PPO vs baselines (E9) |
| `run_phase3.py` | Live integration demo |
| `train.py` | PPO training |
| `ghostnet_pump.ino` | Wokwi ESP32 sketch (optional visual demo) |

### 3.2 Models — READ THIS CAREFULLY

| File | Trained | ent_coef | Status |
|------|---------|----------|--------|
| **`ghostnet_smart.zip`** | 2026-07-18 | 0.02 | **THE GOOD MODEL. Use this.** |
| `ghostnet_final.zip` | 2026-07-16 | 0.01 | **COLLAPSED.** Keep only as the negative baseline. |
| `ghostnet_v2.zip` | older | 0.01 | 10-dim, pre-Phase-2. Obsolete. |
| `best_model/best_model.zip` | — | — | From the collapsed run. Do not use. |

`train.py` hardcodes `model.save("ghostnet_final")`, so *every* run produces
that filename regardless of quality. The name means nothing.

**Strongly recommended:** rename to `ghostnet_v3_fixed_reward.zip` and
`ghostnet_v3_collapsed_baseline.zip` and update the scripts, so nobody
repeats this mistake in the viva.

### 3.3 Stale — do NOT trust

- The GitHub repo `capstone-project` is **behind** the working folder.
- `device.py` (old pump) — listens only on a control *file*, not MQTT. If it
  is running on the EC2 it will silently break topic rotation. Kill it.
- Any copy of `caldera_bridge.py` whose header lists state dims as
  `cvss/abuseipdb/attck/port_exposure/...` — that is the WRONG mapping.

---

## 4. Results — every number, with its source log

All produced 19–20 Sept 2026. Numbers vary slightly by seed; ordering is stable.

### 4.1 Collapse detection and targeting — `logs/e3_e5_agent_checks.txt`

| Test | `ghostnet_final` (collapsed) | `ghostnet_smart` (fixed) |
|------|------------------------------|--------------------------|
| Scenario targeting, 5 hand-built states | 1/5 | **5/5** |
| Unique actions over 30 random states | **1** (collapse signature) | **5** |
| Hot-surface match, 200 random states | 20.5% (= chance) | **53.0%** (2.65× chance) |

### 4.2 Policy comparison on the fixed environment — `logs/e9_policy_comparison.txt`

20 episodes × 200 steps, simulated feeds, reproducible.

| Policy | Return/episode | Hot-surface hit |
|--------|---------------|-----------------|
| Oracle (upper bound) | +27.8 | 100% |
| **PPO GhostNet (smart)** | **−23.8** | **34.2%** |
| Round-robin (fixed-schedule MTD) | −35.1 | 20.2% |
| Random mutation | −51.9 | 17.2% |
| PPO collapsed | −52.6 | 0.1% |
| Always-firewall | −97.2 | 0.0% |

Returns are negative because exposure never regrows (§7.1). **Report the
ordering, not the absolute values.**

### 4.3 Kill-chain evaluation — `logs/e10_phase5_killchain.txt`  ← HEADLINE

9 ATT&CK stages × 6 steps × 10 episodes.

| Policy | Peak exposure | % steps critical | Chain coverage | **Chain precision** | Reward |
|--------|--------------|------------------|----------------|---------------------|--------|
| Static (no defence) | 0.991 | **100.0%** | 0% | 0% | — |
| Random mutation | 0.767 | 58.7% | 65.6% | 17.6% | −11.67 |
| Round-robin MTD | 0.763 | 53.0% | 88.9% | 17.8% | −6.53 |
| PPO collapsed | 0.983 | **100.0%** | 12.2% | 12.2% | −13.47 |
| **PPO GhostNet** | **0.750** | **51.3%** | 82.2% | **68.9%** | −5.33 |
| Oracle | 0.748 | 50.0% | 87.8% | 75.0% | −3.85 |

**Three defensible claims:**
1. Undefended, the network is critically exposed **100%** of steps. GhostNet
   halves it to **51.3%**, against an oracle floor of 50.0%.
2. Precision **68.9% vs round-robin's 17.8% — 3.9×**, and 92% of the oracle
   ceiling. Coverage alone flatters cycling policies (round-robin visits all
   five actions inside a six-step stage), which is exactly why precision was
   added.
3. **The collapsed policy is statistically indistinguishable from no defence**
   (100% critical, 12.2% precision) while appearing to run normally. Silent
   failure — a security result, not just a training anecdote.

### 4.4 Full integrated pipeline — `logs/e7_full_pipeline_clean.txt`  ← DEMO RESULT

The definitive integration run: live threat feeds → 12-dim state → PPO policy
→ real AWS mutation → real IoT mutation → independent verification, in one
loop, with every subsystem active simultaneously.

```
Total reward       : -1.608
Real AWS mutations : 20
Failed mutations   : 0
```

**Cloud side.** Every `rotate_port` reported `verified=True` against an
independent `describe_security_groups` re-read. The final rotations read:

```
rotate_port  8817 -> 8336  verified=True  open now: [22, 443, 1883, 8336, 9001]
rotate_port  8336 -> 8399  verified=True  open now: [22, 443, 1883, 8399, 9001]
```

**Five ports throughout** — four protected (22, 443, 1883, 9001) plus exactly
one mutable port. The surface relocates without growing. This is the net-zero
property, demonstrated live under agent control.

**IoT side.** Six consecutive topic rotations, each confirmed by real
telemetry arriving on the new topic:

```
patient1 -> pbd9z68 -> p1w3r1w -> p2ftw1f -> pegnz2p -> pui4nlc -> po0d6p2
  ... every one: CONFIRMED live telemetry
```

**Safety interlock working.** When the agent selected action 3, the log reads:

```
[OK  ] rotate_iot_ip  SKIPPED: broker relocation disabled
                      (set GHOSTNET_ALLOW_BROKER_HOP=1 for the experiment)
```

The agent proposed a mutation the operator had ruled out, the system refused
it, and the run continued without incident. A concrete human-in-the-loop
boundary (§5.7).

**On the negative total reward.** TADR is a training signal, not a security
measurement (§7.3). Late in a run most surfaces have already been mutated to
low values, so the wasted-move penalty dominates — the agent is paying to keep
relocating an already-relocated surface. It is a direct consequence of
exposure never regrowing (§7.1). Do not present it as a performance figure;
the security results are §4.3.

**Earlier run for comparison** (`logs/e7_full_pipeline.txt`): 18 real AWS
mutations, 2 IoT failures — the failures caused by the agent relocating the
broker before the interlock existed. Keep both logs: the pair shows the
interlock's effect.

Externally confirmed at any time with:
```
aws ec2 describe-security-groups --group-ids sg-011b5416a5dfa61b8 \
  --region ap-south-1 --query "SecurityGroups[0].IpPermissions[].FromPort"
```

### 4.5 IoT topic rotation

Confirmed by subscribing to the new topic and waiting for real payloads, plus
a 10-second dual-publish overlap so no telemetry is lost during cutover.

Standalone: `rotate_mqtt_topic | hospital/icu/vitals/patient1 ->
hospital/icu/vitals/ppcrxsa | CONFIRMED live telemetry`

Under agent control, six consecutive rotations in one run, all confirmed
(§4.4). **Repeatability matters here** — a single rotation could be luck; six
chained rotations with verification at each step is a working mechanism.

### 4.6 CALDERA — `logs/e11_caldera_bridge.txt`

- Server reachable at `http://localhost:8888`
- Adversary `Hospital-IoT-Ransomware`, id `cbac9539-1ed0-455d-8fab-d3cbdf6572f4`
- Operation `65eac785-3e07-4685-ae70-34adc6abcfd9` created and closed
- 9 techniques fired with time-decayed injection vectors

An **earlier** live operation executed Discovery abilities (T1033, T1087.001,
T1057) successfully via a Sandcat agent.

**Exact wording to use:**
> GhostNet integrates with MITRE CALDERA through its REST API, instantiating a
> healthcare ransomware adversary profile. Live emulation validated the
> Discovery stage; the full nine-stage chain was evaluated by deterministic
> replay of the ATT&CK sequence for reproducibility.

Do NOT claim live agent execution of all nine stages.

### 4.7 Broker relocation — INCOMPLETE, see §8.2

The naive hop is demonstrated: broker moves, `telemetry NOT RESUMED in 30s`.
The announce-then-hop comparison has **not yet been run with a pump capable of
following the notice**. Do not report that pair until §8.2 is done.

---

## 5. Problems found and fixed (19–20 Sept)

Each entry: what was wrong, why it mattered, what was done.

### 5.1 Policy collapse (fixed before this session)
Reward used the post-mutation value `1 - new_state[action]`, which is random
in a fixed range regardless of action — no learning signal. Policy collapsed
to one action. Fixed by rewarding `exposure_before` with a precision bonus and
a wasted-move penalty, and raising `ent_coef` 0.01 → 0.02. Result: §4.1.

### 5.2 Action 5 corrupted the CVE feed
`new_state[action] = uniform(...)` with `action == 5` wrote into **index 5,
the live CVE score**. `update_firewall` therefore reduced no exposure but
still collected `mean(surfaces) - 0.1` forever, and destroyed a threat-feed
dimension. Always-firewall scored **+19.6, beating the trained agent's +6.8**.
Fixed: action 5 now reduces all five surfaces by 0.15 and never touches feeds.
After the fix always-firewall scores **−97.2** and GhostNet is the best
non-oracle policy. No retraining needed — the agent had never learned to use
action 5 (0/200 states).

### 5.3 `p3_cloud_mutator.py` mutated AWS **on import**
Three lines at module scope (outside `if __name__ == "__main__"`) called
`rotate_port(8080)`. Every `import p3_cloud_mutator` — by `ghostnet_env_v3`,
`run_phase3`, anything — performed a real AWS port rotation. This is why the
Security Group had accumulated orphan ports 8823, 8388, 8243. Removed.

### 5.4 `rotate_port` grew the attack surface by one port per call
It assumed the old port was always 8080, which was never open, so it opened a
new port and closed nothing. It also returned `True` unconditionally, without
checking. Fixed with the **mutation ledger**: the current live port is read
from `mutation_ledger.json`, the new port is opened and verified first
(availability), the old one is closed and verified, and a failed verification
triggers rollback. Net-zero surface.

**Related:** `ACTION_MAP[1]` was `close_port(port=8080)` — the agent's
highest-bonus cloud action was a permanent no-op. Now mapped to `rotate_port`.

### 5.5 `phase5_eval.py` had four invalidating bugs
1. `MODEL_PATH = "best_model/best_model.zip"` falling back to
   `ghostnet_final.zip` — **the entire Phase 5 evaluation ran on the collapsed
   policy**.
2. The "static defence" control used `action = 0`, which is `rotate_cloud_ip`
   — a real mutation. The control group was "always rotate the cloud IP".
3. `mutation_ct` counted `action != 0`, discarding every action-0 mutation.
4. `attack_success_rate` tested `obs[11] > 0.5` calling it "ransomware risk";
   index 11 is `attck_score`.
Also the kill chain advanced on wall-clock time in a background thread while
env steps ran at CPU speed, so stage alignment varied between runs; and
`use_real_cloud=True` across 3 × 10 × 200 steps meant ~6000 live AWS calls.
Rewritten: step-driven stages, true no-defence control, offline by default,
`ghostnet_smart` default, precision metric added.

### 5.6 `caldera_bridge.py` TTP mapping (repo copy)
The repo copy mapped techniques onto a state vector that does not exist in
this project (`cvss/abuseipdb/attck/port_exposure/...`). Every index
disagreed. **The working copy on the laptop was already corrected** — verify
the header before trusting any copy. `caldera_ttp_map.py` now holds the
canonical mapping plus `expected_action()`, the ground truth used for scoring.

### 5.7 Broker relocation as a routine agent action (interlock added)
With `use_real_iot=True`, the agent picked action 3 repeatedly during demo
runs, relocating the broker every few steps. Devices could not follow;
telemetry died; each failed hop burned 30 s. This is self-inflicted denial of
service. Added `ghostnet_config.ALLOW_BROKER_HOP`, default **False**: action 3
logs `SKIPPED` unless `GHOSTNET_ALLOW_BROKER_HOP=1`. `iot_mutator.py
--port-hop` forces past it for the controlled experiment.

**This is a finding, not just a fix:** some mutations are too disruptive to
leave under autonomous control, because the reward function cannot represent
"this costs every device on the network an outage."

### 5.8 Topic rotation reported success without evidence
`rotate_iot_topic()` published a control message and logged SUCCESS. Now it
subscribes to the new topic and waits up to 20 s for real telemetry.
This immediately caught a real fault: an old `device.py` was still running on
the EC2, listening only on the control *file*, so rotations never took effect.

### 5.9 Broker port detection always returned empty
`ss -tlnp | grep mosquitto` hides the process name from non-root users. Fixed
with `sudo ss -tlnp` plus a fallback intersecting config-declared listeners
with actually-bound ports, and a `systemctl is-active` check.

### 5.10 `restart_broker_with_new_port` edited the wrong file
It ran `sed` on `/etc/mosquitto/mosquitto.conf` while the listeners live in
`conf.d/ghostnet.conf` — silently a no-op, or a half-applied config that
breaks the broker. It also chose ports 1884–1887, none open in the Security
Group, so the broker would move **behind the firewall**. Now: open the SG port
first → rewrite `conf.d/ghostnet.conf` deterministically → verify with `ss` →
roll back the previous config on failure.

### 5.11 Hardcoded to one team member's laptop
`iot_mutator.py` had `KEY_PATH = r"C:\Users\SANGAVI\..."`, so the IoT layer
only ran on her machine. All such values moved to `ghostnet_config.py`.

### 5.12 paho-mqtt 2.x deprecation
All clients now use `CallbackAPIVersion.VERSION2` with callbacks whose
signatures work under both APIs, and distinct client IDs (`ghostnet-pump1`,
`ghostnet-watch`, `ghostnet-verify`, `ghostnet-control`) so clients don't
evict each other.

### 5.13 Availability during relocation — the announce protocol
**The core insight.** The control channel runs ON the broker, so the broker
cannot announce its own relocation after moving. Devices told once and never
updated are stranded; meanwhile an attacker who scans finds the new port in
seconds. So relocation without notification **costs availability and buys no
security**.

Fix: before touching the config, publish `{"action":"broker_move",
"new_port":X,"grace":5}` on the OLD listener; devices note it and reconnect
after the grace window. `device_v2.py` implements this and prints the measured
`telemetry gap N.NNs`.

Trade-off to state in the paper: during the grace window both ports are open,
so the surface is briefly larger. And the notice is unauthenticated on an
`allow_anonymous` broker — anyone able to publish to the control topic could
redirect the pumps.

---

## 6. What GhostNet has genuinely achieved

Claims that are safe to make, each with its evidence:

1. **A PPO agent learns threat-conditioned surface targeting** — 5/5 scenario
   targeting, 53% hot-surface match vs 20% chance (`e3_e5`).
2. **Policy collapse diagnosed, fixed, and measured** — 1 → 5 unique actions,
   1/5 → 5/5 targeting (`e3_e5`).
3. **A collapsed policy provides no measurable protection while appearing
   healthy** — 100% critical steps, same as no defence (`e10`).
4. **The agent outperforms fixed-schedule MTD** — 3.9× precision, 92% of the
   oracle ceiling (`e10`).
5. **Real cloud mutation with independent verification** — 20 verified AWS
   mutations, 0 failures, externally confirmed (`e7_full_pipeline_clean`).
6. **Net-zero attack surface under repeated rotation** — enabled by the
   mutation ledger (`e6`, `e7`).
7. **Real IoT mutation confirmed at the device** — six consecutive topic
   rotations under agent control, each verified by live telemetry, with a
   dual-publish handoff (`e7_full_pipeline_clean`).
8. **Cross-domain coordination is necessary** — the SG port must be opened
   before the broker moves, or the mutation severs the data path.
9. **CALDERA integration** — adversary instantiated and operations run via
   REST API (`e11`).
10. **Live threat intelligence genuinely live** — CVE score observed at 0.98,
    0.88 and 0.98 across runs, tracking the real feed.
11. **End-to-end integration demonstrated** — all five phases running
    simultaneously against live infrastructure, 20/20 mutations verified, 0
    failures, safety interlock refusing an unsafe agent action mid-run
    (`e7_full_pipeline_clean`).

---

## 7. Limitations that REMAIN (state these honestly)

### 7.1 The environment
- **Three of twelve state dimensions are inert.** Index 6 (Shodan) is ~0.003
  every run (173 services ÷ 50,000). Index 10 (AbuseIPDB) saturates at 1.0
  (the divisor is the same page limit the query requests). Index 9
  (`time_since_mutation`) is reset to 0 every step. The agent effectively
  learns on nine dimensions.
- **Exposure never regrows.** A mutated surface stays safe forever, so there
  is no pressure to re-mutate and "mutation duration" has no meaning. This is
  why absolute returns are negative and why only the ordering is reportable.
- **No hold / restore action.** The agent cannot choose to do nothing or to
  undo. The full MTD lifecycle (mutate → verify → maintain → reassess →
  restore) is not learnable in this formulation.

### 7.2 The mutations
- Action 0 rotates a **tag**, not an IP.
- Action 2 writes a **local JSON file**; no live API gateway is reconfigured.
- Only actions 1 and 4 mutate live infrastructure.

### 7.3 The evaluation
- The reward is a **training signal, not a security measurement**. No
  attacker-side metric (attacker cost, recon invalidation, dwell time) exists.
- The nine-stage chain is **deterministic replay**, not live agent execution.
- Six techniques (`T1071`, `T1078`, `T1095`, `T1572`, `T1082`, `T1083`) raise
  only feed dimensions and no attack surface, so at those stages the agent has
  nothing concrete to target.
- **Two reproducible failures:** stage 1 (`T1190`, expected `rotate_api_path`,
  agent chose `rotate_cloud_ip`) and stage 7 (`T1486` ransomware, five
  surfaces hot, expected `update_firewall`, agent kept rotating MQTT). The
  latter is explainable: the agent trained under the reward where action 5 was
  exploitable, so it learned to avoid the broad action.
- The device is **simulated**; no physical hardware. Raspberry Pi integration
  is future work.

### 7.4 Security of GhostNet itself (production gap)
- Broker runs `allow_anonymous true`, plaintext MQTT, no TLS.
- SG rules open to `0.0.0.0/0`.
- The relocation notice is unauthenticated — anyone who can publish to the
  control topic can redirect devices.
- AWS credentials in a local config; an attacker who compromises GhostNet gets
  a legitimate API for reconfiguring hospital defences.
- **Threat feeds are an attack surface** — poison or spoof them and you steer
  the defence.

### 7.5 Clinical and regulatory
- No formal availability SLO, no safety interlock that can veto a mutation on
  clinical grounds, no proof the handoff window holds under load.
- IEC 62304 / HIPAA / change-control compliance not addressed. An autonomous
  agent reconfiguring hospital infrastructure is a multi-year regulatory path.
- Only one EC2, one SG, one broker, one simulated device, one segment.
- No model governance: no drift monitoring, no retraining policy, no
  human-in-the-loop fallback beyond the broker-hop interlock.

### 7.6 Engineering
- No automated tests, no CI.
- `requirements.txt` was only just generated.
- The GitHub repo lags the working folder.

---

## 8. What is left to do

### 8.1 Commit everything (5 minutes, HIGHEST PRIORITY)
The working folder is ahead of the repo and lives on one laptop.
```powershell
cd "C:\Users\nazee\OneDrive\Documents\capstone-project"
pip freeze > requirements.txt
git add -A
git commit -m "GhostNet v2: mutation ledger, verified execution, config module, corrected TTP map, relocation protocol"
git push
```

### 8.2 Finish the broker relocation experiment (30 minutes, OPTIONAL)
Needed only if you want the announce-vs-naive comparison in the paper.
**Prerequisite:** the EC2 must have the patched pump.
```powershell
ssh -i "<KEY>" ubuntu@<EC2_IP> "grep -c broker_move device_v2.py"   # must be > 0
```
Then §10.7.

### 8.3 Figures (60 minutes)
*(§8.2 is the only outstanding experiment; the pipeline demo is DONE — §4.4.)*
1. Training curve (existing `training_curve.png`).
2. Policy comparison bar chart (from `e9` / `e10`).
3. Kill-chain per-stage response table (from `e10`).
4. Security Group port list across rotations, showing constant length
   (from `e7_full_pipeline_clean`).
5. Dual-publish overlap screenshot (topic rotation).
6. Architecture diagram (§1.1).
7. Annotated full-pipeline screenshot (`e7_full_pipeline_clean`) — the single
   figure that shows every subsystem working together, including the
   `SKIPPED` interlock line.

### 8.4 The paper (NOT STARTED — the main remaining work)
Suggested IEEE two-column structure:
- **Abstract** — hospital MTD, DRL surface selection, 100% → 51.3% critical
  exposure, 3.9× precision over fixed-schedule MTD.
- **I. Introduction** — healthcare cyber incidents; medical IoT can't be
  patched; MTD as a fit; availability constraint is the hard part.
- **II. Related work** — DESOLATER (Yoon et al., IEEE Access 2021,
  DOI:10.1109/ACCESS.2021.3076599), MTD surveys, RL for cyber defence,
  healthcare CPS security (Claroty 2023, Armis medical device whitepaper).
- **III. System design** — architecture (§1.1), state (§1.2), actions (§1.3),
  TADR reward (§1.4), verified execution, mutation ledger.
- **IV. Implementation** — AWS/boto3, Mosquitto, live feeds, CALDERA.
- **V. Evaluation** — §4 tables. Lead with the kill chain.
- **VI. Discussion** — collapse as silent failure; net-zero surface; the
  relocation/availability finding; the interlock as a human-in-the-loop
  boundary.
- **VII. Limitations and future work** — §7 verbatim, plus mutation duration
  as a learned variable and full rollback lifecycle.
- **VIII. Conclusion**

### 8.5 The project report
Same content, expanded, with setup instructions (§10), screenshots, and the
problem/solution narrative from §5 — which is genuinely valuable material,
because it shows diagnostic work rather than just a finished artifact.

---

## 9. Troubleshooting — read before changing code

**Most failures in this project are shell or config issues, not bugs.**

| Symptom | Meaning | Fix |
|---------|---------|-----|
| `TimeoutError` / `timed out` connecting | Packets dropped — **firewall**. Port not open in the SG, or wrong host. | Check SG: `python -c "import p3_cloud_mutator as m; print(m.get_current_rules())"` |
| `Connection refused` | Host reachable, **nothing listening**. Broker is on a different port. | `python iot_mutator.py` to see real listeners |
| SSH command returns **nothing at all** | `pkill -f` matched the SSH shell's own command line, killing it mid-command | **Never** combine `pkill` and the thing being killed in one SSH call. Use two calls. Use `'[d]evice'` bracket syntax. |
| `pump.log` empty but process alive | Python buffers stdout to a file | Start with `python3 -u` |
| PowerShell `curl` errors about `SessionVariable` | `curl` is an alias for `Invoke-WebRequest` | Use `curl.exe` |
| PowerShell stuck at `>>` | Pasted a multi-line block including `#` comments | `Ctrl+C`; paste one line at a time |
| `ModuleNotFoundError` for a GhostNet module | File not downloaded into the project folder | `dir *.py` and check |
| Telemetry stops mid-run | Agent relocated the broker | Ensure `GHOSTNET_ALLOW_BROKER_HOP` is unset/0 |
| `rotate_mqtt_topic` times out repeatedly | Broker moved, or no pump running | §10.4 reset sequence |
| Mangled characters (`ù`) in output | PowerShell code page | `chcp 65001` before capturing screenshots |
| Ledger port ≠ real broker port | A hop failed and rolled back | Realign: `ledger.set_config('broker_port', <real>)` |

**Golden rule:** the ledger records *intent*; `ss` and `describe-security-groups`
record *reality*. When they disagree, reality wins — realign the ledger.

---

## 10. FULL DEMO RUNBOOK

Everything below is PowerShell from
`C:\Users\nazee\OneDrive\Documents\capstone-project`.
**Run one command at a time. Do not paste comment lines.**

### 10.0 Prerequisites
```powershell
cd "C:\Users\nazee\OneDrive\Documents\capstone-project"
chcp 65001
pip install "stable-baselines3[extra]" gymnasium numpy requests boto3 paho-mqtt paramiko matplotlib pandas
aws configure          # ghostnet-agent keys, region ap-south-1, output json
aws sts get-caller-identity
python ghostnet_config.py
```
`ghostnet_config.py` must print no warning. If the key path is wrong:
```powershell
setx GHOSTNET_KEY_PATH "C:\full\path\to\ghostnet-iot-key.pem"
setx GHOSTNET_EC2_HOST "<current EC2 public IP>"
```
Then **open a new terminal** (`setx` doesn't affect the current one).

Get the current EC2 IP (it changes on stop/start):
```powershell
aws ec2 describe-instances --region ap-south-1 --query "Reservations[].Instances[].{IP:PublicIpAddress,State:State.Name,Id:InstanceId}" --output table
```

### 10.1 Live threat feeds (30 seconds)
```powershell
python threat_feeds.py
```
Expect CVE ≈ 0.8–1.0, Shodan ≈ 0.003, Abuse = 1.0, ATT&CK ≈ 0.033.
**Talking point:** the CVE value changes between runs — the feed is genuinely live.
*(SSL errors → you're on campus Wi-Fi; switch to a hotspot.)*

### 10.2 The RL result (2 minutes)
```powershell
mkdir logs -Force
python check_agent.py | Tee-Object logs\e3_e5_agent_checks.txt
python compare_policies.py | Tee-Object logs\e9_policy_comparison.txt
```
Shows collapse vs fixed, and PPO vs baselines. Needs `ghostnet_smart.zip`,
`ghostnet_final.zip`, and the FIXED `ghostnet_env_v2.py` in the folder.
Verify the env is the fixed one:
```powershell
findstr /C:"BUGFIX: action 5" ghostnet_env_v2.py
```
Must print a line.

### 10.3 Cloud domain (3 minutes)
```powershell
python -c "import p3_cloud_mutator as m; print('SG:', m.SECURITY_GROUP_ID if hasattr(m,'SECURITY_GROUP_ID') else ''); print('open ports:', m.get_current_rules())"
python p3_cloud_mutator.py --cleanup
python p3_cloud_mutator.py --rotate | Tee-Object logs\e6_rotate_1.txt
python p3_cloud_mutator.py --rotate | Tee-Object logs\e6_rotate_2.txt
python p3_cloud_mutator.py --rotate | Tee-Object logs\e6_rotate_3.txt
aws ec2 describe-security-groups --group-ids sg-011b5416a5dfa61b8 --region ap-south-1 --query "SecurityGroups[0].IpPermissions[].FromPort"
```
**The point:** each rotation shows `verified=True`, and the port list stays at
**five entries** — 22, 443, 1883, 9001 plus one mutable port — no matter how
many times you run it. Net-zero attack surface.

### 10.4 Bring the IoT layer up (5 minutes)
Set `$K` once to save typing:
```powershell
$K = "C:\Users\nazee\OneDrive\Documents\capstone-project\ghostnet-iot-key.pem"
$H = "13.206.71.17"
```
Reset the broker to baseline and realign the ledger:
```powershell
python -c "import iot_mutator as m, time; m._write_broker_conf(1883); time.sleep(4); print('listening:', m.broker_listening_ports())"
python -c "from mutation_ledger import ledger; ledger.set_config('broker_port',1883); ledger.set_config('telemetry_topic','hospital/icu/vitals/patient1'); print('ok')"
```
Expect `listening: [1883, 9001]`.

Copy and start the pump (**two separate SSH calls — see §9**):
```powershell
scp -i $K device_v2.py ubuntu@${H}:~/
ssh -i $K ubuntu@$H "grep -c broker_move device_v2.py"
ssh -i $K ubuntu@$H "pkill -f '[d]evice'; sleep 2; echo STOPPED"
ssh -i $K ubuntu@$H "nohup python3 -u device_v2.py 1883 > pump.log 2>&1 & sleep 6; tail -5 pump.log"
```
`grep` must print > 0. Last command must show `[DEVICE] starting on :1883`.

Status check:
```powershell
python iot_mutator.py
```
Expect `Broker service: active`, `Broker listening: [1883, 9001]`.

### 10.5 IoT mutation, verified (2 minutes) — GOOD DEMO MOMENT
Terminal A (leave running):
```powershell
python mqtt_watch.py 13.206.71.17 1883
```
Terminal B:
```powershell
python iot_mutator.py --topic | Tee-Object logs\e_topic_rotation.txt
```
**Watch terminal A:** `*** NEW TOPIC SEEN ***`, then ~10 s where the old and
new topics carry identical payloads, then the old goes quiet. Terminal B
reports `CONFIRMED live telemetry`.
**Talking point:** the mutation is confirmed by data arriving, not by a
publish call returning. The overlap means no patient telemetry is lost.

### 10.6 Full pipeline (5 minutes) — THE SHOWPIECE
Ensure `run_phase3.py` has:
```python
model = PPO.load("ghostnet_smart")
env = GhostNetEnvV3(use_live_feeds=True, use_real_cloud=True, use_real_iot=True)
```
and that `GHOSTNET_ALLOW_BROKER_HOP` is **not** set to 1.
```powershell
python p3_cloud_mutator.py --cleanup
python run_phase3.py | Tee-Object logs\e7_full_pipeline_clean.txt
```
Expect: live feeds → 12-dim state → policy decision → real AWS mutation with
`verified=True` → real MQTT rotation with `CONFIRMED live telemetry` →
verification. Action 3 logs `SKIPPED`. Watcher stays alive throughout.

**Verified working 20 Sept 2026:** 20 real AWS mutations, 0 failures, six
confirmed topic rotations, port list constant at five entries. If your run
shows failed mutations, the cause is almost always (a) no pump running, (b)
broker not on the port the ledger believes, or (c) `GHOSTNET_ALLOW_BROKER_HOP`
left at 1 from the §10.7 experiment. See §9.

*If IoT still misbehaves and time is short:* set `use_real_iot=False`. You
lose live MQTT rotation in this run only — §10.5 already proves it.

### 10.7 Broker relocation experiment (10 minutes, OPTIONAL)
**Run A — naive:**
```powershell
$env:GHOSTNET_ALLOW_BROKER_HOP = "1"
python iot_mutator.py --port-hop --no-announce | Tee-Object logs\e8a_naive_hop.txt
```
Expect `telemetry NOT RESUMED in 30s` — the pump is stranded.
Note the new port, restart the pump on it, restart the watcher on it:
```powershell
ssh -i $K ubuntu@$H "pkill -f '[d]evice'; sleep 2; echo STOPPED"
ssh -i $K ubuntu@$H "nohup python3 -u device_v2.py <NEW_PORT> > pump.log 2>&1 & sleep 6; tail -3 pump.log"
```
**Run B — announced:**
```powershell
python iot_mutator.py --port-hop | Tee-Object logs\e8b_announced_hop.txt
```
Expect `relocation notice sent`, pump printing `RECONNECTED on :XXXX --
telemetry gap N.NNs`, mutator reporting `telemetry RESUMED in N.Ns`.
Restore the interlock:
```powershell
$env:GHOSTNET_ALLOW_BROKER_HOP = "0"
python -c "import iot_mutator as m, time; m._write_broker_conf(1883); time.sleep(4); print(m.broker_listening_ports())"
python -c "from mutation_ledger import ledger; ledger.set_config('broker_port',1883); print('ok')"
```

### 10.8 CALDERA (5 minutes)
```powershell
docker ps --format "{{.ID}}  {{.Names}}  {{.Status}}  {{.Ports}}"
```
Need a container with `0.0.0.0:8888->8888/tcp`. If stopped:
`docker start <id>` (only one — they contend for ports).
```powershell
curl.exe -s -H "KEY: WhrGbb89JW60pJmCfli7U0Ir2ibMrX30QbpoTuJfORY" http://localhost:8888/api/v2/operations
python caldera_bridge.py | Tee-Object logs\e11_caldera_bridge.txt
```
If `401`, get the real key:
```powershell
docker exec <container_id> grep -A3 "api_key" /usr/src/app/conf/local.yml
```

### 10.9 Kill-chain evaluation (2 minutes) — HEADLINE RESULT
Needs `caldera_ttp_map.py`, `phase5_eval.py`, both models, the fixed env.
```powershell
python caldera_ttp_map.py
python phase5_eval.py | Tee-Object logs\e10_phase5_killchain.txt
```
Produces the §4.3 table. **No CALDERA server or AWS needed** — deterministic
and reproducible.

### 10.10 Demo order for a viva (15 minutes total)
1. `python threat_feeds.py` — "our inputs are live" (30 s)
2. `python check_agent.py` — "we diagnosed and fixed policy collapse" (1 min)
3. `python phase5_eval.py` — "this is the headline result" (2 min)
4. `python p3_cloud_mutator.py --rotate` + the `aws` re-read — "real
   infrastructure, independently verified, surface stays constant" (2 min)
5. Watcher + `iot_mutator.py --topic` — "real device, verified at the device,
   no telemetry lost" (2 min)
6. `python run_phase3.py` — "all of it, in one loop" (5 min)
7. Optionally `caldera_bridge.py` — "adversary emulation integration" (2 min)

---

## 11. Anticipated viva questions

**"Is this really MTD or just random reconfiguration?"**
Precision 68.9% vs round-robin 17.8% on the same kill chain. The agent selects
the surface under attack; a schedule cannot.

**"Does it actually improve security?"**
We measure exposure, not attacker success — a stated limitation. Undefended,
100% of steps are critically exposed; with GhostNet, 51.3%, against an oracle
floor of 50.0%.

**"Why is the reward negative?"**
Exposure never regrows in the environment, so absolute returns aren't
meaningful. We report ordering. Fixing this is future work (§7.1).

**"What happens if the agent fails?"**
We measured it. A collapsed policy is indistinguishable from no defence —
100% critical steps — while appearing to run normally. That's why verification
and the mutation ledger exist.

**"How do you know a mutation happened?"**
Independent re-read: `describe_security_groups` for cloud, subscribing for
telemetry on IoT. A publish returning 200 is never accepted as evidence.

**"Is it production-ready?"**
No, and §7.4/§7.5 says exactly why: GhostNet's own control plane is
unauthenticated, the threat feeds are an attack surface, and there is no
clinical safety interlock or regulatory pathway.

---

## 12. Reference

- Yoon et al., "DESOLATER: Deep Reinforcement Learning-Based Resource
  Allocation and Moving Target Defense Deployment Framework," *IEEE Access*,
  2021. DOI: 10.1109/ACCESS.2021.3076599
- Claroty, *State of CPS Security: Healthcare 2023*
- Armis, *Medical and IoT Device Security* whitepaper
- MITRE ATT&CK; MITRE CALDERA
- Stable-Baselines3 PPO

---

## 13. Final note to whoever continues this

The code is in good shape and the system has been demonstrated end to end
(§4.4: 20/20 mutations verified, 0 failures, all subsystems live). The hard
diagnostic work is done and documented in §5 — that material is itself worth
writing up, because it shows engineering judgement rather than just a finished
artifact.

**Do not start over.** Every defect found was peripheral — config, indices,
defaults, module-scope side effects. None were in the state representation,
the reward architecture, the PPO setup, or the dual-domain design. A rewrite
would discard verified results and re-encounter the same bugs in new clothing.

The remaining risk is not technical. It is that the paper and report don't get
written. Everything needed for them is in §4 (results), §5 (problems and
solutions), §6 (claims), and §7 (limitations).

Be precise about what is real: actions 1 and 4 mutate live infrastructure,
action 0 is a tag, action 2 is a file, the kill chain is replay, the device is
simulated. Precision here is not weakness — it is what makes the rest
credible.

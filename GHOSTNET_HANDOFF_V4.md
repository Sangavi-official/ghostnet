# GhostNet — Development Handoff (v4)

**Written:** 1 October 2026
**Supersedes nothing; extends** GHOSTNET_HANDOFF_V2/V3. Everything in the earlier
handoffs still holds unless contradicted here. This file records the work done in
the v4 session: a re-built evaluation, multi-seed training with rivals and
ablations, a robustness study, a device-coordination protocol, a real firewall
action, a corrected CALDERA bridge, a full reference check, and a rewritten IEEE
paper.

**Purpose:** total context transfer to a fresh reader (human or AI) with no memory
of the v4 session. If you are an AI continuing this: the code works, the hard
diagnostic work is done and committed; do not start over. Read §1 and §2 first.

**Project:** GhostNet — Deep RL-driven Moving Target Defense for hospital
IoMT-to-cloud infrastructure.
**Team:** Suha N (drives the laptop), Meghana N, Sangavi S. **Guides:** Dr Mithun D
Souza, Dr Kavitha S.
**Machine:** `C:\Users\nazee\OneDrive\Documents\capstone-project` (Windows, VS Code,
PowerShell + Git Bash).
**Repo:** GitHub `Sangavi-official/ghostnet` (renamed from `capstone-project`;
update remotes). Branch `suha/sliced-agent`. Open PR: #3.

---

## 0. THE ONE-PARAGRAPH SUMMARY

A reviewer called the submitted paper an "application paper" with a circular metric
("precision" scored against labels the reward itself encoded) and "no IoT
protocol". The v4 session fixed the *evaluation* and the *IoT control channel*
rather than rebuilding the system. We put a reconnaissance-and-exploit attacker
inside the environment so a mutation genuinely sets the attacker back, and measured
attacker outcomes (break-ins, dwell time) instead of label agreement. Across 10
training seeds per method, a learned policy (PPO) does **not** beat a one-line
greedy heuristic on break-ins, but disrupts the hospital ~13% less — and we
documented three ways a learned MTD fails *silently*. We added GMCP (a signed,
two-phase device protocol), made the firewall action real, corrected the CALDERA
bridge, verified all references, and produced a reframed IEEE paper. All v2/v3
files are untouched, so every earlier result still reproduces.

---

## 1. WHAT CHANGED, IN ORDER

### 1.1 Security (do not skip)
- **`threat_feeds.py`**: API keys now read from environment variables
  (`GHOSTNET_NIST_KEY`, `GHOSTNET_SHODAN_KEY`, `GHOSTNET_ABUSEIPDB_KEY`), never from
  source. **The three old keys were rotated by the team** (new ones set via `setx`).
- **`rotate_ssh_key.py`** (new): rotates the EC2 SSH key with no lock-out risk
  (add-new → prove it logs in alone → point `GHOSTNET_KEY_PATH` at it → remove old,
  keeping an open connection as a safety net). **The team completed this**; the EC2
  now trusts only `C:\Users\nazee\.ssh\ghostnet-key-2026.pem`; the old
  `ghostnet-iot-key.pem` is refused.
- Still outstanding: the old keys remain in GitHub *history* (rotation is why that
  no longer matters), and the shared zip should be deleted by anyone who has it.

### 1.2 A fair evaluation world — `ghostnet_env_v4.py` (new)
Why: the old Phase 5 eval added the kill chain to the *observation* only, so no
action could suppress an attack, and reward paid +0.3 for choosing
`argmax(surfaces)` — the exact rule the "oracle" used, making the metric circular.
v4 fixes all of it, in a new file (v2/v3 untouched):
- **Attack is in the world.** A technique raises the real exposure of the surfaces
  it targets; a mutation resets the chosen surface, genuinely setting the attacker
  back.
- **Exposure regrows** from continued scanning → mutation *timing* matters.
- **Outcome-only reward**: negative weighted sum of mean exposure, hot surfaces,
  compromised surfaces, and per-action clinical disruption. No label term.
- **Hold action added** (action 6): the agent can choose *when* to act.
- **Feeds sampled per episode** so the policy must read them, not memorise one value.
- **Seeded** through `self.np_random` so an episode reproduces exactly.

### 1.3 Attacker model (inside `ghostnet_env_v4.py`)
The attacker scans (exposure rises), and when a surface passes a launch threshold it
starts an exploit that lands after `EXPLOIT_STEPS`. Moving that surface first makes
the exploit fail (recon invalidated); a landed exploit is a foothold until the
surface is moved. The defender sees exposure through Gaussian IDS noise
(`OBS_NOISE`), i.e. partial observability. This yields the metrics the paper needs:
break-ins, % time with a foothold, attacks launched, forced rescans.
**World constants are frozen** (PRESSURE_RATE 0.30, EXPLOIT_STEPS 1, OBS_NOISE 0.15,
FIREWALL_CUT 0.15), chosen using only rule-based players *before any training*, and
never retuned. This is stated in the file and the paper.

### 1.4 Training — `train_v4.py` (new)
- 10 independent seeds per method; the end-of-training model is kept (no
  best-checkpoint selection, so the test set cannot leak into model choice).
- Variants: `ppo` (main), `dqn`, `a2c`, `ppo-nofeeds` (feeds hidden ablation),
  `ppo-nohold` (no hold ablation), `ppo-fwrand` (robust: firewall strength random
  per episode, via domain randomization).
- Parallel across seeds (`torch.set_num_threads(1)`, `ProcessPoolExecutor`). ~15 min
  for 10 PPO seeds at 300k steps each on this laptop.
- Models in `models/v4/<variant>_seed<0-9>.zip` (committed).

### 1.5 Evaluation — `eval_v4.py`, `eval_v4_agents.py` (new)
- `eval_v4.py`: rule baselines (static, random, round-robin, greedy, tuned
  threshold) with attacker-side metrics. Threshold tuned on random chains (disjoint
  from the AIIMS test chain).
- `eval_v4_agents.py`: every trained model + rules on the AIIMS chain; a **collapse
  check** (flags any model using one action >90% of steps), group means with 95% CI
  across seeds, and paired bootstrap comparisons (95% CI; "real" = excludes 0).

### 1.6 Robustness — `robustness_v4.py` (new)
Re-tests the *same trained models* under 9 changed-world settings (firewall effect
weaker/none, attacker faster/slower, perfect/blurrier view, longer exploit). Each
setting runs in a fresh worker (`max_tasks_per_child=1`) — a reused-worker bug had
corrupted one row of an earlier run (`logs/e21`, superseded by `logs/e22`).

### 1.7 GMCP — `gmcp.py`, `gmcp_sim.py`, `device_v3.py`, `gmcp_live_attack.py` (new); `iot_mutator.py` (extended)
The device-coordination protocol the reviewer's "no IoT protocol" comment pointed
at. Signed (HMAC-SHA256, per-device key), sequence-numbered (anti-replay),
two-phase (prepare/commit with retries, aborts if prepare unacked), make-before-
break (new rendezvous opened before the device moves; old closed only after
telemetry confirmed). `device_v3.py` is the new pump; `iot_mutator.py` gained
`--gmcp` variants of topic rotation and broker hop; original functions unchanged.

### 1.8 Real firewall action — `host_firewall.py` (new); `p3_cloud_mutator.py` (edited)
Action 5 (`update_firewall`) was read-only. Now it loads the live AbuseIPDB
high-confidence blocklist into an EC2 `ipset` matched by one `iptables` rule, swaps
it atomically, and verifies entry count + sample membership *on the host*. Unchanged
list → "NO CHANGE" (no false mutation claim). Never blocks the controller's own IP.
`p3_cloud_mutator.update_firewall()` now calls it; the old read-only review is kept
as `firewall_posture_review()`.

### 1.9 CALDERA — `caldera_bridge.py` (edited)
Now imports the single corrected `caldera_ttp_map.py` (it previously kept its own
*wrong* copy — e.g. T1071 didn't touch MQTT). Documents in-code what is live
(connection + operation lifecycle) vs replay (the technique sequence). CALDERA key
reads from `GHOSTNET_CALDERA_KEY`, defaulting to the lab key.

### 1.10 References + paper — `paper/` (new)
- `REFERENCES_VERIFIED.md`: all 16 original refs checked against
  Crossref/arXiv/Semantic Scholar/publishers. None fabricated; 7 had wrong/missing
  details, 4 in-text citations pointed to the wrong paper, 3 sources were missing
  (Claroty, MITRE ATT&CK, Gymnasium). Corrected IEEE entries included. 4 new refs
  (DQN, A2C, HMAC, domain randomization) verified 1 Oct.
- `GhostNet_v4_paper.md`: full reframed paper (source).
- `make_figures.py` + `figures/`: 3 print-safe figures from the result JSONs.
- `build_docx.py`: assembles `GhostNet_v4_IEEE.docx` (A4, two-column, Times New
  Roman, IEEE sizes; resolves [CITE]→[n]; embeds figures + 4 tables).
- `sections/caldera.md`: ready CALDERA text + what to delete from the old draft.

---

## 2. HEADLINE RESULTS (all in `eval_v4_agents.json`, log `e23`)

AIIMS nine-stage chain, 50 seeded test games; learned = mean over 10 seeds.
Lower is better except reward.

| Policy | Break-ins/game | Attacker inside | Disruption |
|---|---|---|---|
| Static (no defence) | 5.00 | 94.9% | 0.00 |
| Round-robin MTD | 3.00 | 3.4% | 4.09 |
| Greedy (most-exposed) | 0.88 | 1.2% | 4.15 |
| **PPO (main)** | **0.69** | 1.3% | **3.61** |
| DQN | 0.72 | 1.1% | 3.45 |
| A2C | 0.87 | 10.1% | 3.61 |
| PPO robust (ppo-fwrand) | 0.92 | 1.4% | 3.80 |
| PPO v2 (old model, in v4 world) | 4.12 | 37.1% | 4.62 |

Key claims (each with a saved CI, do not overstate):
1. **PPO vs greedy on break-ins: NOT significant** (−0.19, 95% CI [−0.44,+0.05]).
   Do not claim the learned policy stops more break-ins than a one-line rule.
2. **Every learned policy disrupts the hospital less than greedy, in all 9
   robustness settings** (significant). This is the reliable benefit.
3. **Collapse is real and silent**: 5 of 10 A2C seeds exceed the 90%-one-action
   threshold; the old reward-defect PPO is indistinguishable from no defence.
4. **Over-reliance on the firewall action**: if its real effect is 0, PPO break-ins
   rise 0.69 → 4.04 (worse than round-robin); robust training cuts this to 1.29.
   (`robustness_v4.json`, log `e22`.)
5. **Feeds ablation**: hiding the feeds does not significantly change break-ins — so
   do NOT claim feeding them to the policy improves security. Their value is the
   real firewall action instead.
6. **GMCP** (`gmcp_sim_results.json`): 0% device stranding up to 50% message loss
   vs 5–51% for the deployed single-notice scheme; forged/replayed/tampered/
   stranding commands all rejected (deployed scheme accepts all).

---

## 3. WHAT IS REAL vs PENDING vs SIMULATED (be precise in the paper)

| Thing | Status |
|---|---|
| Action 1 rotate_port (cloud) | **REAL, verified** on live AWS |
| Action 4 rotate_mqtt_topic (IoT) | **REAL, verified** by telemetry |
| Action 5 update_firewall | **CODE real**; EC2 live validation **PENDING** (runbook Part D) |
| Action 3 broker relocation | **REAL but GATED off** by default |
| Action 0 rotate_cloud_ip | **PARTIAL** — SG tag, not an IP change |
| Action 2 rotate_api_path | **PARTIAL** — writes a local file |
| GMCP | tested in simulation + offline on the laptop; **EC2 live test PENDING** |
| CALDERA | live connection + real operation; techniques by **REPLAY**, not live execution |
| Attacker | a **model** inside the env, not a live red team |
| Device | **simulated** pump |

---

## 4. FILE INVENTORY (v4 additions)

Core new: `ghostnet_env_v4.py`, `train_v4.py`, `eval_v4.py`, `eval_v4_agents.py`,
`robustness_v4.py`, `gmcp.py`, `gmcp_sim.py`, `device_v3.py`, `gmcp_live_attack.py`,
`host_firewall.py`, `rotate_ssh_key.py`.
Edited: `threat_feeds.py`, `ghostnet_config.py`, `iot_mutator.py`,
`p3_cloud_mutator.py`, `caldera_bridge.py`, `dashboard/integration/instrumented_env.py`.
Results: `eval_v4_rules.json`, `eval_v4_agents.json`, `robustness_v4.json`,
`gmcp_sim_results.json`, `phase5_seeded_results.json`, `models/v4/*.zip` (60 models).
Paper: `paper/` (see §1.10). Runbook: `RUNBOOK_LIVE_TESTS.md`.
Logs: `e12` seeded, `e17`/`e20`/`e23` agent evals, `e21`/`e22` robustness,
`e19`/`e24` CALDERA, `v4_training*.txt`.

## 5. HOW TO REPRODUCE

```
python eval_v4.py --episodes 50                 # rule baselines, fair-world sanity
python train_v4.py                              # 10 PPO seeds
python train_v4.py --variant all                # dqn, a2c, ablations (40 models)
python train_v4.py --variant ppo-fwrand         # robust PPO (10 models)
python eval_v4_agents.py --episodes 50          # main comparison table + collapse check
python robustness_v4.py --episodes 50           # 9-setting robustness
python gmcp_sim.py                              # protocol: stranding + attacks
python caldera_bridge.py                        # live CALDERA integration (Docker up)
python paper/make_figures.py                    # regenerate the 3 figures
python paper/build_docx.py                      # rebuild GhostNet_v4_IEEE.docx
```

## 6. WHAT IS LEFT TO DO (priority order)

1. **EC2 live tests** — `RUNBOOK_LIVE_TESTS.md` Parts B–D: broker auth, GMCP topic
   rotation + attack rejection + broker hop, host firewall apply/verify. Save logs
   `e13`–`e18`. Then update the `[LIVE]` numbers in the paper.
2. **CALDERA live run (optional, stronger)** — deploy a CALDERA agent on the EC2
   with real discovery abilities, save the operation report to `logs/`. Needs the
   new .pem, current EC2 IP, and SG access. Otherwise keep the replay wording.
3. **Paper** — add author names/emails; team + guides review `GhostNet_v4_paper.md`;
   a human opens each reference DOI once.
4. **Decide the "AIIMS chain" naming** — cite a source for the AIIMS Delhi
   techniques or rename to "a hospital ransomware chain modelled on reported
   incidents".
5. **Optional, to raise % of live actions from ~22% toward ~88–100%**: make action
   2 real (nginx reverse proxy, secret path rotation, verified from outside) and
   action 0 real (Elastic IP swap; config already reads the host from the ledger).
   Both were scoped but not built this session.

## 7. GOTCHAS / NOTES

- Repo renamed to `ghostnet`; run
  `git remote set-url origin https://github.com/Sangavi-official/ghostnet.git`.
- `gh` (GitHub CLI) is **not installed** on this laptop; PRs are opened via the
  pre-filled compare URL, or install `gh` and `gh auth login`.
- No `pandoc`/`node`/LibreOffice here; the paper is built with `python-docx`, and
  rendered to PDF via the installed Word (COM) for proof-reading.
- `documents/DESOLATER_...pdf` shows an unexplained local modification; left
  uncommitted on purpose — check who changed it.
- Three state dimensions still carry little signal (Shodan ÷50000, saturated
  AbuseIPDB, reset timing) — unchanged from v2; stated as a limitation.
- The v4 world has 7 actions (6 + hold); the live executors know 6. Adding "hold"
  live is trivial (do nothing) and noted for whoever wires it up.

## 8. THE THROUGH-LINE (for the paper and the viva)

A moving-target defence is only trustworthy if **every move is verified end to end —
at the target, at the device, and on the attacker's side.** Checking a command's
return code is not enough: a learned defence can collapse, over-trust one action, or
strand the device it protects, and **none of these produce an external symptom.**
The contribution is the measurement method and the failure modes, with verification
(the ledger, target re-reads, and GMCP) as the fix — not the choice of RL algorithm.

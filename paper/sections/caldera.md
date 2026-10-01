# CALDERA and adversary emulation — paper text

Citation keys refer to `paper/REFERENCES_VERIFIED.md`; final IEEE numbers are
assigned when the full paper is assembled. Every claim below is backed by a
saved log (listed at the end).

---

## Part 1 — Related work (replaces 26 Sept draft §II-D)

**D. Adversary Emulation for Security Evaluation**

MITRE ATT&CK provides a shared taxonomy of adversary tactics and techniques
[Strom2020], and adversary emulation tools use it to exercise defences with
recognisable attack behaviour rather than random traffic. CALDERA, which grew
out of MITRE's work on intelligent, automated red-team emulation
[Applebaum2016], is the most widely used open-source example. Structured,
ATT&CK-aligned red-teaming has been argued to make security assessment more
realistic and repeatable [Yulianto2025]. However, automated emulators cover an
environment unevenly in practice: in a 1,700-hour cyber-range study of four
emulators, CALDERA discovered 27% of the machines and compromised 7%
[Holm2026]. A live emulation run therefore exercises only part of a defence
and is not repeatable from run to run. For this reason GhostNet uses CALDERA
to define and drive the adversary, but compares defence policies on a
deterministic replay of an ATT&CK technique sequence, so that every policy
faces an identical attack.

---

## Part 2 — System design (replaces 26 Sept draft §V-C)

**C. Adversary-Emulation Bridge**

GhostNet connects to a CALDERA server (version 5.0.0) through its REST API.
The bridge creates an adversary profile and an operation, and polls the
operation for executed techniques. Each ATT&CK technique identifier is mapped
to the state dimensions that the technique affects, using a fixed table
(Table X): for example, Network Service Discovery (T1046) raises open-port
exposure and reconnaissance activity, Application Layer Protocol (T1071)
raises MQTT exposure, and Data Encrypted for Impact (T1486) raises all five
attack surfaces at once. This table is an author-defined modelling choice; we
publish it in full so that it can be scrutinised, and the same table is used
by every component of the evaluation.

---

## Part 3 — Evaluation (replaces 26 Sept draft §VI-E)

**E. Adversary Emulation and the Kill-Chain Replay**

*Live integration.* The bridge was run against the CALDERA server, which
created and closed a GhostNet operation through the API (operation
`286a4135-d50f-4405-bc99-ddf67f76a53d`). Because the operation's adversary
profile contains no executable abilities, CALDERA itself executed no
techniques in this run. The run therefore validates the integration path
(connection, operation lifecycle, and the technique-to-state mapping), not
live attack execution against the host.

*Kill-chain replay.* All policy comparisons use a nine-stage hospital
ransomware chain in ATT&CK order: Network Service Discovery (T1046), Exploit
Public-Facing Application (T1190), Valid Accounts (T1078), Remote Services
(T1021), Application Layer Protocol (T1071), Exfiltration Over C2 Channel
(T1041), Data Manipulation (T1565), Data Encrypted for Impact (T1486), and
Service Stop (T1489). Each stage lasts ten decision steps. During a stage,
the active technique adds pressure to the surfaces it targets inside the
environment, so a defensive mutation genuinely pushes the attacker back. The
learned policies were trained on random technique sequences drawn from the
same table rather than on this chain, so the chain's ordering is held out
from training.

*What is not claimed.* We do not report live execution of the nine-stage
chain against the deployment. Replaying the chain trades realism for
repeatability: every policy is evaluated on the same 50 seeded games, which is
what makes the paired statistical comparisons in Section VI possible.

---

## Remove from the 26 Sept draft

- Abstract: *"CALDERA adversary emulation, which executes real reconnaissance
  techniques (T1033, T1087.001, T1057) against the deployed environment."*
  No saved evidence exists (`logs/e19_caldera_operations.txt`).
- §VI-E: *"A CALDERA agent was deployed to the target host ... Three ATT&CK
  techniques executed successfully"* and the claim that the
  Hospital-IoT-Ransomware adversary executed techniques. The profile has no
  abilities, so it executed nothing.
- §V-C: the 30-second half-life description belongs to the old Phase 5 bridge
  overlay. The v4 evaluation applies technique pressure inside the
  environment instead (Part 3).

If the team later runs a live operation with real abilities and saves the
operation report in `logs/`, Part 3 can gain a sentence reporting exactly
which techniques executed. Nothing should be added without that report.

## Evidence for each claim

| Claim | Evidence |
|---|---|
| CALDERA 5.0.0, REST API, operation created and closed | `logs/e24_caldera_bridge_corrected.txt` |
| No techniques executed by CALDERA (0 links) | `logs/e19_caldera_operations.txt` |
| Technique → state table | `caldera_ttp_map.py` |
| Nine-stage chain, 10 steps per stage, in-world pressure | `ghostnet_env_v4.py` |
| Training on random chains, test on the fixed chain | `train_v4.py`, `eval_v4_agents.py` |
| CALDERA coverage 27% / 7% | [Holm2026], verified in `REFERENCES_VERIFIED.md` |

## Open point for the authors

The code calls this the "AIIMS chain". The paper should not say it reproduces
the AIIMS Delhi attack unless a published source describing that attack's
techniques is cited. Safer wording: "a hospital ransomware chain modelled on
the stages typical of publicly reported incidents".

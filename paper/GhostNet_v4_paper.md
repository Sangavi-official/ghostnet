# Verified-at-Target Moving Target Defense for Hospital IoMT-to-Cloud Infrastructure: An Attacker-Side Evaluation and the Silent Failure Modes of Learned Defenses

Sangavi S, N Suha, N Meghana, Dr Mithun D Souza, Dr Kavitha S
Department of Computer Science, CHRIST (Deemed to be University), Bengaluru, India

<!--
EDITING NOTES — read before you touch this file
- Every number below is traceable to a results file; the source is named in an
  HTML comment beside the claim. If you change a number, change the file and
  re-run, do not hand-edit.
- [LIVE] marks a claim that needs the EC2 live tests (RUNBOOK_LIVE_TESTS.md)
  before it can stay. Until then it is written in the conditional.
- [CITE n] is a reference from paper/REFERENCES_VERIFIED.md. Numbers are assigned
  at assembly time from order of first appearance.
- This is the content source. The formatted IEEE Word file is built from it by
  build_docx.py. Edit prose here; re-run that script to refresh the .docx.
-->

## Abstract

Hospital IoMT-to-cloud pipelines run on fixed IP addresses, ports, API paths and
MQTT topics, so an attacker can map them once and exploit them weeks later. Moving
Target Defense (MTD) keeps these properties changing, and recent work drives the
changes with reinforcement learning (RL). We present GhostNet, an MTD system in
which a single learned policy mutates both the cloud and the medical-IoT attack
surface of a hospital pipeline, executes each mutation against real infrastructure
(AWS security groups and a live MQTT broker), and confirms it at the target rather
than trusting an API return code. Our central finding is methodological: a learned
MTD can appear to work while providing no defense, and the only reliable guard is
end-to-end verification. We evaluate against a simulated reconnaissance-and-exploit
attacker that invalidates its own progress when a surface it has mapped is moved,
which lets us measure the outcome a defender cares about — attacker break-ins and
dwell time — instead of agreement with a hand-labeled action. Across ten training
seeds per method, a learned policy stops break-ins no better than a one-line greedy
heuristic (0.69 vs 0.88 break-ins per episode; difference not significant) but
disrupts the hospital 13% less, a gap that holds under every environment
perturbation we tested. We document three ways a learned MTD fails silently: a
collapsed policy indistinguishable from no defense yet still logging actions (also
reproduced in 5 of 10 A2C seeds); over-reliance on a single action whose modeled
effect, if optimistic, triples break-ins with no external symptom; and a relocated
rendezvous point that strands the device it protects. For the last we give GMCP, a
signed, two-phase coordination protocol that eliminates stranding under message
loss and rejects forged, replayed and tampered control commands. We argue that
verification at the target, the device and the attacker's side — not the choice of
RL algorithm — is what makes such a system credible.

*Keywords —* Moving Target Defense; Reinforcement Learning; Healthcare IoT Security; Verified Execution; Adversary Emulation; MQTT

## I. Introduction

Medical IoT devices sit at the center of clinical workflows: infusion pumps,
monitors and imaging systems stream telemetry to cloud-connected platforms. This
connectivity improves care but widens the attack surface into a setting where an
intrusion threatens patient safety, not only finances. Recent healthcare incidents
have followed the same pattern of ransomware and data theft against static,
mappable infrastructure.

The clinical environment stays static largely because it is safety-critical and
hard to change: cloud instances keep fixed public addresses, security groups keep
long-lived ports open, REST endpoints keep stable paths, and MQTT brokers keep
unchanging topics. Because none of this moves, an attacker can scan, fingerprint
and map the environment at leisure, and reconnaissance gathered weeks ahead stays
valid until exploitation. The exposure is compounded by unsupported software: an
industry census of connected medical devices found 14% running an unsupported or
end-of-life operating system [CITE Claroty]. <!-- documents/state-of-cps-security-healthcare-2023.pdf, p.16 -->

Moving Target Defense (MTD) counters this by continuously reconfiguring system
properties so an attacker's map expires before it can be used. A growing line of
work selects MTD actions with reinforcement learning rather than a fixed schedule
[CITE DESOLATER], [CITE Celdran], [CITE Eghtesad], [CITE Zhang]. Most of it,
however, is evaluated in simulation or on one domain, and reports how often the
learned policy takes a "correct" action rather than whether an attacker was
actually slowed. That gap motivates this paper.

We present GhostNet, an MTD system for the hospital IoMT-to-cloud pipeline. A
single policy mutates both cloud infrastructure and IoT messaging, executes each
mutation against live AWS and a live MQTT broker, and verifies it at the target.
Building and stress-testing it surfaced a set of results that we believe matter
more than the system itself. Our contributions are:

1. **An attacker-side evaluation of learned MTD.** We place a
   reconnaissance-and-exploit attacker inside the environment, so a mutation
   genuinely invalidates the attacker's knowledge, and report break-ins, dwell
   time and forced rescans. Under this measure, across ten training seeds per
   method with paired confidence intervals, a learned policy does not stop more
   break-ins than a greedy heuristic, but consistently disrupts the hospital less.
   <!-- eval_v4_agents.json; ghostnet_env_v4.py -->

2. **Three silent failure modes of learned MTD, each measured.** (i) Policy
   collapse yields a defense statistically indistinguishable from none yet still
   selecting actions and logging mutations; we reproduce it both from a reward
   defect and, independently, in 5 of 10 A2C seeds. (ii) Over-reliance on a single
   high-value action: if that action's real effect is weaker than modeled,
   break-ins rise from 0.69 to 4.04 per episode with no external symptom, and
   training under uncertainty about the action's effect cuts this to 1.29. (iii) A
   relocated rendezvous point strands the device it protects.
   <!-- robustness_v4.json; eval_v4_agents.json; logs/e8b_announced_hop.txt -->

3. **GMCP, a mutation-coordination protocol for the IoT domain.** Signed,
   sequence-numbered, two-phase and make-before-break, it removes device stranding
   under control-message loss and rejects forged, replayed and tampered commands,
   addressing the availability and authentication gaps of the naive scheme.
   <!-- gmcp.py; gmcp_sim_results.json -->

4. **A verified dual-domain execution layer.** Every mutation is re-read at the
   target — a security-group query, a host-firewall membership check, or live
   telemetry on a rotated topic — and recorded in a ledger separating intent from
   confirmed effect, with automatic rollback of anything unconfirmed.
   <!-- p3_cloud_mutator.py; iot_mutator.py; mutation_ledger.py -->

We also report honestly what is not yet real: two of six mutation actions change
only a tag or a local file, broker relocation is gated off by default, and the
adversary-emulation integration drives the attack sequence by reproducible replay
rather than live execution. We argue this precision is what makes the rest credible.

## II. Related Work

### A. Reinforcement Learning for Moving Target Defense

Yoon et al. proposed DESOLATER, a deep-RL framework that jointly learns resource
allocation and MTD deployment, weighing security benefit against cost [CITE
DESOLATER]. Huertas Celdrán et al. used RL with behavioral fingerprinting to select
MTD mechanisms against zero-day attacks on single-board IoT devices [CITE Celdran],
and Feng et al. extended this to a federated setting [CITE Feng]. Eghtesad et al.
framed adaptive MTD as a two-player game solved with adversarial deep RL [CITE
Eghtesad], and Zhang et al. applied deep RL to host-address mutation that disrupts
reconnaissance while preserving live connections [CITE Zhang]. These works
establish that a learned policy can outperform a fixed schedule. GhostNet differs
in three respects: it spans cloud and IoT in one policy, it executes against live
infrastructure with verification at the target, and — most relevant to our findings
— it is evaluated by attacker outcome rather than action-label agreement, which is
what exposes the failure modes of Section VI.

### B. Healthcare Cyber-Physical System Security

Healthcare environments combine medical devices, imaging systems and connected
services that must stay available for clinical use. Industry analyses document the
difficulty of inventorying and securing these devices and the prevalence of
unsupported operating systems [CITE Armis], [CITE Claroty]. Conventional patching
is constrained because device changes require clinical testing and coordination,
which motivates defenses that change exposed network properties without depending
on patching.

### C. Cloud Moving Target Defense

Torquato and Vieira surveyed cloud MTD and identified VM migration and IP shuffling
as common mechanisms, noting that multi-layer MTD and standard evaluation methods
remain open problems [CITE Torquato] — gaps this paper speaks to with a dual-domain
system and an outcome-based evaluation. Park et al. proposed Ghost-MTD, mutating
the application protocol with a pre-shared one-time bit sequence and redirecting
non-conforming traffic to a decoy, at 3.28–4.97% overhead [CITE Park]; GMCP
(Section V) likewise authenticates a mutating control channel but targets device
coordination and availability rather than deception. Alavizadeh et al. evaluated
combined shuffle/diversity/redundancy MTD on cloud models including an e-health
context, under both security and economic metrics [CITE Alavizadeh].

### D. Adversary Emulation for Security Evaluation

MITRE ATT&CK provides a shared taxonomy of adversary techniques [CITE ATTACK], and
CALDERA, from MITRE's work on automated red-team emulation [CITE Applebaum], applies
it for automated assessment; structured ATT&CK-aligned red-teaming has been argued
to make assessment more realistic [CITE Yulianto]. Emulators cover an environment
unevenly in practice, however: a 1,700-hour cyber-range study found CALDERA
discovered 27% of machines and compromised 7% [CITE Holm]. GhostNet therefore uses
CALDERA to define and drive the adversary but compares defense policies on a
deterministic replay of an ATT&CK sequence, so every policy faces an identical,
reproducible attack (Section V-C, VI-A).

### E. Research Gap

Prior work addresses RL-driven MTD, healthcare device exposure, and adversary
emulation largely in isolation, and evaluates learned MTD by how often it selects a
labeled action. We are not aware of a system that unifies dual-domain mutation,
verified-at-target execution, and an attacker-outcome evaluation on a hospital
IoMT-to-cloud pipeline, nor of a study that characterizes how such a learned
defense fails silently. GhostNet addresses that combination.

## III. Threat Model and System Architecture

### A. Threat Model

We consider an external, unauthenticated adversary seeking to disrupt or manipulate
the infusion-pump-to-cloud pharmacy pipeline, proceeding through reconnaissance,
initial access, lateral movement, command-and-control and impact, consistent with
ATT&CK tactic ordering. The adversary continuously scans to map surfaces; a surface
becomes exploitable once sufficiently mapped, an exploit takes non-zero time to
land, and **relocating a surface after the adversary has mapped it invalidates that
knowledge and forces a rescan.** The defender does not observe the attacker
directly; it sees a noisy intrusion-detection estimate of per-surface exposure. The
defender's objective is not to prevent every technique but to invalidate
reconnaissance so that later stages fail or cost more. Insider threats,
supply-chain compromise and physical tampering are out of scope. We note that the
unauthenticated control channel of the deployed broker is itself within this model:
anyone able to publish on it could redirect the pump — the motivation for GMCP.

### B. System Architecture

Fig. 1 shows the architecture. A simulated ESP32-class infusion pump streams
telemetry over MQTT to a Mosquitto broker on an AWS EC2 instance. A threat-state
engine combines live threat intelligence and IDS-estimated exposure into a
12-dimensional state vector. A single learned policy maps the state to one of seven
actions (six mutations and hold) and dispatches it to a cloud executor (AWS SDK) or
an IoT executor (an authenticated SSH session and an MQTT control channel that, in
the deployed broker, is unauthenticated until GMCP secures it at the message layer,
Section V-C). Each executor
applies the mutation to live infrastructure and re-reads the target to confirm it;
a mutation ledger records old value, new value and confirmation, supplies the
current live configuration back to the executors, and rolls back anything
unconfirmed. A separate evaluation path drives a MITRE CALDERA operation and a
replayed ATT&CK kill chain.

**[FIGURE 1: paper/figures/fig1_architecture.png — GhostNet architecture.]**

## IV. Methodology

### A. Problem Formulation

We model defense as a Markov Decision Process (S, A, P, R, γ). The state
S ⊆ [0,1]¹² encodes attack-surface exposure and threat conditions; the action set
A = {0,…,6} is six surface mutations plus a hold action; γ = 0.99. The policy π(a|s)
maximizes the expected discounted return E[Σₜ γᵗ R(sₜ,aₜ)]. Actions are chosen from
the current state rather than on a fixed schedule.

### B. Threat-State Representation

The 12-dimensional state (Table I) comprises five surface-exposure dimensions
(0–4), four live threat-intelligence dimensions (5, 6, 10, 11) from NIST NVD,
Shodan, AbuseIPDB and MITRE ATT&CK, and three network/timing dimensions (7–9). All
values are normalized to [0,1]. Threat-intelligence values are sampled per episode
so the policy learns to read them rather than memorize one constant.

**[TABLE I: Threat-State Vector Dimensions — see Table I block below.]**

### C. The Evaluation Environment

A defense that is only scored on whether it picks a "correct" action can score well
without slowing an attacker. We therefore evaluate in an environment where the
attack is part of the dynamics (contributions 1–2 depend on this):

- **In-world attack.** During each kill-chain stage, the active technique raises
  the exposure of the surfaces it targets; a mutation resets the chosen surface's
  exposure, genuinely setting the attacker back. <!-- ghostnet_env_v4.py step() -->
- **Reconnaissance that regrows.** Exposure rises again from continued scanning, so
  mutation *timing* matters and a moved surface does not stay safe for free.
- **An attacker with memory.** When a surface's exposure reaches a launch
  threshold the attacker begins an exploit that lands after a fixed delay; moving
  that surface first makes the attempt fail (recon invalidated). A foothold
  persists until the surface is moved. These states are hidden from the defender.
- **Partial observability.** The defender sees exposure through Gaussian IDS noise.
- **Outcome reward.** Reward is the negative of a weighted sum of mean exposure,
  hot surfaces, compromised surfaces, and the clinical disruption each action
  causes — no term rewards matching a label. <!-- ghostnet_env_v4.py W_* -->

Environment constants (attacker speed, exploit delay, IDS noise, the firewall
action's modeled effect) were frozen using only the rule-based baselines of
Section VI-A, before any agent was trained, and never retuned afterward; Section
VI-D reports sensitivity to them.

### D. Dual-Domain Action Space and the Reality of Each Action

The six mutations and their execution status are listed in Table II. We state
plainly that only two change live infrastructure today: port rotation (cloud) and
MQTT topic rotation (IoT). The host-firewall blocklist (action 5) is implemented
against the live host but its end-to-end validation is pending; broker relocation
(action 3) is gated off by default because it affects every device on the segment;
cloud-IP identity (action 0) writes a security-group tag and API-path rotation
(action 2) writes a local mapping file. This distribution is itself a subject of
Section VI.

**[TABLE II: Dual-Domain Action Space and Execution Status — see Table II block.]**

### E. Reward Design and Two Collapse Modes

Early reward formulations caused policy collapse, and the diagnosis is a result in
its own right (Section VI-B). A first version scored an action by exposure *after*
mutation; because the post-mutation value was effectively random, every action
earned the same expected reward and the policy collapsed to a single action. A
second version valued the broad firewall action by maximum rather than mean surface
exposure, giving it a standing advantage and again collapsing the policy onto it.
The present environment (Section IV-C) scores by pre-mutation exposure and outcome,
removing both degeneracies.

### F. Training Configuration

Policies are trained with PPO [CITE PPO] in Stable-Baselines3 [CITE SB3] on a
Gymnasium environment [CITE Gymnasium] (Table III). To separate real effects from
seed luck we train **ten independent seeds per method** and report the mean and a
95% confidence interval across seeds; the policy kept is the one at the end of
training, with no best-checkpoint selection, so the test set cannot leak into model
choice. The same protocol trains two rival algorithms, DQN [CITE DQN] and A2C [CITE
A2C], and two ablations (threat feeds hidden; hold action removed). Training uses
randomly ordered technique sequences; the fixed AIIMS-style chain used for testing
is never seen in training.

**[TABLE III: Training Hyperparameters — see Table III block.]**

## V. Implementation

### A. Cloud Mutation and Verification

Cloud mutations run through the AWS SDK against a live EC2 security group. Success
is never inferred from the API response: after each mutation the security group is
re-read and compared against intent. This is a requirement, not a diagnostic — an
earlier implementation reported success for operations that only wrote local files.
Port rotation opens the new port, verifies it, closes the old one and verifies
again, holding the open-port count constant. The host-firewall action loads the
current AbuseIPDB high-confidence blocklist into a host ipset matched by one
iptables rule, swaps it atomically, and verifies entry count and sample membership
on the host; an unchanged blocklist is reported as no-change rather than as a
mutation. A mutation ledger records, per mutation, the previous value, the new
value and whether an independent re-read confirmed it; it supplies the live
configuration so a rotation acts on the port actually in use, and flags unconfirmed
mutations for rollback.

### B. IoT Mutation

IoT mutations use two channels. Topic rotation publishes a control message to the
device's command topic; the device switches its publication topic at runtime, and
rotation is confirmed only when telemetry appears on the new topic on an independent
subscription — publishing alone is not treated as evidence. Broker-port migration
rewrites the listener configuration over SSH and restarts the service. Because the
control channel runs on the broker, the broker cannot announce its own relocation
after moving; the naive scheme publishes one relocation notice on the old listener
before moving. Section VI-E measures the failure of this scheme and Section V-C
gives the protocol that fixes it. Because a relocation affects every device on the
segment, the action is gated off by default; the policy may select it, and the
executor declines it unless explicitly enabled.

### C. GMCP: Mutation-Coordination Protocol

GMCP replaces the single unacknowledged notice with four rules. (1) *Authenticated*
— every control message carries an HMAC-SHA256 tag [CITE HMAC] under a per-device
key; unauthenticated messages are dropped. (2) *Fresh* — a monotonic sequence
number and a timestamp defeat replay and stale messages. (3) *Two-phase* —
a prepare/commit exchange with bounded retries; if prepare is never acknowledged
the change is aborted and nothing moves, and retries are idempotent. (4)
*Make-before-break* — the new rendezvous is opened before the device moves and the
old one is closed only after telemetry is confirmed on the new one, so a device
that fails to move falls back to the still-open old listener. The same signed,
sequenced exchange is applied to topic rotation.

### D. Adversary-Emulation Bridge

The bridge connects to a CALDERA 5.0.0 server over its REST API, creates an
operation, and maps each executed ATT&CK technique to the state dimensions it
affects — e.g. network service discovery (T1046) raises open-port and
reconnaissance exposure, application-layer C2 (T1071) raises MQTT exposure, and
data-encrypted-for-impact (T1486) raises all five surfaces. This technique-to-state
table is an author-defined modeling choice, published in full and used identically
by every component. What is live and what is replay is stated in Section VI-A.

## VI. Results and Evaluation

Unless noted, results are on the nine-stage chain (T1046, T1190, T1078, T1021,
T1071, T1041, T1565, T1486, T1489; ten steps per stage), over 50 seeded games;
learned methods are averaged over ten training seeds with a 95% CI across seeds,
and rules over a 95% CI across games. Per-game paired differences between methods
use a 10,000-sample bootstrap; "significant" means the 95% interval excludes zero.
<!-- eval_v4_agents.json -->

### A. Live Feeds and the CALDERA Integration

All four feeds returned live data: NVD 15–20 CVEs per query with peak CVSS 8.8–9.8
(normalized 0.88–0.98, varying across cycles); Shodan 0.003–0.004; AbuseIPDB
saturating at 1.000; ATT&CK 0.033. <!-- logs, threat_feeds.py --> The bridge drove
a real CALDERA operation through the API (created and closed; operation id in the
run log). <!-- logs/e24_caldera_bridge_corrected.txt --> Because the adversary
profile carries no executable abilities, CALDERA executed no techniques in this run;
the integration path is validated, not live execution, and all policy comparisons
use the deterministic replay described above. We make no claim of live execution of
the full chain. <!-- logs/e19_caldera_operations.txt -->

### B. Policy Collapse as a Silent Security Failure

Under the defective reward, mean episode reward stayed flat and explained variance
never left zero; action sampling showed a single action chosen on 30 of 30 sampled
states. The resulting policy leaves the network critically exposed on essentially
every step — indistinguishable from no defense — while still selecting actions,
executing mutations and returning rewards. Nothing external distinguishes it from a
working defense. We observe the same pattern independently in a rival algorithm: 5
of 10 A2C seeds exceed a 90%-single-action collapse threshold (Section VI-C),
confirming collapse is a property of learned MTD under these conditions, not of one
run. <!-- eval_v4_agents.json models[*].collapsed -->

### C. Attacker-Outcome Comparison

Table IV reports the main comparison. A no-defense control is breached on 5.0 of 5
attacker attempts and the attacker holds a foothold 94.9% of the time. Among
non-learning policies, round-robin rotation (classical fixed-schedule MTD) reduces
break-ins to 3.00 per game but still allows them, while a greedy "move the
most-exposed surface" rule reduces them to 0.88. The learned PPO policy reaches 0.69
break-ins; the paired difference from greedy is not significant
(−0.19, 95% CI [−0.44, +0.05]), so **we do not claim the learned policy stops more
break-ins than a one-line rule.** What it does do significantly is act less often on
a hot surface (attacker-launch opportunities 2.33 vs 4.48, significant) and disrupt
the hospital less (3.61 vs 4.15, significant). DQN matches PPO (0.72 break-ins). The
original single-run model from the pre-registration evaluation, run in this
environment, allows 4.12 break-ins and 37.1% dwell — worse than round-robin — which
is why an attacker-side evaluation matters.

**[TABLE IV: Attacker-Outcome Comparison — see Table IV block.]**

### D. Robustness and Over-Reliance on One Action

The learned policies place 51–68% of their decisions on the firewall action
(ablations and rivals similarly), so their security depends on that action's modeled
effect. Fig. 2 re-tests the *same trained policies* as that effect is weakened. When
the firewall action is made ineffective, PPO break-ins rise from 0.69 to 4.04 per
game — worse than round-robin — while the greedy rule, which never uses it, is
unchanged at 0.88. This is a silent failure: in the nominal environment the policy
looks excellent. Training under uncertainty about the action's effect (domain
randomization over its strength [CITE DomainRand]) reduces the worst case to 1.29
break-ins at a small nominal cost (0.92 vs 0.69). The robustness sweep also surfaced
one regime where learning helps on security: under the highest IDS noise
(observation noise 0.20) the learned policies allowed significantly fewer break-ins
than greedy (PPO 1.11 vs 1.44 per game, −0.33, 95% CI [−0.63, −0.05]; DQN 1.04),
plausibly because a greedy rule chases the noisiest apparent surface while the policy
has learned to discount the noise. Across all nine perturbations we tested — attacker
speed, exploit delay, IDS noise, firewall effect — one property held without
exception: every learned policy disrupted the hospital less than greedy. <!-- robustness_v4.json, logs/e22 -->

**[FIGURE 2: paper/figures/fig2_robustness.png — breaches vs firewall effect.]**

### E. The Threat-Feed Ablation

Hiding the four threat-intelligence dimensions from the policy did not significantly
change break-ins (0.62 vs 0.69, CI includes zero). We therefore do **not** claim
that conditioning the policy on the live feeds improves security in this
environment; the feeds' operational value is elsewhere — the firewall action blocks
real AbuseIPDB-reported addresses. This is a negative result we report rather than
omit. <!-- eval_v4_agents.json paired[ppo-nofeeds vs ppo] -->

### F. Verified Infrastructure Mutation

In an integrated run against live infrastructure, independent re-reads confirmed
every cloud and IoT mutation attempted. Port rotation moved the open mutable port
across {8545→8202→8737→8288} while the protected ports (SSH, HTTPS, the MQTT
listener and its websocket) and the total open-port count were held constant,
confirming that repeated rotation does not expand the surface. <!-- logs/e7_full_pipeline_clean.txt --> Of the mutations in the
representative run, those that changed live infrastructure were the port and topic
rotations; the remainder exercised partial or gated actions, consistent with Table
II. [LIVE: numbers from logs/e7; refresh after the hardened-broker run e13.]

### G. Device Availability and GMCP

The naive broker relocation exposes the availability problem: in a measured run the
broker moved and was verified on the new port, yet the pump, told nothing it could
act on, did not reconnect within the 30-second window. <!-- logs/e8b_announced_hop.txt --> Fig. 3 quantifies this over a
lossy control channel in simulation. The no-notice scheme strands the device on
essentially every relocation; the single-notice scheme (as deployed) strands it on
5–51% of relocations as message loss rises from 5% to 50%; GMCP strands it on none,
at the cost of a few extra control messages, falling back to the old listener
whenever the move is not confirmed. <!-- gmcp_sim_results.json --> Against an
adversary able to publish on the broker, the deployed scheme accepts forged,
replayed, cancelled-then-replayed, tampered and stranding-port commands, whereas
GMCP rejects all five. <!-- gmcp_sim_results.json security -->

**[FIGURE 3: paper/figures/fig3_gmcp.png — device stranding vs message loss.]**

## VII. Discussion and Limitations

GhostNet shows that cloud and IoT surface mutation can be coordinated in one
verified loop, and that an attacker-side evaluation changes the conclusions one
draws about it. The system's honest limitations are substantial and we state them so
results are not over-read.

- **Two of six actions are not yet live** (cloud-IP tag, API-path file); two more
  (host firewall, GMCP coordination) are implemented but their end-to-end live
  validation on EC2 is pending. [LIVE]
- **The evaluation attacker is a model,** not a live red team; the CALDERA path
  validates integration, and the kill chain is replay, not concurrent live
  execution.
- **The learned policy does not beat a greedy heuristic on break-ins;** its
  measured advantage is reduced clinical disruption and, under high IDS noise,
  fewer break-ins.
- **Scope is one segment, one device, one cloud instance,** with a simulated pump.
- **The firewall action's modeled effect is an assumption;** Section VI-D is the
  sensitivity analysis, and over-reliance on it is a documented risk.
- **Three state dimensions carry little signal** under current normalization
  (Shodan, saturated AbuseIPDB, reset timing), so the effective state is smaller
  than twelve.

## VIII. Conclusion and Future Work

We presented GhostNet, a verified-at-target, dual-domain moving target defense for
hospital IoMT-to-cloud infrastructure, and used it to argue a methodological point:
a learned MTD can look like a working defense while providing none, and only
end-to-end verification — at the target, the device and the attacker's side —
distinguishes the two. Evaluated by attacker outcome across ten seeds per method, a
learned policy did not stop more break-ins than a one-line heuristic but disrupted
the hospital less; and we characterized three silent failure modes, giving a signed
two-phase protocol that removes the availability failure. Future work will complete
live validation of the partial actions and the host-firewall and GMCP paths on the
deployment, replace the modeled attacker with a live adaptive red team, add a
restore action (the environment already models exposure regrowth and a hold action)
so the full mutation lifecycle is learnable, and scale beyond a
single segment and device. We also intend to make cloud-IP and API-path rotation
live (Elastic IP and a reverse proxy) so that every action the policy can select is
executed and confirmed on real infrastructure.

## Acknowledgment

The authors thank Dr Mithun D Souza and Dr Kavitha S for their guidance, and
CHRIST (Deemed to be University) for supporting this work.

## References

<!-- Final numbered list is emitted from paper/REFERENCES_VERIFIED.md at assembly;
numbers assigned by order of first in-text appearance. New references added here and
verified 1 Oct 2026: DQN (Mnih et al., Nature 2015); A2C (Mnih et al., ICML 2016,
PMLR 48:1928-1937); domain randomization (Tobin et al., IROS 2017); HMAC (Krawczyk
et al., RFC 2104, 1997). -->

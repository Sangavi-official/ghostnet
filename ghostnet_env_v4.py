"""
GhostNet Environment v4 — a fair practice world
================================================
v2/v3 are kept unchanged so every earlier result stays reproducible.
v4 fixes four problems found in the v2 evaluation:

  1. The attack lived OUTSIDE the world. phase5_eval added kill-chain
     boosts to the observation only, so no defensive action could ever
     suppress an ongoing technique. In v4 the attack is part of the
     world: it raises the real surface values, and a mutation really
     pushes them back down.

  2. Nothing grew back. In v2 a mutated surface stayed safe forever, so
     mutation TIMING could not matter. In v4 every surface regrows as
     the attacker keeps scanning, faster under stronger threat signals.

  3. The reward gave away the answer. v2 paid +0.3 for choosing
     argmax(surfaces), so the policy learned that one rule. v4 pays only
     for outcomes: how exposed the network is, whether a surface was
     breached, and how much the mutation disturbed the hospital.

  4. There was no "wait". v4 adds action 6 = hold (no mutation), so the
     agent can choose WHEN to act, not only WHAT to move.

Also:
  - Threat-feed values are sampled per episode (unless given), so the
    agent learns to READ them instead of seeing one constant value.
  - Feeds influence which surfaces grow fastest, so they carry signal.
  - All randomness goes through self.np_random, so a seed reproduces an
    episode exactly (v2 used the global np.random).

STATE VECTOR — same 12 indices as v2 (see STATE_VECTOR_SPEC.txt):
  [0-4] surface exposures   how much the attacker has learned about
                            each surface (0 = nothing, 1 = fully mapped)
  [5]  cve_score  [6] shodan_score  [10] abuse_score  [11] attck_score
  [7]  traffic_load         [8] recon_attempts
  [9]  time_since_mutation  REDEFINED: steps since the last mutation of
                            any kind / 20, capped at 1 (v2 reset it to 0
                            every step, so it carried no information)

ACTIONS: 0-5 as in v2, plus 6 = hold.

WORLD SETTINGS ARE FROZEN (30 Sept 2026) before any agent is trained on v4:
  PRESSURE_RATE = 0.30, EXPLOIT_STEPS = 1, OBS_NOISE = 0.15.
  They were chosen using ONLY the rule-based players in eval_v4.py, so
  that a blind rotation schedule is breached measurably and a greedy
  rule is not perfect. They are never re-tuned after seeing any trained
  agent's result. Sensitivity over 0.20-0.35 / 1-2 / 0-0.20 is reported.

ATTACKER MODEL (attacker-side metrics)
  Exposure is the attacker's reconnaissance: what they have learned about
  a surface. When a surface reaches LAUNCH the attacker starts an exploit
  built from that knowledge. The exploit needs EXPLOIT_STEPS steps to
  land. If the defender rotates that surface before it lands, the
  attacker's map is stale and the exploit FAILS (recon invalidated). If
  it lands, the surface is COMPROMISED: the attacker holds a foothold
  until the defender rotates that surface (eviction).
  The broad firewall action lowers exposure but does not relocate a
  surface, so it neither foils an exploit in flight nor evicts.
  Exploits and footholds are hidden from the defender.

DEFENDER OBSERVATION (partial observability)
  A real defender does not know exactly what the attacker has learned.
  It estimates reconnaissance from IDS alerts and logs, which miss some
  scanning and raise false alarms. The observed surface values are the
  true exposure plus Gaussian noise of std OBS_NOISE, clipped to [0, 1].
  All other state entries are observed exactly. OBS_NOISE = 0 recovers a
  fully observed world (reported as a sensitivity case).
"""

import gymnasium as gym
import numpy as np

from caldera_ttp_map import KILL_CHAIN, TTP_BOOST_MAP

N_SURFACES  = 5
HOLD        = 6
FEED_IDX    = (5, 6, 10, 11)
STAGE_STEPS = 10          # env steps per kill-chain stage
HOT           = 0.70      # attacker knows enough to be dangerous
LAUNCH        = 0.95      # attacker knows enough to launch an exploit
EXPLOIT_STEPS = 1         # steps from launch until the exploit lands
OBS_NOISE     = 0.15      # std of the defender's IDS estimate of exposure

ACTION_NAMES = ["rotate_cloud_ip", "rotate_port", "rotate_api_path",
                "rotate_iot_ip", "rotate_mqtt_topic", "update_firewall",
                "hold"]

# How fast each surface regrows from background scanning, per step.
BASE_GROWTH  = 0.005
RECON_GROWTH = 0.020      # extra growth at recon_attempts = 1.0

# Kill-chain pressure: a TTP boost of b adds b * PRESSURE_RATE per step
# to the surface it targets, for as long as its stage lasts.
# 0.30 chosen so that a blind rotation schedule (round-robin) is breached
# in a measurable share of steps; 0.20-0.35 reported as sensitivity.
PRESSURE_RATE = 0.30

# Threat feeds speed up the surfaces they are evidence about.
# Modelling assumption, stated in the paper and tested by ablation.
FEED_PRESSURE = {
    5:  {1: 0.03, 2: 0.03},   # CVE severity   -> exposed services, API
    6:  {0: 0.03, 1: 0.02},   # Shodan counts  -> internet-facing IP, ports
    10: {0: 0.02, 3: 0.02},   # AbuseIPDB      -> active scanning of IPs
    11: {4: 0.03, 3: 0.01},   # ATT&CK health  -> IoT / MQTT techniques
}

# Broad firewall action: lowers every surface's exposure by this much.
# Modelling assumption. The live action (host_firewall.py) only helps
# when the AbuseIPDB blocklist actually changes, so robustness_v4.py
# re-tests the trained agents with weaker values (0.10, 0.05, 0.0).
FIREWALL_CUT = 0.15

# Disruption to the hospital caused by each action (before traffic
# scaling). IoT actions interrupt pump telemetry, so they cost more.
DISRUPTION = [0.03, 0.02, 0.03, 0.10, 0.05, 0.04, 0.0]

# Reward weights
W_EXPOSURE = 0.10
W_HOT      = 0.20
W_COMPROMISE = 1.00       # per compromised surface, per step


class GhostNetEnvV4(gym.Env):

    STATE_DIM = 12

    def __init__(self, chain="random", feeds=None, stages=9,
                 mask_feeds=False, allow_hold=True, firewall_cut_range=None):
        """
        chain  "random"  -> a new random sequence of TTPs every episode
                            (training: the agent cannot memorise one chain)
               "aiims"   -> the fixed hospital kill chain (evaluation)
               list      -> an explicit TTP sequence
               None      -> no attack, background scanning only
        feeds  None -> sampled uniformly per episode
               dict {5: cve, 6: shodan, 10: abuse, 11: attck} -> fixed

        Ablations (the world itself is unchanged in both):
        mask_feeds  True -> the defender sees 0 for indices 5, 6, 10, 11.
                    Tests whether reading threat intelligence helps.
        allow_hold  False -> 6 actions, no hold; the defender must mutate
                    every step. Tests whether choosing WHEN helps.

        Robust training (training worlds only, never the test world):
        firewall_cut_range  (lo, hi) -> each episode draws the firewall's
                    strength uniformly from this range, so the agent cannot
                    rely on one modelled value. None -> FIREWALL_CUT.
        """
        super().__init__()
        self.chain_mode  = chain
        self.fixed_feeds = feeds
        self.mask_feeds  = mask_feeds
        self.fw_range    = firewall_cut_range
        self.fw_cut      = None
        self.stages      = stages
        self.max_steps   = stages * STAGE_STEPS

        self.observation_space = gym.spaces.Box(0.0, 1.0, (self.STATE_DIM,), np.float32)
        self.action_space      = gym.spaces.Discrete(7 if allow_hold else 6)
        self.state = None

    # ------------------------------------------------------------------
    def _pick_chain(self):
        mode = self.chain_mode
        if mode is None:
            return []
        if mode == "aiims":
            return list(KILL_CHAIN[:self.stages])
        if mode == "random":
            pool = list(TTP_BOOST_MAP)
            return [pool[i] for i in self.np_random.integers(0, len(pool), self.stages)]
        return list(mode)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        r = self.np_random
        s = np.zeros(self.STATE_DIM, dtype=np.float32)

        s[0:N_SURFACES] = r.uniform(0.0, 0.4, N_SURFACES)
        s[7] = r.uniform(0.1, 0.6)                     # traffic_load
        s[8] = r.uniform(0.0, 0.3)                     # recon_attempts
        s[9] = 0.0

        feeds = self.fixed_feeds or {i: float(r.uniform()) for i in FEED_IDX}
        for i in FEED_IDX:
            s[i] = feeds[i]

        self.state       = s
        self.chain       = self._pick_chain()
        self.t           = 0
        self.since_mut   = 0
        self.traffic_base = float(s[7])

        # Attacker bookkeeping (hidden from the defender)
        self.exploit     = np.full(N_SURFACES, -1, dtype=int)   # steps left, -1 = none
        self.compromised = np.zeros(N_SURFACES, dtype=bool)
        self.stats = {"launched": 0, "succeeded": 0, "foiled": 0,
                      "evicted": 0, "first_compromise": None}
        # Drawn last, and only for robust training, so the default
        # random stream (and every reported result) is unchanged.
        self.fw_cut = float(r.uniform(*self.fw_range)) if self.fw_range else None
        return self._observe(), {"chain": self.chain}

    # ------------------------------------------------------------------
    def _observe(self):
        """What the defender sees: noisy surface estimates, exact rest."""
        o = self.state.copy()
        if OBS_NOISE > 0:
            o[0:N_SURFACES] = np.clip(
                o[0:N_SURFACES] + self.np_random.normal(0, OBS_NOISE, N_SURFACES), 0, 1)
        if self.mask_feeds:
            o[list(FEED_IDX)] = 0.0
        return o.astype(np.float32)

    def _stage(self):
        k = self.t // STAGE_STEPS
        return (k, self.chain[k]) if k < len(self.chain) else (k, None)

    def step(self, action):
        action = int(action)
        r = self.np_random
        s = self.state.copy()
        traffic = float(s[7])

        # 1. Defender acts ------------------------------------------------
        foiled = evicted = 0
        if action < N_SURFACES:
            s[action] = r.uniform(0.0, 0.10)          # attacker's map of it is now stale
            if self.exploit[action] >= 0:             # exploit in flight -> fails
                self.exploit[action] = -1
                foiled = 1
            if self.compromised[action]:              # foothold lost
                self.compromised[action] = False
                evicted = 1
        elif action == 5:
            cut = FIREWALL_CUT if self.fw_cut is None else self.fw_cut
            s[0:N_SURFACES] = np.maximum(0.0, s[0:N_SURFACES] - cut)
        mutated = action != HOLD
        self.since_mut = 0 if mutated else self.since_mut + 1
        disruption = DISRUPTION[action] * (0.5 + traffic)

        # 2. Attacker acts (inside the world) -------------------------------
        growth = np.full(N_SURFACES, BASE_GROWTH + RECON_GROWTH * float(s[8]))
        for f, targets in FEED_PRESSURE.items():
            for surf, rate in targets.items():
                growth[surf] += rate * float(s[f])

        stage, ttp = self._stage()
        boosts = TTP_BOOST_MAP.get(ttp, {}) if ttp else {}
        for idx, b in boosts.items():
            if idx < N_SURFACES:
                growth[idx] += b * PRESSURE_RATE
        s[0:N_SURFACES] = np.clip(s[0:N_SURFACES] + growth * r.uniform(0.7, 1.3, N_SURFACES), 0, 1)

        # recon rises while the attacker is active; traffic wanders around
        # its baseline and rises when a technique loads the network
        s[8] = np.clip(s[8] + r.uniform(0, 0.01) + 0.05 * boosts.get(8, 0.0), 0, 1)
        s[7] = np.clip(traffic + r.normal(0, 0.02) + 0.05 * (self.traffic_base - traffic)
                       + 0.05 * boosts.get(7, 0.0), 0.05, 0.95)
        s[9] = min(1.0, self.since_mut / 20.0)

        # 3. Exploits in flight advance; new ones launch -------------------
        surf = s[0:N_SURFACES]
        succeeded = launched = 0
        for i in range(N_SURFACES):
            if self.exploit[i] >= 0:
                self.exploit[i] -= 1
                if self.exploit[i] == 0:
                    self.exploit[i] = -1
                    self.compromised[i] = True
                    succeeded += 1
            if surf[i] >= LAUNCH and self.exploit[i] < 0 and not self.compromised[i]:
                self.exploit[i] = EXPLOIT_STEPS
                launched += 1
        st = self.stats
        st["launched"] += launched; st["succeeded"] += succeeded
        st["foiled"] += foiled;     st["evicted"] += evicted
        if succeeded and st["first_compromise"] is None:
            st["first_compromise"] = self.t + 1

        # 4. Score the outcome ---------------------------------------------
        n_hot         = int((surf > HOT).sum())
        n_compromised = int(self.compromised.sum())
        reward = -(W_EXPOSURE * float(surf.mean())
                   + W_HOT * n_hot
                   + W_COMPROMISE * n_compromised
                   + disruption)

        self.state = s
        self.t += 1
        done = self.t >= self.max_steps
        info = {"stage": stage, "ttp": ttp, "mutated": mutated,
                "n_hot": n_hot, "n_compromised": n_compromised,
                "launched": launched, "succeeded": succeeded,
                "foiled": foiled, "evicted": evicted,
                "disruption": disruption, "peak": float(surf.max()),
                "attack": dict(self.stats)}
        info["true_surfaces"] = s[0:N_SURFACES].copy()
        return self._observe(), float(reward), done, False, info

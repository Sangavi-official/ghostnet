"""
gmcp.py — GhostNet Mutation Coordination Protocol
==================================================
The original device-notification scheme was one unacknowledged control
message: no authentication, no replay protection, no acknowledgement,
no retry. So anyone able to publish on the broker could redirect the
pump, a recorded command could be replayed to undo a rotation, and a
lost notice left the device stranded (logs/e8b_announced_hop.txt).

GMCP fixes this with four rules:

  1. AUTHENTICATED  every message carries an HMAC-SHA256 tag computed
                    with a per-device key shared by controller and device.
                    Messages with a bad tag are dropped silently.
  2. FRESH          every command has a sequence number that only goes
                    up, and a timestamp. The device drops any sequence
                    number it has already used (replay) and any message
                    older than MAX_SKEW seconds.
  3. TWO-PHASE      PREPARE -> device ACKs "prepared"
                    COMMIT  -> device applies the change, ACKs "committed"
                    Each step is retried up to RETRIES times. If PREPARE
                    is never acknowledged the mutation is ABORTED and
                    nothing changes. Retries are safe: the device answers
                    a repeated message with the same ACK (idempotent).
  4. MAKE BEFORE BREAK  (applied by the executor, not this module) the
                    new rendezvous is opened BEFORE the device moves and
                    the old one is closed only AFTER telemetry is seen on
                    the new one. A device that fails to move falls back
                    to the old one, which is still open.

This module is transport-agnostic: it builds, signs and checks messages
and holds the device's protocol state. The same code runs in the offline
simulator (gmcp_sim.py) and over real MQTT.

Message fields
  v    protocol version        dev  device id
  seq  sequence number         ts   sender clock (seconds)
  type prepare | commit | abort | ack
  cmd  {"action": "rotate_topic", "new_topic": ...}
       {"action": "broker_move",  "new_port": ...}
  status (ack only) prepared | committed | aborted
  mac  HMAC-SHA256 over every other field, canonical JSON
"""

import hashlib
import hmac
import json

VERSION     = 1
MAX_SKEW    = 30.0      # seconds a message stays valid
PREPARE_TTL = 30.0      # device forgets an un-committed PREPARE after this
RETRIES     = 4         # sends per phase before giving up
ACK_TIMEOUT = 2.0       # seconds to wait for each ACK


# ─── signing ────────────────────────────────────────────────────────────
def _body(msg):
    return json.dumps({k: v for k, v in msg.items() if k != "mac"},
                      sort_keys=True, separators=(",", ":")).encode()


def sign(key, msg):
    """Return a copy of msg with its HMAC tag."""
    return {**msg, "mac": hmac.new(key, _body(msg), hashlib.sha256).hexdigest()}


def verify(key, msg):
    tag = msg.get("mac")
    if not isinstance(tag, str):
        return False
    good = hmac.new(key, _body(msg), hashlib.sha256).hexdigest()
    return hmac.compare_digest(tag, good)


# ─── controller side ───────────────────────────────────────────────────
class Controller:
    """
    Builds commands for one device. `next_seq` must survive restarts
    (store it in the mutation ledger), otherwise a restarted controller
    would reuse numbers the device already rejected as replays.
    """

    def __init__(self, dev_id, key, clock, next_seq=1):
        self.dev, self.key, self.clock = dev_id, key, clock
        self.next_seq = next_seq

    def _msg(self, type_, seq, cmd=None):
        m = {"v": VERSION, "dev": self.dev, "seq": seq, "ts": self.clock(), "type": type_}
        if cmd is not None:
            m["cmd"] = cmd
        return sign(self.key, m)

    def new_seq(self):
        s = self.next_seq
        self.next_seq += 1
        return s

    def prepare(self, seq, cmd): return self._msg("prepare", seq, cmd)
    def commit(self, seq):       return self._msg("commit", seq)
    def abort(self, seq):        return self._msg("abort", seq)

    def is_ack(self, msg, seq, status):
        return (isinstance(msg, dict) and verify(self.key, msg)
                and msg.get("type") == "ack" and msg.get("dev") == self.dev
                and msg.get("seq") == seq and msg.get("status") == status)


def run_transaction(ctrl, send, recv, cmd, retries=RETRIES, timeout=ACK_TIMEOUT):
    """
    Drive one PREPARE/COMMIT exchange.
      send(msg)          deliver a message towards the device (may be lost)
      recv(seq, status, timeout) -> True if a matching valid ACK arrived
    Returns (outcome, seq, messages_sent) where outcome is
      "committed"  device confirmed the change
      "aborted"    device never confirmed PREPARE; nothing changed
      "uncertain"  PREPARE confirmed but COMMIT never acknowledged; the
                   caller must decide from ground truth (telemetry)
    """
    seq, sent = ctrl.new_seq(), 0
    for _ in range(retries):
        send(ctrl.prepare(seq, cmd)); sent += 1
        if recv(seq, "prepared", timeout):
            break
    else:
        send(ctrl.abort(seq)); sent += 1
        return "aborted", seq, sent
    for _ in range(retries):
        send(ctrl.commit(seq)); sent += 1
        if recv(seq, "committed", timeout):
            return "committed", seq, sent
    return "uncertain", seq, sent


# ─── device side ───────────────────────────────────────────────────────
class Device:
    """
    Protocol state for one device. handle() takes a received message and
    returns (reply_or_None, effect_or_None). `effect` is the command the
    device must now apply (e.g. switch topic); applying it is the
    caller's job, so this class never touches the network.
    """

    def __init__(self, dev_id, key, clock, last_seq=0):
        self.dev, self.key, self.clock = dev_id, key, clock
        # highest CLOSED sequence number (committed or aborted); anything
        # at or below it is a replay. Must survive device restarts.
        self.last_seq = last_seq
        self.last_committed = last_seq
        self.pending = None          # (seq, cmd, prepared_at)
        self.rejected = {"bad_mac": 0, "replay": 0, "stale": 0, "other": 0}

    def _ack(self, seq, status):
        return sign(self.key, {"v": VERSION, "dev": self.dev, "seq": seq,
                               "ts": self.clock(), "type": "ack", "status": status})

    def handle(self, msg):
        now = self.clock()
        if not isinstance(msg, dict) or not verify(self.key, msg):
            self.rejected["bad_mac"] += 1
            return None, None
        if msg.get("v") != VERSION or msg.get("dev") != self.dev:
            self.rejected["other"] += 1
            return None, None
        seq, typ = msg.get("seq"), msg.get("type")
        if not isinstance(seq, int):
            self.rejected["other"] += 1
            return None, None

        # A retry of the last committed command: re-ACK, change nothing.
        if typ == "commit" and seq == self.last_committed:
            return self._ack(seq, "committed"), None
        if seq <= self.last_seq:
            self.rejected["replay"] += 1
            return None, None
        if abs(now - float(msg.get("ts", -1e9))) > MAX_SKEW:
            self.rejected["stale"] += 1
            return None, None
        if self.pending and now - self.pending[2] > PREPARE_TTL:
            self.pending = None

        if typ == "prepare":
            cmd = msg.get("cmd")
            if not isinstance(cmd, dict) or cmd.get("action") not in ("rotate_topic", "broker_move"):
                self.rejected["other"] += 1
                return None, None
            if not self.pending or self.pending[0] != seq:
                self.pending = (seq, cmd, now)
            return self._ack(seq, "prepared"), None

        if typ == "commit":
            if not self.pending or self.pending[0] != seq:
                self.rejected["other"] += 1          # commit without prepare
                return None, None
            cmd = self.pending[1]
            self.pending = None
            self.last_seq = self.last_committed = seq
            return self._ack(seq, "committed"), cmd

        if typ == "abort":
            # Close the number too, so a recorded PREPARE/COMMIT for this
            # cancelled command can never be replayed later.
            if self.pending and self.pending[0] == seq:
                self.pending = None
            self.last_seq = max(self.last_seq, seq)
            return self._ack(seq, "aborted"), None

        self.rejected["other"] += 1
        return None, None

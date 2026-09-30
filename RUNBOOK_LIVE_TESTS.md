# Live tests on the EC2 — step-by-step

For whoever runs the real-infrastructure session. Do the parts **in order**.
Every command is **one line**. Paste one line, press Enter, wait for it to
finish, then paste the next. Never paste several lines at once into PowerShell.

Replace `EC2_IP` with the current EC2 public IP (it changes on stop/start).

---

## Part A — Lock the doors (keys)

The old keys were uploaded to GitHub and shared in a zip. They must be replaced.

1. **NIST**: request a new key at nvd.nist.gov.
2. **Shodan**: account.shodan.io → Reset API Key.
3. **AbuseIPDB**: Account → API → create a new key, delete the old one.
4. Save each new key on the laptop (put the key between the quotes):
   ```
   setx GHOSTNET_NIST_KEY "new-key-here"
   ```
   ```
   setx GHOSTNET_SHODAN_KEY "new-key-here"
   ```
   ```
   setx GHOSTNET_ABUSEIPDB_KEY "new-key-here"
   ```
5. Close the terminal, open a new one, and check it works:
   ```
   python threat_feeds.py
   ```
6. **Server key (.pem)**: AWS console → EC2 → Key Pairs → create a new key pair.
   Add its public key to the server **before** removing the old one, or you
   lock yourself out. Never put the .pem file in a zip or in GitHub.

**Never paste a key into a chat, a document or a commit.**

---

## Part B — Broker login (from the v3 handoff, §7)

Follow `GHOSTNET_HANDOFF_V3` §7, steps 1–10, with **one change** to step 5:
the pump must also be allowed to send its "got it" replies. Use this ACL line instead:

```
ssh -i ghostnet-iot-key.pem ubuntu@EC2_IP "printf 'user ghostnet\ntopic readwrite #\n\nuser pump1\ntopic write hospital/icu/vitals/#\ntopic read ghostnet/control/pump1\ntopic write ghostnet/ack/pump1\n' | sudo tee /etc/mosquitto/ghostnet.acl > /dev/null; sudo chown mosquitto:mosquitto /etc/mosquitto/ghostnet.acl; echo ACL_OK"
```

Proof for the paper: step 10 of §7 (anonymous connection **must fail**).
Save the output as `logs\e13_broker_auth.txt`.

---

## Part C — The new pump protocol (GMCP)

### C1. Make the shared secret (once)

This creates a random 64-character secret. The laptop and the pump both need it.
```
python -c "import secrets; print(secrets.token_hex(32))"
```
Save it on the laptop (paste the printed value between the quotes):
```
setx GHOSTNET_GMCP_KEY "paste-the-64-characters-here"
```
Close and reopen the terminal.

### C2. Copy the new pump code to the EC2
```
scp -i ghostnet-iot-key.pem gmcp.py device_v3.py ubuntu@EC2_IP:/home/ubuntu/
```

### C3. Stop the old pump
```
ssh -i ghostnet-iot-key.pem ubuntu@EC2_IP "pkill -f '[d]evice'; sleep 2; echo STOPPED"
```

### C4. Start the new pump
Replace `THE_KEY` with the same 64 characters, and `PUMP_PASSWORD` with the pump1 broker password.
```
ssh -i ghostnet-iot-key.pem ubuntu@EC2_IP "GHOSTNET_GMCP_KEY=THE_KEY GHOSTNET_MQTT_USER=pump1 GHOSTNET_MQTT_PASS=PUMP_PASSWORD nohup python3 -u device_v3.py 1883 > pump.log 2>&1 & sleep 6; tail -4 pump.log"
```
You should see `connected on :1883` and telemetry lines.

To read the pump log at any time:
```
ssh -i ghostnet-iot-key.pem ubuntu@EC2_IP "tail -20 pump.log"
```

### C5. Test 1 — topic rotation with GMCP (run it 10 times)
```
1..10 | ForEach-Object { python iot_mutator.py --topic --gmcp } | Tee-Object logs\e14_gmcp_topic.txt
```
Expected: every line says `GMCP seq N committed ... CONFIRMED live telemetry`.

### C6. Test 2 — attacks on the live pump
Forged commands:
```
python gmcp_live_attack.py --forge | Tee-Object logs\e15_gmcp_attack_forge.txt
```
Then read the pump log (command in C4). Every attack line must say `REJECTED (bad_mac)`.

Replay: open **two** terminals. In terminal 1:
```
python gmcp_live_attack.py --replay | Tee-Object logs\e15_gmcp_attack_replay.txt
```
In terminal 2:
```
python iot_mutator.py --topic --gmcp
```
Then read the pump log: the replay must say `REJECTED (replay)` and the topic must not change back.
Save the pump log too:
```
ssh -i ghostnet-iot-key.pem ubuntu@EC2_IP "cat pump.log" > logs\e15_pump_log.txt
```

### C7. Test 3 — broker move with GMCP (run it 5 times)
```
1..5 | ForEach-Object { python iot_mutator.py --port-hop --gmcp } | Tee-Object logs\e16_gmcp_broker_hop.txt
```
Expected: `broker A -> B | GMCP seq N committed | telemetry on new listener after X s`.

### C8. Test 4 — the pump is OFF during a broker move (the stranding test)
This is the case that stranded the pump before. Stop the pump (C3), then:
```
python iot_mutator.py --port-hop --gmcp | Tee-Object logs\e16_gmcp_hop_pump_off.txt
```
Expected: `device never confirmed PREPARE ... old listener kept`. **Nothing moved, nobody stranded.**
Start the pump again (C4) and check it connects on the old port.

---

## If something goes wrong

| What you see | Why | Fix |
|---|---|---|
| Pump log says `REJECTED (replay)` for **real** commands | The laptop's ticket counter is behind the pump's (e.g. ledger file was reset) | `python -c "from mutation_ledger import ledger; ledger.set_config('gmcp_next_seq', 1000)"` |
| Pump log says `REJECTED (stale)` | Laptop and EC2 clocks differ by more than 30 s | Sync the laptop clock (Windows Settings → Time → Sync now) |
| Pump log says `REJECTED (bad_mac)` for **real** commands | Laptop and pump have different secrets | Repeat C4 with exactly the same key as `GHOSTNET_GMCP_KEY` |
| `set GHOSTNET_GMCP_KEY` error | Terminal opened before `setx` | Open a new terminal |

## Afterwards

Send the `logs\e13` to `logs\e16` files to the paper writers. If anything
fails, copy the exact error text; don't debug in a hurry. Undo for the
broker config: §7 step 4 of the handoff.

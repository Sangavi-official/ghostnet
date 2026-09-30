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
6. **Server key (.pem)**. Deleting a key pair in the AWS console does NOT stop
   the old key opening the server; the server's own trusted-key list must change.
   `rotate_ssh_key.py` does it in a safe order (add new → prove it → remove old).
   1. AWS console → EC2 → Key Pairs → **Create key pair**: name `ghostnet-key-2026`,
      type **RSA**, format **.pem**. It downloads once; keep it safe.
   2. Move it out of OneDrive, into your own SSH folder:
      ```
      New-Item -ItemType Directory -Force $HOME\.ssh
      ```
      ```
      Move-Item $HOME\Downloads\ghostnet-key-2026.pem $HOME\.ssh\
      ```
   3. Check the current key still logs in (must say `ok`):
      ```
      python rotate_ssh_key.py --check
      ```
   4. Phase 1, add the new key (must say `TEST PASSED`):
      ```
      python rotate_ssh_key.py --add $HOME\.ssh\ghostnet-key-2026.pem
      ```
   5. Point GhostNet at the new key, then **close and reopen** the terminal:
      ```
      setx GHOSTNET_KEY_PATH "C:\Users\nazee\.ssh\ghostnet-key-2026.pem"
      ```
   6. Phase 2, remove the old key (must end with `DONE`):
      ```
      python rotate_ssh_key.py --remove-old C:\Users\nazee\OneDrive\Documents\capstone-project\ghostnet-iot-key.pem
      ```
   7. Tidy up: delete the old key pair in the AWS console, delete the old
      `.pem` everywhere (project folder, Downloads, zip copies), and give
      teammates the new key privately.

   Never put a .pem file in a zip, OneDrive or GitHub.

**Never paste a key into a chat, a document or a commit.**

---

## Part B — Broker login (from the v3 handoff, §7)

Follow `GHOSTNET_HANDOFF_V3` §7, steps 1–10, with **one change** to step 5:
the pump must also be allowed to send its "got it" replies. Use this ACL line instead:

```
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "printf 'user ghostnet\ntopic readwrite #\n\nuser pump1\ntopic write hospital/icu/vitals/#\ntopic read ghostnet/control/pump1\ntopic write ghostnet/ack/pump1\n' | sudo tee /etc/mosquitto/ghostnet.acl > /dev/null; sudo chown mosquitto:mosquitto /etc/mosquitto/ghostnet.acl; echo ACL_OK"
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
scp -i $env:GHOSTNET_KEY_PATH gmcp.py device_v3.py ubuntu@EC2_IP:/home/ubuntu/
```

### C3. Stop the old pump
```
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "pkill -f '[d]evice'; sleep 2; echo STOPPED"
```

### C4. Start the new pump
Replace `THE_KEY` with the same 64 characters, and `PUMP_PASSWORD` with the pump1 broker password.
```
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "GHOSTNET_GMCP_KEY=THE_KEY GHOSTNET_MQTT_USER=pump1 GHOSTNET_MQTT_PASS=PUMP_PASSWORD nohup python3 -u device_v3.py 1883 > pump.log 2>&1 & sleep 6; tail -4 pump.log"
```
You should see `connected on :1883` and telemetry lines.

To read the pump log at any time:
```
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "tail -20 pump.log"
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
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "cat pump.log" > logs\e15_pump_log.txt
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

## Part D — The real firewall action (action 5)

Needs Part A done (a working AbuseIPDB key).

### D1. Install the firewall tool on the EC2 (once)
```
ssh -i $env:GHOSTNET_KEY_PATH ubuntu@EC2_IP "sudo apt-get install -y ipset; ipset --version"
```

### D2. Check the state before (should show no set, no rule)
```
python host_firewall.py --status | Tee-Object logs\e18_firewall_before.txt
```

### D3. Apply the blocklist
```
python host_firewall.py --apply | Tee-Object logs\e18_firewall_apply.txt
```
Expected: `SUCCESS | host firewall now blocks N AbuseIPDB IPs ... verified=True`.

### D4. Apply again straight away (must say NO CHANGE)
```
python host_firewall.py --apply | Tee-Object logs\e18_firewall_nochange.txt
```
Expected: `blocklist already current ... [NO CHANGE]`. This shows GhostNet does not claim a change that did not happen.

### D5. Check you can still reach everything
SSH still works (you just used it), and the pump is still sending data:
```
python mqtt_watch.py
```

### D6. Undo (only if needed)
```
python host_firewall.py --remove
```

---

## If something goes wrong

| What you see | Why | Fix |
|---|---|---|
| Pump log says `REJECTED (replay)` for **real** commands | The laptop's ticket counter is behind the pump's (e.g. ledger file was reset) | `python -c "from mutation_ledger import ledger; ledger.set_config('gmcp_next_seq', 1000)"` |
| Pump log says `REJECTED (stale)` | Laptop and EC2 clocks differ by more than 30 s | Sync the laptop clock (Windows Settings → Time → Sync now) |
| Pump log says `REJECTED (bad_mac)` for **real** commands | Laptop and pump have different secrets | Repeat C4 with exactly the same key as `GHOSTNET_GMCP_KEY` |
| `set GHOSTNET_GMCP_KEY` error | Terminal opened before `setx` | Open a new terminal |
| `UNPROTECTED PRIVATE KEY FILE` from `ssh -i` | Windows lets other accounts read the .pem | `icacls $env:GHOSTNET_KEY_PATH /inheritance:r /grant:r "$($env:USERNAME):(R)"` |
| `cannot reach ...` from `rotate_ssh_key.py` | EC2 stopped, or its public IP changed | Start it / `setx GHOSTNET_EC2_HOST <new ip>`, new terminal |
| `ipset not installed on host` | D1 not done | Run D1 |
| `no blocklist: ... not set` | AbuseIPDB key missing | Part A step 4, then a new terminal |
| `AbuseIPDB request rejected: HTTP 429` | Daily download limit reached | Wait until tomorrow; the saved list is reused meanwhile |

## Afterwards

Send the `logs\e13` to `logs\e18` files to the paper writers. If anything
fails, copy the exact error text; don't debug in a hurry. Undo for the
broker config: §7 step 4 of the handoff.

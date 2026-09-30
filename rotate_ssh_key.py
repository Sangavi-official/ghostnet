"""
rotate_ssh_key.py — replace the EC2 SSH key without locking yourself out
=========================================================================
Why this is needed
  The old private key (ghostnet-iot-key.pem) was shared inside a zip, so
  anyone with a copy can log in to the EC2. Deleting the key pair in the
  AWS console does NOT stop that: the server trusts every public key
  listed in ~/.ssh/authorized_keys, and AWS never edits that file after
  launch. The list on the server itself has to change.

Safe order (you can never lock yourself out)
  Phase 1   python rotate_ssh_key.py --add NEW.pem
            Logs in with the CURRENT key, adds the NEW public key, then
            opens a second connection with ONLY the new key to prove it.

  Between   setx GHOSTNET_KEY_PATH "<full path of NEW.pem>"
            then close the terminal and open a new one.

  Phase 2   python rotate_ssh_key.py --remove-old OLD.pem
            Logs in with the NEW key and stays connected. Removes the OLD
            public key (backup kept), then proves the new key still works
            and the old key is now REFUSED. If the new key stops working,
            it restores the backup through the connection it kept open.

  Any time  python rotate_ssh_key.py --check [KEY.pem ...]
            Which keys can log in right now?
"""

import argparse
import os
import sys
import time

import paramiko

import ghostnet_config as cfg

AUTH = "$HOME/.ssh/authorized_keys"


# ─── remote commands (plain functions so they can be tested offline) ──────
def add_cmd(line):
    """Back up the list, make sure it ends in a newline, append one key line."""
    return (f'cp "{AUTH}" "{AUTH}.bak" && '
            f'if [ -n "$(tail -c1 "{AUTH}")" ]; then echo >> "{AUTH}"; fi && '
            f"printf '%s\\n' '{line}' >> \"{AUTH}\"")


def remove_cmd(old_blob, new_blob):
    """Drop every line holding the old key. Refuses to install the result
    unless the new key is still in it, so the list can never end up
    without a working key."""
    return (f'cp "{AUTH}" "{AUTH}.bak2" && '
            f"grep -v -F '{old_blob}' \"{AUTH}.bak2\" > \"{AUTH}.new\"; "
            f"grep -q -F '{new_blob}' \"{AUTH}.new\" && "
            f'chmod 600 "{AUTH}.new" && mv "{AUTH}.new" "{AUTH}"')


# ─── helpers ──────────────────────────────────────────────────────────────
def load(path):
    try:
        return paramiko.PKey.from_path(path)
    except FileNotFoundError:
        sys.exit(f"  key file not found: {path}")
    except paramiko.PasswordRequiredException:
        sys.exit(f"  {path} has a passphrase. Create the AWS key pair without one.")
    except Exception as e:
        sys.exit(f"  cannot read {path} as a private key: {e}")


def connect(pkey):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(cfg.EC2_HOST, username=cfg.EC2_USER, pkey=pkey, timeout=15,
              look_for_keys=False, allow_agent=False)
    return c


def connect_or_exit(pkey, which):
    try:
        return connect(pkey)
    except paramiko.AuthenticationException:
        sys.exit(f"  the server REFUSED the {which} key. Nothing was changed.")
    except Exception as e:
        sys.exit(f"  cannot reach {cfg.EC2_HOST} ({e}).\n"
                 f"  Is the EC2 running? Is its public IP still {cfg.EC2_HOST}?\n"
                 f"  If the IP changed:  setx GHOSTNET_EC2_HOST <new ip>  and open a new terminal.")


def run(c, cmd):
    _, out, err = c.exec_command(cmd, timeout=30)
    code = out.channel.recv_exit_status()
    return code, out.read().decode(), err.read().decode()


def works(pkey):
    """'ok', 'refused', or 'error: ...' for a login using ONLY this key."""
    try:
        c = connect(pkey)
    except paramiko.AuthenticationException:
        return "refused"
    except Exception as e:
        return f"error: {e}"
    try:
        return "ok" if run(c, "whoami")[1].strip() == cfg.EC2_USER else "error: unexpected user"
    finally:
        c.close()


def header(**keys):
    print(f"  server   {cfg.EC2_USER}@{cfg.EC2_HOST}")
    for label, (path, k) in keys.items():
        print(f"  {label:<8} {path}\n           {k.fingerprint}")


# ─── phases ───────────────────────────────────────────────────────────────
def add(new_path):
    new_path = os.path.abspath(new_path)
    cur, new = load(cfg.KEY_PATH), load(new_path)
    header(current=(cfg.KEY_PATH, cur), new=(new_path, new))
    if cur.get_base64() == new.get_base64():
        sys.exit("  the new key is the same as the current key. Nothing to do.")

    c = connect_or_exit(cur, "current")
    try:
        _, keys, _ = run(c, f'cat "{AUTH}"')
        if new.get_base64() in keys:
            print("  the server already trusts the new key")
        else:
            line = f"{new.get_name()} {new.get_base64()} ghostnet-{time.strftime('%Y-%m-%d')}"
            code, _, err = run(c, add_cmd(line))
            if code:
                sys.exit(f"  could not add the new key: {err.strip()}")
            print("  added the new key to the server's trusted list (backup: authorized_keys.bak)")
    finally:
        c.close()

    result = works(new)
    if result != "ok":
        sys.exit(f"  TEST FAILED: login with the new key alone -> {result}\n"
                 f"  The old key still works, so you are not locked out. Tell Claude the message.")
    print("  TEST PASSED: the new key logs in on its own.\n")
    print("  NEXT, one line at a time:")
    print(f'    setx GHOSTNET_KEY_PATH "{new_path}"')
    print("    (close this terminal, open a new one)")
    print(f'    python rotate_ssh_key.py --remove-old "{cfg.KEY_PATH}"')


def remove_old(old_path):
    old_path = os.path.abspath(old_path)
    new, old = load(cfg.KEY_PATH), load(old_path)
    header(new=(cfg.KEY_PATH, new), old=(old_path, old))
    if new.get_base64() == old.get_base64():
        sys.exit("  GHOSTNET_KEY_PATH still points at the OLD key.\n"
                 "  Run the setx line from phase 1, open a NEW terminal, then run this again.")
    if works(new) != "ok":
        sys.exit("  the new key cannot log in, so NOTHING was removed. Run phase 1 first.")

    c = connect_or_exit(new, "new")        # stays open until everything is proven
    try:
        ob, nb = old.get_base64(), new.get_base64()
        _, keys, _ = run(c, f'cat "{AUTH}"')
        if ob not in keys:
            print("  the server does not list the old key (already removed)")
        else:
            code, _, err = run(c, remove_cmd(ob, nb))
            if code:
                run(c, f'rm -f "{AUTH}.new"')
                sys.exit(f"  removal stopped by a safety check, nothing changed. {err.strip()}")
            print("  removed the old key from the trusted list (backup: authorized_keys.bak2)")

        new_state, old_state = works(new), works(old)
        if new_state != "ok":
            run(c, f'cp "{AUTH}.bak2" "{AUTH}"')
            sys.exit(f"  the new key stopped working ({new_state}). Backup RESTORED; "
                     f"the old key is trusted again. Tell Claude the message.")
    finally:
        c.close()

    print(f"  login with new key: {new_state}")
    print(f"  login with old key: {old_state}")
    if old_state == "refused":
        print("\n  DONE. The leaked key no longer opens the server.")
        print("  Tidy up:")
        print("    - AWS console > EC2 > Key Pairs: delete the old key pair")
        print("    - delete the old .pem from the project folder, Downloads and any zip copies")
        print("    - give teammates the new key privately (or add each person's own key)")
    else:
        print("\n  WARNING: could not confirm the old key is refused. Tell Claude the message.")


def check(paths):
    paths = [cfg.KEY_PATH] + [os.path.abspath(p) for p in paths]
    print(f"  server   {cfg.EC2_USER}@{cfg.EC2_HOST}")
    for p in paths:
        k = load(p)
        tag = "  (GHOSTNET_KEY_PATH)" if p == cfg.KEY_PATH else ""
        print(f"  {works(k):<8} {p}{tag}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--add", metavar="NEW.pem")
    g.add_argument("--remove-old", metavar="OLD.pem")
    g.add_argument("--check", nargs="*", metavar="KEY.pem")
    a = ap.parse_args()
    if a.add:
        add(a.add)
    elif a.remove_old:
        remove_old(a.remove_old)
    else:
        check(a.check)

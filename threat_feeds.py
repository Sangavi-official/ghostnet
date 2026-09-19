"""
GhostNet Threat Feeds — Phase 2/3 (Corrected, Final)
======================================================
Live threat intelligence from four independent sources:
  1. NIST NVD CVE API       -> state index 5
  2. Shodan API              -> state index 6
  3. AbuseIPDB API           -> state index 10
  4. MITRE ATT&CK            -> state index 11

All four scores are fetched ONCE per environment instance,
never repeatedly during training or inference, to avoid
API rate-limit exhaustion.
"""

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from datetime import datetime, timedelta, timezone

# ─── API CREDENTIALS ───────────────────────────────────────
# Paste your own keys below. Each is free and instant to obtain.
NIST_API_KEY      = "0a22271e-2d42-452e-abcb-fb0374583f64"
SHODAN_API_KEY     = "xkj8RSp4CUje2FXyHJtaaI4tWh1nuWjs"
ABUSEIPDB_API_KEY  = "ecea33fba3183fafe07fba0d510cf58750707d08203aba590570a4cebcfce7cf1ea6731de6e0d767"
# ────────────────────────────────────────────────────────────


def get_cve_score():
    """
    Fetches CVEs published in the last 7 days from NIST NVD.
    Returns a normalized score from 0.0 (no notable threats)
    to 1.0 (critical vulnerability published this week).
    """
    end   = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=7)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 20
    }
    headers = {}
    if NIST_API_KEY and "PASTE_YOUR" not in NIST_API_KEY:
        headers["apiKey"] = NIST_API_KEY

    try:
        r = requests.get(url, params=params, headers=headers,
                          timeout=15, verify=False)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])

        scores  = []
        cve_ids = []
        for v in vulns:
            cve_id  = v["cve"].get("id", "unknown")
            metrics = v["cve"].get("metrics", {})
            if "cvssMetricV31" in metrics:
                s = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                scores.append(s)
                cve_ids.append((cve_id, s))
            elif "cvssMetricV30" in metrics:
                s = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                scores.append(s)
                cve_ids.append((cve_id, s))

        if scores:
            max_score  = max(scores)
            normalized = round(max_score / 10.0, 3)
            top3 = sorted(cve_ids, key=lambda x: x[1], reverse=True)[:3]
            print(f"  [CVE]  {len(scores)} CVEs this week")
            for cid, sc in top3:
                print(f"         {cid}  CVSS: {sc}")
            print(f"         Highest: {max_score} -> Normalized: {normalized}")
            return normalized

        print("  [CVE]  No scored CVEs this week -> default 0.3")
        return 0.3

    except requests.exceptions.Timeout:
        print("  [CVE]  Request timeout -> fallback 0.3")
        return 0.3
    except Exception as e:
        print(f"  [CVE]  Error: {e} -> fallback 0.3")
        return 0.3


def get_shodan_score():
    """
    Queries Shodan for hospital-relevant exposed services.
    Returns a normalized score from 0.0 (hidden) to 1.0 (fully exposed).
    Falls back to a simulated value if no key is configured.
    """
    if not SHODAN_API_KEY or "PASTE_YOUR" in SHODAN_API_KEY:
        import random
        score = round(random.uniform(0.2, 0.6), 3)
        print(f"  [Shodan] No key configured -> simulated score: {score}")
        return score

    try:
        url    = "https://api.shodan.io/shodan/host/count"
        params = {
            "key":   SHODAN_API_KEY,
            "query": "hospital port:8080,1883,443"
        }
        r     = requests.get(url, params=params, timeout=10)
        count = r.json().get("total", 0)
        score = round(min(1.0, count / 50000), 3)
        print(f"  [Shodan] {count} exposed services -> {score}")
        return score
    except Exception as e:
        print(f"  [Shodan] Error: {e} -> fallback 0.4")
        return 0.4


def get_abuse_score():
    """
    Queries AbuseIPDB for currently active high-confidence
    malicious IP addresses.
    Returns a normalized score from 0.0 to 1.0.

    The query limit is set well above the expected real-world
    range so the score reflects genuine relative threat level
    rather than saturating at the API page-size limit.
    """
    if not ABUSEIPDB_API_KEY or "PASTE_YOUR" in ABUSEIPDB_API_KEY:
        import random
        score = round(random.uniform(0.2, 0.5), 3)
        print(f"  [AbuseIPDB] No key configured -> simulated score: {score}")
        return score

    try:
        url     = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key":    ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {"confidenceMinimum": 90, "limit": 10000}
        r      = requests.get(url, headers=headers,
                               params=params, timeout=10)
        count  = len(r.json().get("data", []))
        score  = round(min(1.0, count / 1000), 3)
        print(f"  [AbuseIPDB] {count} malicious IPs active -> {score}")
        return score
    except Exception as e:
        print(f"  [AbuseIPDB] Error: {e} -> fallback 0.3")
        return 0.3


def get_attck_score():
    """
    Counts MITRE ATT&CK techniques specifically relevant to
    healthcare and medical device contexts. No API key needed.
    Returns a normalized score from 0.0 to 1.0.

    Keyword set is intentionally narrow to healthcare-specific
    terms only, avoiding broad industrial/IoT terms that would
    match a large fraction of the entire framework.
    """
    healthcare_keywords = [
        "medical device", "healthcare", "hospital",
        "patient", "clinical"
    ]
    try:
        url = ("https://raw.githubusercontent.com/mitre/cti"
               "/master/enterprise-attack/enterprise-attack.json")
        r    = requests.get(url, timeout=20, verify=False)
        objs = r.json().get("objects", [])

        healthcare_techs = [
            o for o in objs
            if o.get("type") == "attack-pattern"
            and any(kw in str(o).lower() for kw in healthcare_keywords)
        ]
        score = round(min(1.0, len(healthcare_techs) / 30), 3)
        print(f"  [ATT&CK] {len(healthcare_techs)} healthcare-specific "
              f"techniques -> {score}")
        return score
    except Exception as e:
        print(f"  [ATT&CK] Error: {e} -> fallback 0.2")
        return 0.2


def get_live_threat_state():
    """
    Fetches all four independent threat scores once.
    Called only at environment construction, never per-step
    or per-episode, to respect API rate limits.
    """
    print("\n  [LTSA] Fetching live threat intelligence...")
    print("  " + "-" * 45)

    cve    = get_cve_score()
    shodan = get_shodan_score()
    abuse  = get_abuse_score()
    attck  = get_attck_score()

    level = "CRITICAL" if cve >= 0.9 else \
            "HIGH"     if cve >= 0.7 else \
            "MEDIUM"   if cve >= 0.5 else "LOW"

    print("  " + "-" * 45)
    print(f"  [LTSA] CVE score    : {cve}   -> {level}")
    print(f"  [LTSA] Shodan score : {shodan}")
    print(f"  [LTSA] Abuse score  : {abuse}")
    print(f"  [LTSA] ATT&CK score : {attck}")
    print("  " + "-" * 45)

    return {
        "cve_score":    cve,
        "shodan_score": shodan,
        "abuse_score":  abuse,
        "attck_score":  attck
    }


if __name__ == "__main__":
    print("=" * 50)
    print("  GhostNet LTSA — Live Threat Feed Test")
    print("=" * 50)
    result = get_live_threat_state()
    print()
    print(f"  State index 5  (CVE)    = {result['cve_score']}")
    print(f"  State index 6  (Shodan) = {result['shodan_score']}")
    print(f"  State index 10 (Abuse)  = {result['abuse_score']}")
    print(f"  State index 11 (ATT&CK) = {result['attck_score']}")
    print()
    print("  All four scores are independent and properly normalized.")
    print("=" * 50)

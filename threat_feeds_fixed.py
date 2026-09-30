"""
threat_feeds_fixed.py — corrected threat-feed normalisation
============================================================
This file CORRECTS two defects reported in the paper. It is supplied
alongside the original threat_feeds.py and is NOT used by the reported
results: the evaluation in the paper was produced with the original
normalisation, and re-training under the corrected feeds is future work.
Keeping both files makes the reported results reproducible.

DEFECT 1 — Shodan: constant near zero
    original:  score = min(1.0, count / 50000)
    Observed counts are 150-200, so the score is 0.003-0.004 every run.
    The denominator is two orders of magnitude above the realistic range,
    so the dimension carries no information.
    corrected: logarithmic scaling over the plausible range, so a change
    of one order of magnitude moves the score by roughly 0.25.

DEFECT 2 — AbuseIPDB: saturated at 1.0
    original:  count = len(data);  score = min(1.0, count / 1000)
    The API returns up to `limit` (10000) records, and the divisor is
    1000, so any full page yields 10 -> clamped to exactly 1.0 forever.
    The record COUNT is a property of the requested page size, not of
    the threat environment.
    corrected: score from the CONFIDENCE DISTRIBUTION of the returned
    records (share at maximum confidence), which varies day to day and
    does describe the threat environment.

DEFECT 3 — errors indistinguishable from "no threat"
    Neither function checked the HTTP status, so a rejected request
    (quota exhausted, bad key) returned an empty list and was reported
    as a score of 0.0 — a quiet failure that looks like good news.
    corrected: status is checked, and failures return the documented
    fallback together with an explicit status flag.
"""

import math

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from datetime import datetime, timedelta, timezone

from threat_feeds import (NIST_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY,
                          get_cve_score, get_attck_score)

SHODAN_REF = 10000.0     # upper reference for log scaling
FALLBACK = {"shodan": 0.4, "abuse": 0.3}


def get_shodan_score_fixed():
    """
    Exposed hospital-relevant services, log-scaled.

        score = log10(1 + count) / log10(1 + SHODAN_REF)

    count=10 -> 0.26,  count=190 -> 0.57,  count=2000 -> 0.83
    Returns (score, raw_detail_dict).
    """
    raw = {"count": None, "status": "not_attempted"}
    if not SHODAN_API_KEY or "PASTE_YOUR" in SHODAN_API_KEY:
        raw["status"] = "no_key"
        return FALLBACK["shodan"], raw
    try:
        r = requests.get("https://api.shodan.io/shodan/host/count",
                         params={"key": SHODAN_API_KEY,
                                 "query": "hospital port:8080,1883,443"},
                         timeout=10)
        if r.status_code != 200:
            raw["status"] = f"http_{r.status_code}"
            print(f"  [Shodan] request failed ({r.status_code}) -> fallback")
            return FALLBACK["shodan"], raw
        count = int(r.json().get("total", 0))
        score = round(min(1.0, math.log10(1 + count) / math.log10(1 + SHODAN_REF)), 3)
        raw.update({"count": count, "status": "ok"})
        print(f"  [Shodan] {count} exposed services -> {score}  (log-scaled)")
        return score, raw
    except Exception as e:
        raw["status"] = f"error:{type(e).__name__}"
        print(f"  [Shodan] {e} -> fallback")
        return FALLBACK["shodan"], raw


def get_abuse_score_fixed(limit=10000):
    """
    Share of blacklisted addresses reported at maximum confidence.

        score = (records with abuseConfidenceScore == 100) / records

    This is independent of the requested page size, so it no longer
    saturates. Returns (score, raw_detail_dict).
    """
    raw = {"records": None, "at_max_confidence": None, "status": "not_attempted"}
    if not ABUSEIPDB_API_KEY or "PASTE_YOUR" in ABUSEIPDB_API_KEY:
        raw["status"] = "no_key"
        return FALLBACK["abuse"], raw
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/blacklist",
                         headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                         params={"confidenceMinimum": 90, "limit": limit}, timeout=10)
        if r.status_code != 200:
            raw["status"] = f"http_{r.status_code}"
            note = " (daily quota exhausted)" if r.status_code == 429 else ""
            print(f"  [AbuseIPDB] request failed ({r.status_code}){note} -> fallback")
            return FALLBACK["abuse"], raw
        data = r.json().get("data", [])
        if not data:
            raw.update({"records": 0, "status": "empty"})
            print("  [AbuseIPDB] no records returned -> fallback")
            return FALLBACK["abuse"], raw
        top = sum(1 for d in data if int(d.get("abuseConfidenceScore", 0)) >= 100)
        score = round(top / len(data), 3)
        raw.update({"records": len(data), "at_max_confidence": top, "status": "ok"})
        print(f"  [AbuseIPDB] {top}/{len(data)} at max confidence -> {score}")
        return score, raw
    except Exception as e:
        raw["status"] = f"error:{type(e).__name__}"
        print(f"  [AbuseIPDB] {e} -> fallback")
        return FALLBACK["abuse"], raw


def get_live_threat_state_fixed():
    """Same four scores as the original, with corrected Shodan and
       AbuseIPDB normalisation and explicit per-feed status."""
    print("\n  [LTSA] Fetching live threat intelligence (corrected)...")
    cve = get_cve_score()
    shodan, shodan_raw = get_shodan_score_fixed()
    abuse, abuse_raw = get_abuse_score_fixed()
    attck = get_attck_score()
    return {"cve_score": cve, "shodan_score": shodan,
            "abuse_score": abuse, "attck_score": attck,
            "raw": {"shodan": shodan_raw, "abuse": abuse_raw}}


if __name__ == "__main__":
    print("=" * 62)
    print("  Corrected normalisation — response curves")
    print("=" * 62)
    print("  Shodan: exposed services -> score")
    for c in (10, 50, 150, 190, 600, 2000, 10000):
        old = round(min(1.0, c / 50000), 3)
        new = round(min(1.0, math.log10(1 + c) / math.log10(1 + SHODAN_REF)), 3)
        print(f"    {c:>6} services   original {old:<6}  corrected {new}")
    print("\n  AbuseIPDB: records returned -> score (original)")
    for c in (500, 2000, 5000, 10000):
        print(f"    {c:>6} records    original {round(min(1.0, c/1000), 3)}")
    print("    corrected score depends on the confidence distribution, "
          "not the page size")
    print("\n  Live check (needs network + keys):")
    print("   ", get_live_threat_state_fixed())

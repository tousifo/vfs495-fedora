#!/usr/bin/env python3
"""Reproducible intermittent-verify diagnosis for the VFS495 bridge (no root needed).

Runs N fprintd-verify rounds while watching the D-Bus device state and the system
journal, then correlates each delivered scan (dimensions, capture time) with the
matcher's score batch. Prints a table + a verdict for each attempt and appends a
CSV summary under /tmp/opencode (scores + dimensions only — no biometric images).

Usage (as the enrolled ordinary user):
    python3 tools/vfs495_diag_session.py [N] [--finger right-index-finger]

NOTE: for each attempt, wait ~2 s for the sensor to arm after the prompt, then
swipe the SAME enrolled finger slowly, full length, one steady motion.
"""
import csv
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

LOCAL_TZ = datetime.now().astimezone().tzinfo
FP_DEVICE_IFACE = "net.reactivated.Fprint.Device"

def now_micro():
    return datetime.now(LOCAL_TZ)

def journal(since, unit):
    out = subprocess.run(["journalctl", "-u", unit, "--since=" + since, "-O", "short-iso"],
                         capture_output=True, text=True, check=False).stdout
    return out

def highest_since(since):
    f = journal(since, "fprintd.service")
    scores = [(int(a), int(b)) for a, b in re.findall(r"score (\d+)/(\d+)", f)]
    br = journal(since, "vfs495-bridge.service")
    dims = [(int(x), int(y)) for x, y in re.findall(r"delivered scan (\d+)x(\d+)", br)]
    msgs = [m for m in re.findall(r"\[vfs495-bridge\] (.*)", br)]
    return scores, dims, msgs

def fmt_iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 10
    finger = sys.argv[sys.argv.index("--finger") + 1] if "--finger" in sys.argv else "right-index-finger"
    rows = []
    print(__doc__)
    for i in range(1, n + 1):
        t0 = now_micro()
        since = fmt_iso(t0)
        print(f"\n[{i}/{n}] starting verify at {since} — WAIT ~2 s, then SWIPE SLOW, FULL LENGTH")
        p = subprocess.run(["fprintd-verify", "-f", finger], capture_output=True, text=True)
        scores, dims, msgs = highest_since(since)
        # take the last delivered scan and the score batch tied to it
        got = dims[-1] if dims else ("-", "-")
        maxsc = max((s for s, t in scores), default=None)
        ok = maxsc is not None and maxsc >= 40
        rows.append({"time": fmt_iso(t0),
                     "delivered_w": got[0], "delivered_h": got[1],
                     "scores": ";".join(str(s) + "/" + str(t) for s, t in scores),
                     "max_score": maxsc if maxsc is not None else -1,
                     "verdict": ("MATCH" if ok else ("NO-MATCH" if scores else "NO-SCAN-DELIVERED")),
                     "cli_rc": p.returncode,
                     "bridge_msgs": " | ".join(msgs)})
        print(f"    delivered: {got[0]}x{got[1]}   scores: {rows[-1]['scores'] or '(none logged)'}   -> {rows[-1]['verdict']}")
        if p.returncode != 0:
            print(f"    fprintd-verify rc={p.returncode}: {p.stderr.strip()[:200]}")
        time.sleep(1.5)
    outcsv = "/tmp/opencode/vfs495_diag_sessions.csv"
    with open(outcsv, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        for r in rows:
            w.writerow(r)
    good = [r for r in rows if r["verdict"] == "MATCH"]
    print(f"\n==== summary: {len(good)}/{len(rows)} matches. CSV appended: {outcsv}")
    hs = sorted(set(r["delivered_h"] for r in rows if r["delivered_h"] != "-"))
    ms = max((r["max_score"] for r in rows), default=0)
    print(f"delivered heights seen: {hs}   best score: {ms}/40")

if __name__ == "__main__":
    main()

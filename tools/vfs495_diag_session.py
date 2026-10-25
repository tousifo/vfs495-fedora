#!/usr/bin/env python3
"""Live intermittent-verify diagnosis for the VFS495 bridge (ordinary user, no root).

For each requested finger it runs N fprintd-verify rounds, streaming live prompts
from fprintd-verify and "swipe now / delivered scan" from both systemd units.
After each round it correlates the last delivered scan (dimensions, capture time)
with the matcher's score batch. Appends a score+dimension CSV (no image data).

Usage:
    python3 tools/vfs495_diag_session.py [N] [finger ...]
    N                verify rounds per finger (default 3)
    finger           enroled finger names; default = ALL enrolled fingers

Timing rule for good data: when the prompt says the sensor is armed (verify
started), WAIT ~2 s, then swipe ONE steady full-length motion of the same finger.
"""
import csv
import os
import re
import subprocess
import sys
import time
from datetime import datetime

RESULTS_CSV = "/tmp/opencode/vfs495_diag_sessions.csv"


def fmt_iso(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def now_iso():
    return fmt_iso(datetime.now())


def journal_since(since):
    """Full journal since a timestamp. NOTE: after some reboots journald's -u unit
    filter misses fprintd entries; filtering by text is reliable on this machine."""
    return subprocess.run(["journalctl", "--since=" + since, "--no-pager", "-o", "short-iso"],
                          capture_output=True, text=True, check=False).stdout


def analyze_round(since):
    j = journal_since(since)
    scores = re.findall(r"score (\d+)/(\d+)", j)
    br = "\n".join(l for l in j.splitlines() if "vfs495-bridge" in l)
    dims = re.findall(r"delivered scan (\d+)x(\d+)(?: mean=(\d+) std=(\d+) dark=([\d.]+)%"
                      r"(?: sat=([\d.]+)%)?)? after ([\d.]+)s", br)
    msgs = re.findall(r"\[vfs495-bridge\] (.*)", br)
    return scores, dims, msgs


def enrolled_fingers(dev_path="/net/reactivated/Fprint/Device/0", user=None):
    import dbus
    from dbus.mainloop import glib
    glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    o = bus.get_object("net.reactivated.Fprint", dev_path)
    user = user or os.environ.get("SUDO_USER") or __import__("getpass").getuser()
    return [str(x) for x in dbus.Interface(o, "net.reactivated.Fprint.Device")
            .ListEnrolledFingers(user)], user


def run_round(finger, round_no, total):
    print(f"\n───────── round {round_no}/{total}: {finger} ─────────")
    print("  READY: verify starting — wait ~2 s after 'swipe now', then SWIPE SLOW & FULL")
    t0 = datetime.now()
    since = fmt_iso(t0)
    p = subprocess.Popen(["fprintd-verify", "-f", finger],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    fprintd_out = []
    try:
        for line in p.stdout:
            line = line.strip()
            fprintd_out.append(line)
            print("  [verify] " + line)
    except Exception:
        pass
    p.wait()
    scores, dims, msgs = analyze_round(since)
    stats = ""
    if dims:
        g = dims[-1]
        w, h, captime = g[0], g[1], g[6]
        stats = f"mean={g[2]} std={g[3]} dark={g[4]}%" if g[2] else ""
        if g[5]:
            stats += f" sat={g[5]}%"
    else:
        w = h = captime = "-"
    maxsc = max((int(s) for s, _ in scores), default=None)
    verdict = ("MATCH" if maxsc is not None and maxsc >= 40 else
               ("NO-MATCH" if scores else "NO-SCAN-DELIVERED"))
    row = {"time": since, "finger": finger, "delivered_w": w, "delivered_h": h,
           "capture_s": captime, "image_stats": stats,
           "scores": ";".join(f"{s}/{t}" for s, t in scores),
           "max_score": maxsc if maxsc is not None else -1, "verdict": verdict,
           "verify_rc": p.returncode, "bridge_msgs": " | ".join(msgs[-4:])}
    print(f"  → DELIVERED {w}x{h} in {captime}s {stats} | scores {row['scores'] or '(none)'} | {verdict}")
    return row


def main():
    args = sys.argv[1:]
    gap = 4.0
    if "--gap" in args:
        i = args.index("--gap")
        gap = float(args[i + 1])
        del args[i:i + 2]
    n = int(args.pop(0)) if args and args[0].isdigit() else 3
    fingers = args if args else None
    if not fingers:
        fingers, user = enrolled_fingers()
        print(f"enrolled for {user}: {', '.join(fingers)}")
    rows = []
    for finger in fingers:
        for i in range(1, n + 1):
            rows.append(run_round(finger, i, n))
            time.sleep(gap)          # let the sensor settle (burst captures degrade it)
    os.makedirs(os.path.dirname(RESULTS_CSV), exist_ok=True)
    new = not os.path.exists(RESULTS_CSV)
    with open(RESULTS_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        for r in rows:
            w.writerow(r)
    print("\n════════ summary ════════")
    for finger in fingers:
        fr = [r for r in rows if r["finger"] == finger]
        match = sum(r["verdict"] == "MATCH" for r in fr)
        print(f"{finger:20} {match}/{len(fr)} matches | heights "
              f"{[r['delivered_h'] for r in fr]} | best {max(r['max_score'] for r in fr)}/40")
    print(f"CSV appended to {RESULTS_CSV}")


if __name__ == "__main__":
    main()

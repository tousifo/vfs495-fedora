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
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

RESULTS_CSV = "/tmp/opencode/vfs495_diag_sessions.csv"
ROUND_TIMEOUT = 75.0      # a round with no swipe is abandoned after this many seconds
SOUND = "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"


def notify(title, body):
    """Desktop cue so the user knows exactly when to swipe (output is only visible later)."""
    for cmd in (["notify-send", "-a", "VFS495 test", "-t", "5000", "-u", "critical", title, body],
                ["paplay", SOUND]):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def _pump(stream, q):
    try:
        for line in stream:
            q.put(line)
    finally:
        q.put(None)


def start_retry_watchdog():
    """While a round is running, surface rejected/partial swipes immediately.

    fprintd keeps the finger prompt open, so the user can simply swipe again; without
    this cue an incomplete swipe just looks like nothing happened."""
    def watch():
        j = subprocess.Popen(["journalctl", "-f", "-o", "cat", "--since", now_iso()],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        last = 0.0
        for line in j.stdout:
            if "vfs495-bridge" not in line:
                continue
            if "rejected scan" in line or "retrying capture" in line:
                if time.monotonic() - last < 2.0:
                    continue
                last = time.monotonic()
                why = "press the whole finger flat" if "partial contact" in line else "swipe again"
                notify("Swipe AGAIN", f"previous swipe not usable — {why}")
                print("  >>> SWIPE AGAIN: previous swipe was unusable", flush=True)
    threading.Thread(target=watch, daemon=True).start()


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
                      r"(?: sat=([\d.]+)%)?(?: cover=(\d+)%)?)? after ([\d.]+)s", br)
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


def run_round(finger, round_no, total, round_timeout=ROUND_TIMEOUT):
    print(f"\n───────── round {round_no}/{total}: {finger} ─────────", flush=True)
    print("  READY: waiting for fprintd to arm the sensor...", flush=True)
    notify(f"Round {round_no}/{total}", "Get your right index ready — swipe prompt follows")
    t0 = datetime.now()
    since = fmt_iso(t0)
    p = subprocess.Popen(["fprintd-verify", "-f", finger],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    q = queue.Queue()
    threading.Thread(target=_pump, args=(p.stdout, q), daemon=True).start()
    fprintd_out = []
    armed = False
    deadline = time.monotonic() + round_timeout
    timed_out = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"  [verify] TIMEOUT: no swipe within {round_timeout:.0f}s — abandoning round", flush=True)
            timed_out = True
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
            break
        try:
            line = q.get(timeout=min(remaining, 1.0))
        except queue.Empty:
            continue
        if line is None:
            break
        line = line.strip()
        fprintd_out.append(line)
        print("  [verify] " + line, flush=True)
        if not armed and "Verify started" in line:
            armed = True
            notify("SWIPE NOW", f"{finger}: wait ~3 s, then one slow full-length swipe")
            print("  >>> SWIPE NOW: wait ~3 s, then one slow full-length swipe", flush=True)
    p.wait()
    scores, dims, msgs = analyze_round(since)
    stats = ""
    if dims:
        g = dims[-1]
        w, h, captime = g[0], g[1], g[7]
        stats = f"mean={g[2]} std={g[3]} dark={g[4]}%" if g[2] else ""
        if g[5]:
            stats += f" sat={g[5]}%"
        if g[6]:
            stats += f" cover={g[6]}%"
    else:
        w = h = captime = "-"
    maxsc = max((int(s) for s, _ in scores), default=None)
    verdict = ("MATCH" if maxsc is not None and maxsc >= 40 else
               ("NO-MATCH" if scores else
                ("TIMEOUT" if timed_out else "NO-SCAN-DELIVERED")))
    row = {"time": since, "finger": finger, "delivered_w": w, "delivered_h": h,
           "capture_s": captime, "image_stats": stats,
           "scores": ";".join(f"{s}/{t}" for s, t in scores),
           "max_score": maxsc if maxsc is not None else -1, "verdict": verdict,
           "verify_rc": p.returncode, "bridge_msgs": " | ".join(msgs[-4:])}
    print(f"  → DELIVERED {w}x{h} in {captime}s {stats} | scores {row['scores'] or '(none)'} | {verdict}",
          flush=True)
    return row


def main():
    args = sys.argv[1:]
    gap = 4.0
    round_timeout = ROUND_TIMEOUT
    if "--gap" in args:
        i = args.index("--gap")
        gap = float(args[i + 1])
        del args[i:i + 2]
    if "--timeout" in args:
        i = args.index("--timeout")
        round_timeout = float(args[i + 1])
        del args[i:i + 2]
    n = int(args.pop(0)) if args and args[0].isdigit() else 3
    fingers = args if args else None
    if not fingers:
        fingers, user = enrolled_fingers()
        print(f"enrolled for {user}: {', '.join(fingers)}", flush=True)
    rows = []
    start_retry_watchdog()
    for finger in fingers:
        for i in range(1, n + 1):
            rows.append(run_round(finger, i, n, round_timeout))
            time.sleep(gap)          # let the sensor settle (burst captures degrade it)
    os.makedirs(os.path.dirname(RESULTS_CSV), exist_ok=True)
    new = not os.path.exists(RESULTS_CSV)
    with open(RESULTS_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        if new:
            w.writeheader()
        for r in rows:
            w.writerow(r)
    print("\n════════ summary ════════", flush=True)
    for finger in fingers:
        fr = [r for r in rows if r["finger"] == finger]
        match = sum(r["verdict"] == "MATCH" for r in fr)
        print(f"{finger:20} {match}/{len(fr)} matches | heights "
              f"{[r['delivered_h'] for r in fr]} | best {max(r['max_score'] for r in fr)}/40",
              flush=True)
    print(f"CSV appended to {RESULTS_CSV}", flush=True)


if __name__ == "__main__":
    main()

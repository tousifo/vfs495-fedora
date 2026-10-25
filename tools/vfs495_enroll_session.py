#!/usr/bin/env python3
"""Guided enrollment for the VFS495 bridge (ordinary user, no root).

The bridge prints "swipe now" / "rejected scan" / "delivered scan" to the journal as
fprintd asks for each stage. This helper turns those lines into desktop notifications
(plus a sound), because fprintd-enroll's own prompts are only visible afterwards.

Usage:
    python3 tools/vfs495_enroll_session.py [finger] [username]

Run it with the bridge's VFS495_MIN_COVER raised (e.g. 65) so low-contact swipes are
rejected during enrollment and the stored template is built from clean frames.
"""
import os
import re
import subprocess
import sys
import threading
import time

SOUND = "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"


def notify(title, body):
    for cmd in (["notify-send", "-a", "VFS495 enrollment", "-t", "5000", "-u", "critical", title, body],
                ["paplay", SOUND]):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def main():
    args = sys.argv[1:]
    finger = args[0] if args else "right-index-finger"
    user = args[1] if len(args) > 1 else os.environ.get("USER", "")
    cmd = ["fprintd-enroll", "-f", finger]
    if user:
        cmd.append(user)

    j = subprocess.Popen(["journalctl", "-f", "-o", "cat", "--since", time.strftime("%Y-%m-%d %H:%M:%S")],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    stop = threading.Event()

    def watch_journal():
        for line in j.stdout:
            if stop.is_set():
                break
            if "vfs495-bridge" not in line:
                continue
            if "finger needed" in line:
                notify("SWIPE NOW", f"{finger}: whole pad flat, slow full swipe")
            elif "rejected scan" in line:
                m = re.search(r"rejected scan (\d+x\d+): (.*)", line)
                notify("Swipe again", (m.group(2) if m else "incomplete contact")[:120])
            elif "retrying capture" in line:
                notify("Swipe again", "the previous swipe was not usable")
            elif "delivered scan" in line:
                notify("Captured", "lift your finger for the next stage")

    threading.Thread(target=watch_journal, daemon=True).start()

    print(f"enrolling {finger} for {user or 'current user'} — follow the notifications", flush=True)
    notify("Enrollment starting", f"{finger}: 5 clean swipes needed")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    done = 0
    for line in p.stdout:
        line = line.rstrip()
        print("  [enroll] " + line, flush=True)
        if "enroll-stage-passed" in line:
            done += 1
        if "enroll-completed" in line:
            notify("Enrollment complete", f"{finger}: {done} stages captured")
        elif "enroll-fail" in line or "enroll-retry" in line:
            notify("Stage not accepted", "swipe again with full contact")
    p.wait()
    stop.set()
    j.terminate()
    ok = p.returncode == 0
    print(("enrollment finished OK" if ok else f"enrollment FAILED (rc={p.returncode})"), flush=True)
    notify("Enrollment finished" if ok else "Enrollment failed",
           f"{finger}: {done} stages" if ok else "template may be unchanged; check output")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

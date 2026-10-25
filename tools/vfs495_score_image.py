#!/usr/bin/env python3
"""Offline bozorth3 scorer for VFS495 scans (no root, no sensor, no swipes).

Feeds archived PGM captures to libfprint's `virtual_image` driver on a private
socket and reports the same bozorth3 score fprintd computes, using a copy of the
enrolled print file. One print is verified; two or more comma-separated prints are
identified against exactly like fprintd does for `VerifyStart("any")`.

Usage:
    python3 tools/vfs495_score_image.py PRINT_FILE[,PRINT_FILE2] IMAGE.pgm [IMAGE.pgm ...]

Environment:
    VFS495_SCORE_SOCK   private unix socket path (default /tmp/vfs495-score.sock)

The enrolled print lives in /var/lib/fprint/<user>/<driver>/<device>/<finger> and is
root-only; copy it out once (see docs/FINDINGS.md) and score against the copy.
"""
import contextlib
import os
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

SOCK = os.environ.get("VFS495_SCORE_SOCK", "/tmp/vfs495-score.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK
os.environ.setdefault("FP_VIRTUAL_IMAGE_HOT_SECONDS", "-1")
os.environ["G_MESSAGES_DEBUG"] = "all"   # GLib caches this on first log; set before import

import gi  # noqa: E402

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint  # noqa: E402


@contextlib.contextmanager
def captured_output():
    """Capture stdout+stderr (libfprint logs DEBUG, including the score, to stdout)."""
    r, w = os.pipe()
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    lines = []

    def reader():
        with os.fdopen(r, "rb") as fh:
            for line in fh:
                lines.append(line.decode(errors="replace"))

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(w, 1)
    os.dup2(w, 2)
    os.close(w)
    try:
        yield lines
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)
        th.join(timeout=2)


def read_pgm(path):
    b = Path(path).read_bytes()
    toks = b.split(maxsplit=4)
    assert toks[0] == b"P5", f"{path}: not a binary PGM"
    w, h = int(toks[1]), int(toks[2])
    return w, h, toks[4][: w * h]


def send_image(w, h, data):
    for _ in range(100):
        if os.path.exists(SOCK):
            break
        time.sleep(0.05)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data)
    s.close()


def match_one(dev, prints, pgm):
    w, h, data = read_pgm(pgm)
    result = {}

    def run():
        try:
            if len(prints) == 1:
                result["res"] = dev.verify_sync(prints[0], None)
            else:
                result["res"] = dev.identify_sync(prints, None)
        except Exception as e:  # noqa: BLE001
            result["error"] = e

    with captured_output() as lines:
        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.4)
        send_image(w, h, data)
        t.join(timeout=30)

    if "error" in result:
        return f"ERROR {result['error']}"

    found = re.findall(r"score (\d+)/(\d+)", "".join(lines))
    scores = [int(s) for s, _ in found]
    thr = found[0][1] if found else "?"
    best = max(scores) if scores else "?"
    detail = ";".join(f"{s}/{thr}" for s in scores) or "?"

    res = result.get("res")
    if len(prints) == 1:
        matched = bool(res[0]) if isinstance(res, tuple) else bool(res)
        extra = ""
    else:
        match, _probe = res
        matched = match is not None
        extra = f" finger={match.get_finger()}" if match else ""

    return (f"{'MATCH' if matched else 'no-match':8} best={best:>3}/{thr:<3} "
            f"all={detail}{extra}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    print_files, images = sys.argv[1].split(","), sys.argv[2:]
    prints = []
    for f in print_files:
        prints.append(FPrint.Print.deserialize(Path(f).read_bytes()))
    for f, p in zip(print_files, prints):
        print(f"print: {f} finger={p.get_finger()} user={p.get_username()} "
              f"driver={p.get_driver()} device={p.get_device_id()!r} "
              f"desc={p.get_description()}")

    with captured_output():
        devs = FPrint.Context().get_devices()
        dev = devs[0] if devs else None
        if dev:
            dev.open_sync(None)
    if not dev:
        print("no devices (is FP_VIRTUAL_IMAGE honoured?)")
        return 1
    print(f"device: {dev.get_name()} driver={dev.get_driver()}")

    for pgm in images:
        print(f"{Path(pgm).name:44} {match_one(dev, prints, pgm)}", flush=True)

    with captured_output():
        dev.close_sync(None)
    return 0


if __name__ == "__main__":
    sys.exit(main())

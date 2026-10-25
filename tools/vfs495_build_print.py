#!/usr/bin/env python3
"""Build an extra NBIS print template from archived scans (no root, no sensor).

libfprint's image devices store 5 sub-templates per enrolled print (one per
enrollment stage) and the matcher tries each until one scores >= 40. Extra
sub-templates therefore translate directly into extra chances for a borderline
swipe -- but fprintd 1.94 refuses a second enrollment of a finger it can already
identify (`enroll-duplicate`).

This tool builds a print the same way enrollment does, but offline: it runs the
`virtual_image` driver in ENROLL mode on a private socket and feeds it archived
PGM captures. The result is serialized in the normal print format and can be
installed as a *second gallery print* (see docs/FINDINGS.md).

Only use scans of the SAME finger that is being strengthened.

Usage:
    VFS495_PRINT_FINGER=RIGHT_MIDDLE VFS495_PRINT_USER=$USER \\
        python3 tools/vfs495_build_print.py OUT.print IMAGE.pgm [IMAGE.pgm ...]

Environment:
    VFS495_PRINT_FINGER  FpFinger name to record, e.g. RIGHT_MIDDLE (must match the
                         file name fprintd expects: right-middle-finger -> 8)
    VFS495_PRINT_USER    username to record (must match fprintd's print owner)
    VFS495_PRINT_DESC    free-form description stored in the print
    VFS495_ENROLL_SOCK   private unix socket path (default /tmp/vfs495-enroll.sock)

Good source scans are ones that already scored high against the existing print
(see tools/vfs495_score_image.py); 5 are enough (the driver's stage count).
"""
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

SOCK = os.environ.get("VFS495_ENROLL_SOCK", "/tmp/vfs495-enroll.sock")
os.environ["FP_VIRTUAL_IMAGE"] = SOCK
os.environ.setdefault("FP_VIRTUAL_IMAGE_HOT_SECONDS", "-1")

import gi  # noqa: E402

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint  # noqa: E402


def read_pgm(path):
    b = Path(path).read_bytes()
    toks = b.split(maxsplit=4)
    assert toks[0] == b"P5", f"{path}: not a binary PGM"
    w, h = int(toks[1]), int(toks[2])
    return w, h, toks[4][: w * h]


def send_image(w, h, data):
    for _ in range(200):
        if os.path.exists(SOCK):
            break
        time.sleep(0.05)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data)
    s.close()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2

    out = Path(sys.argv[1])
    images = sys.argv[2:]
    dev = FPrint.Context().get_devices()[0]
    dev.open_sync(None)
    stages = dev.get_nr_enroll_stages()
    print(f"device={dev.get_name()} stages={stages} images={len(images)}", flush=True)

    tpl = FPrint.Print.new(dev)
    state = {"stage": 0}

    def progress(device, completed, print_, *args):
        state["stage"] = completed
        print(f"  stage {completed}/{stages}", flush=True)

    result = {}

    def run():
        try:
            result["print"] = dev.enroll_sync(tpl, None, progress)
        except Exception as e:  # noqa: BLE001
            result["error"] = e

    th = threading.Thread(target=run, daemon=True)
    th.start()

    sent = 0
    while th.is_alive() and sent < 40:
        time.sleep(0.7)
        if not th.is_alive():
            break
        w, h, data = read_pgm(images[sent % len(images)])
        send_image(w, h, data)
        sent += 1
        if state["stage"] >= stages:
            break
    th.join(timeout=60)

    if "error" in result:
        print("ENROLL ERROR:", result["error"])
        return 1
    print_ = result.get("print")
    if print_ is None:
        print("no print returned")
        return 1

    finger = os.environ.get("VFS495_PRINT_FINGER")
    user = os.environ.get("VFS495_PRINT_USER")
    desc = os.environ.get("VFS495_PRINT_DESC")
    if finger:
        print_.set_finger(getattr(FPrint.Finger, finger))
    if user:
        print_.set_username(user)
    if desc:
        print_.set_description(desc)

    blob = print_.serialize()
    out.write_bytes(blob)
    print(f"print written: {out} ({len(blob)} bytes) finger={print_.get_finger()} "
          f"user={print_.get_username()} driver={print_.get_driver()} "
          f"device={print_.get_device_id()!r} images_fed={sent}")

    dev.close_sync(None)
    return 0


if __name__ == "__main__":
    sys.exit(main())

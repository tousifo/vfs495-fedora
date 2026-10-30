#!/usr/bin/env python3
"""Capture a fingerprint using the TOOL's OWN motion-compensated assembly (IRreconstructImage),
harvested via gdb from IRqualityDetermination. Produces a match-quality image (ridges dark).
Usage: sudo python3 vfs495_capture_asm.py out.pgm

Exit codes (the bridge acts on these):
   0  image written
  10  no assembled image (no/partial swipe)
  11  capture failed/timeout, sensor session cleaned up normally
  12  a SIGKILL was needed to stop gdb/the vendor tool -> sensor may need re-enumeration
  13  cancelled by SIGTERM, sensor session cleaned up normally

Shutdown is deliberately polite: SIGTERM first, wait, and SIGKILL only as a last resort.
Hard-killing the vendor tool mid-session can leave the sensor waiting for a USB transfer
that never completes (the "stuck until power-off" state).
"""
import json, os, signal, struct, subprocess, sys, tempfile, time
import numpy as np

RE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME = RE + "/runtime"
VENDOR = RUNTIME + "/bin/validity-sensor-unlocked"
HARVEST = RUNTIME + "/harvest_assembled.py"
EXIT_OK, EXIT_NO_IMAGE, EXIT_ERROR, EXIT_FORCED, EXIT_CANCELLED = 0, 10, 11, 12, 13
GRACE = 2.0                     # seconds a polite SIGTERM gets before we escalate
_proc = None                    # gdb, set once it is running (needed by the SIGTERM handler)


def _cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def _exe(pid):
    try:
        return os.path.basename(os.readlink("/proc/%d/exe" % pid))
    except OSError:
        return ""


def session_pids():
    """Our gdb/vendor processes, matched by executable (NOT by cmdline substring: a shell
    whose script text merely mentions the binary must never be killed).
    Scanning /proc also finds orphans left after a hard kill."""
    me, found = os.getpid(), []
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == me:
            continue
        exe = _exe(pid)
        if exe == "validity-sensor-unlocked":
            found.append(pid)
        elif exe.startswith("gdb") and HARVEST in _cmdline(pid):
            found.append(pid)
    return found


def _wait_gone(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not session_pids():
            return True
        time.sleep(0.05)
    return not session_pids()


def reap_session(grace=GRACE):
    """Stop leftover gdb/vendor processes politely. Returns True if SIGKILL was needed."""
    if _wait_gone(0):
        return False
    for pid in session_pids():
        try: os.kill(pid, signal.SIGTERM)
        except OSError: pass
    if _wait_gone(grace):
        return False
    for pid in session_pids():
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
    _wait_gone(1.0)
    return True


def _signal_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)          # gdb runs with start_new_session=True
    except OSError:
        try: os.kill(proc.pid, sig)
        except OSError: pass


def stop_gdb(proc, grace=GRACE):
    """Stop gdb + its inferior; SIGTERM first, SIGKILL only if they ignore it."""
    forced = False
    if proc is not None and proc.poll() is None:
        _signal_group(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            forced = True
            _signal_group(proc, signal.SIGKILL)
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
    if reap_session(grace):
        forced = True
    return forced


def _on_sigterm(signum, frame):
    """Turn SIGTERM into an orderly unwind through main()'s cleanup path."""
    raise SystemExit(EXIT_CANCELLED)


def _watch_assembly(proc, asm, timeout):
    """Run proc to completion while following the harvest file.

    The gdb breakpoint rewrites the file on every assembled-frame callback, so its
    mtime marks first finger contact, swipe progress, and the moment the tool stops
    producing frames. The teardown tail (tool deinit + gdb quit) cannot be skipped:
    the vendor tool must deinit the sensor itself or the reader wedges.
    Returns (rc, phase); rc is None on timeout. Phase values are seconds since spawn.
    """
    t0 = time.monotonic()
    phase = {"first_frame_s": None, "last_frame_s": None, "gdb_exit_s": None}
    prev = object()
    while True:
        rc = proc.poll()
        try:
            st = os.stat(asm)
            if st.st_size >= 8 and st.st_mtime != prev:
                now = time.monotonic() - t0
                if phase["first_frame_s"] is None:
                    phase["first_frame_s"] = now
                phase["last_frame_s"] = now
                prev = st.st_mtime
        except OSError:
            pass
        if rc is not None:
            phase["gdb_exit_s"] = time.monotonic() - t0
            return rc, phase
        if time.monotonic() - t0 >= timeout:
            return None, phase
        time.sleep(0.05)


def _write_timing(out, phase, dims=None):
    """Persist phase timings next to the capture for the bridge to log."""
    try:
        d = dict(phase)
        if dims:
            d.update(dims)
        with open(out + ".timing", "w") as f:
            json.dump(d, f)
    except OSError:
        pass


def main():
    global _proc
    out = sys.argv[1]
    timeout = float(os.environ.get("VFS_TIMEOUT", "75"))
    signal.signal(signal.SIGTERM, _on_sigterm)

    # Never start a second vendor session on top of a stale one: that is the classic way
    # to get two processes doing -doinit on the same reader and zero frames afterwards.
    if reap_session():
        print("stale sensor session needed SIGKILL before capture", file=sys.stderr)
        return EXIT_FORCED

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        asm = tf.name
    open(asm, "wb").close()
    env = {**os.environ, "LD_LIBRARY_PATH": RUNTIME + "/lib", "VFS_ASM_OUT": asm}
    cmd = ["gdb", "-q", "-batch", "-x", RUNTIME + "/harvest_assembled.py",
           "--args", RUNTIME + "/bin/validity-sensor-unlocked", "getprintwait", "-doinit"]

    _proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    phase = {}
    try:
        rc, phase = _watch_assembly(_proc, asm, timeout)
        if rc is None:
            raise subprocess.TimeoutExpired(cmd, timeout)
    except subprocess.TimeoutExpired:
        forced = stop_gdb(_proc)
        print("capture timed out after %.0fs%s" % (timeout, " (forced kill)" if forced else ""),
              file=sys.stderr)
        _write_timing(out, phase)
        try: os.unlink(asm)
        except OSError: pass
        return EXIT_FORCED if forced else EXIT_ERROR
    except SystemExit:
        forced = stop_gdb(_proc)
        print("capture cancelled%s" % (" (forced kill)" if forced else ""), file=sys.stderr)
        _write_timing(out, phase)
        try: os.unlink(asm)
        except OSError: pass
        return EXIT_FORCED if forced else EXIT_CANCELLED
    finally:
        if _proc is not None and _proc.poll() is None:
            stop_gdb(_proc)

    # gdb exited on its own; make sure it did not leave the vendor session behind.
    if reap_session(1.0):
        print("stale sensor session cleaned after capture", file=sys.stderr)
        _write_timing(out, phase)
        try: os.unlink(asm)
        except OSError: pass
        return EXIT_FORCED

    try:
        if os.path.getsize(asm) < 16:
            print("no assembled image (no finger?)", file=sys.stderr)
            _write_timing(out, phase)
            return EXIT_NO_IMAGE
        d = open(asm, "rb").read()
    finally:
        try: os.unlink(asm)
        except OSError: pass
    w, h = struct.unpack("<II", d[:8])
    img = np.frombuffer(d[8:8 + w * h], np.uint8).reshape(h, w)
    with open(out, "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode())
        f.write(np.ascontiguousarray(img).tobytes())
    _write_timing(out, phase, {"cols": w, "rows": h})
    print(f"captured assembled {w}x{h} -> {out}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

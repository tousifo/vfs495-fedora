#!/usr/bin/env python3
"""vfs495 bridge (event-driven): stays completely idle until fprintd's device reports
finger-needed=true (a verify or enroll is waiting for a swipe), then runs ONE capture on
the real sensor and delivers the image to libfprint's virtual_image socket. When fprintd
stops needing a finger (timeout, cancel, done) a still-running capture is cancelled, so the
sensor is never held longer than an authentication actually lasts.

Speed path (pre-arm): when the screen locks the bridge starts ONE vendor session right
away, so the tool is already armed when the user swipes at the lock screen. A good scan
captured while fprintd is not asking yet is cached and handed over the instant
finger-needed arrives, which takes the tool start (~0.5 s) and the capture wait out of
the unlock. The lock source is a 1 s poll of logind's LockedHint (mutter sets it on every
lock; the system bus accepts root where user session buses refuse it), with the
PropertiesChanged signal as an instant path. Pre-arm sessions are bounded
(VFS495_PREARM_WINDOW, 45 s) and torn down politely; one pre-arm per lock period.

Sensor-health handling (post-suspend / after a hard kill):
  * cancellation is polite (SIGTERM -> the capture wrapper deinits the vendor tool itself);
  * a forced kill marks the sensor for recovery, and two degenerate frames in a row trigger
    recovery on their own;
  * recovery = unbind/bind the USB device (re-enumeration), never a SIGKILL loop. A sensor
    that is already wedged must still be recovered by a full power-off.
"""
import glob, json, os, signal, socket, struct, subprocess, sys, threading, time
import dbus, dbus.bus, dbus.mainloop.glib
from gi.repository import GLib

SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
CAPTURE = "/home/tousifo/vfs495-linux/tools/vfs495_capture_asm.py"
RUNTIME = os.path.normpath(os.path.dirname(CAPTURE) + "/../runtime")
VENDOR = RUNTIME + "/bin/validity-sensor-unlocked"
HARVEST = RUNTIME + "/harvest_assembled.py"
MIN_ROWS = 180                                # a real swipe assembles to ~200x300; tiny = no usable print
MAX_STD = 85                                # extreme only: real swipes measured 34-80, broken frame 91/99
MAX_SAT = 25                                # % of pixels at the extremes (saturated) — healthy <7%
MIN_COVER = int(os.environ.get("VFS495_MIN_COVER", "60"))  # % of frame covered by the print.
                                                            # Calibrated: at >=61% matches occur,
                                                            # at <=58% none did. Override for tuning.
RUN = "/run/vfs495-fprint"                  # tmpfs, root only; last.pgm = most recent capture (debugging)
SCAN_DIR = RUN + "/scans"                   # archive: 40 delivered scans + 20 rejected (rej-*)
BUS_NAME, DEV_IFACE = "net.reactivated.Fprint", "net.reactivated.Fprint.Device"
PROPS = "org.freedesktop.DBus.Properties"
CAPTURE_PAUSE = 1.5                         # kept for documentation; applied only between retries
RETRY_PAUSE = float(os.environ.get("VFS495_RETRY_PAUSE", "2.5"))
                                            # wait before retrying after sensor-side bad frames
RETRY_PAUSE_FAST = float(os.environ.get("VFS495_RETRY_PAUSE_FAST", "1.2"))
                                            # wait after clean captures: a missed swipe must not eat
                                            # the whole verify window (fprintd cancels after ~30 s)
CAPTURE_TIMEOUT = 10                        # per-attempt budget; the LAST attempt gets the remainder
AUTH_WINDOW = float(os.environ.get("VFS495_AUTH_WINDOW", "28"))   # fprintd cancels the verify at ~30 s
MAX_ATTEMPTS = 3                            # retries within one auth request
GRACE = 5.0                                 # seconds the capture wrapper gets to exit after SIGTERM
PREARM_WINDOW = float(os.environ.get("VFS495_PREARM_WINDOW", "45"))
                                            # how long a pre-arm session may stay armed after the
                                            # screen locks; expired ones are torn down politely
PREARM_FRESH = float(os.environ.get("VFS495_PREARM_FRESH", "20"))
                                            # how long a pre-arm scan stays deliverable once fprintd asks
PREARM_BACKSTOP = PREARM_WINDOW + 10        # wrapper-side timeout cap for pre-arm attempts
USB_DRIVER = "/sys/bus/usb/drivers/usb"
USB_IDS = ("138a", "003f")                  # Validity Sensors VFS495
EXIT_OK, EXIT_NO_IMAGE, EXIT_ERROR, EXIT_FORCED = 0, 10, 11, 12
lock = threading.Lock()
state = {"proc": None, "capturing": False, "wanted": False, "gen": 0, "deferred": False,
         "needs_reinit": False, "locked": False, "cache": None, "mode": None,
         "prearm_done": False}
# mode: "auth" (worker serves fprintd) or "prearm" (worker armed by the screen lock;
# it serves fprintd too the moment finger-needed arrives). cache: (w, h, data, ts).

def log(m): print("[vfs495-bridge] " + m, file=sys.stderr, flush=True)

def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return w, h, f.read(w * h)


def read_timing(out):
    """Phase timings the capture wrapper wrote next to the image (best effort)."""
    try:
        with open(out + ".timing") as f:
            d = json.load(f)
        os.unlink(out + ".timing")
        return d
    except (OSError, ValueError):
        return {}


def timing_note(t):
    """Human-readable phase breakdown for the journal, or '' when nothing was produced.

    first contact = tool startup + the user's reaction; swipe = assembly progress;
    teardown = tool deinit + gdb quit (cannot be skipped without wedging the sensor).
    'no frames produced' while the user swears they swiped is the wedge signature.
    """
    if not t:
        return ""
    if t.get("first_frame_s") is None:
        return " [no frames produced]"
    parts = ["first contact +%.1fs" % t["first_frame_s"]]
    if t.get("last_frame_s") is not None:
        parts.append("swipe %.1fs" % (t["last_frame_s"] - t["first_frame_s"]))
        if t.get("gdb_exit_s") is not None:
            parts.append("teardown %.1fs" % (t["gdb_exit_s"] - t["last_frame_s"]))
    return " [" + ", ".join(parts) + "]"


def retry_pause(sensor_side_bad):
    """Clean captures can be retried sooner; only sensor-side badness needs the long pause."""
    return RETRY_PAUSE if sensor_side_bad else RETRY_PAUSE_FAST


def image_stats(w, h, data):
    """Compact quality metrics used to gate delivery and logged with each scan."""
    try:
        import numpy as np
        a = np.frombuffer(data[:w * h], dtype=np.uint8)
        if a.size != w * h:
            return "", None, None, None
        sat = float(((a <= 2) | (a >= 253)).mean() * 100)
        # contact coverage: share of the frame that differs from the flat background.
        # Failing swipes measured 30-67 %, matching swipes 75-84 %.
        cover = float((np.abs(a.astype(np.int16) - int(np.median(a))) > 12).mean() * 100)
        txt = (f"mean={a.mean():.0f} std={a.std():.0f} "
               f"dark={(a < 128).mean() * 100:.1f}% sat={sat:.1f}% cover={cover:.0f}%")
        return txt, float(a.std()), sat, cover
    except Exception:
        return "", None, None, None

_image_socket = None

def deliver(w, h, data):
    global _image_socket

    payload = struct.pack("<ii", w, h) + data

    for attempt in range(2):
        if _image_socket is None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.connect(SOCK)
            except OSError:
                connection.close()
                raise
            _image_socket = connection

        try:
            _image_socket.sendall(payload)
            return
        except OSError:
            _image_socket.close()
            _image_socket = None
            if attempt == 1:
                raise

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


def capture_pids():
    """gdb/vendor processes belonging to a capture (also finds orphans after a hard kill).

    Matched by executable name, never by cmdline substring: a shell or editor whose text
    mentions the vendor binary must not be signalled.
    """
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


def signal_capture_pids(sig):
    for pid in capture_pids():
        try: os.kill(pid, sig)
        except OSError: pass


def kill_capture():
    """Cancel a running capture politely.

    The wrapper gets SIGTERM and deinits the vendor tool itself; we only SIGKILL it (and mark
    the sensor for USB recovery) if it refuses to exit. Returns True if force was needed.
    """
    with lock: p = state["proc"]
    if not p:
        return False
    if p.poll() is not None:
        # wrapper already gone; make sure it did not leave gdb/the vendor behind
        if not capture_pids():
            return False
        log("leftover capture processes after the wrapper exited -> cleaning up")
        for sig, pause in ((signal.SIGTERM, 1.0), (signal.SIGKILL, 0.5)):
            if not capture_pids():
                break
            signal_capture_pids(sig)
            time.sleep(pause)
        with lock: state["needs_reinit"] = True
        return True
    try: os.killpg(p.pid, signal.SIGTERM)
    except OSError:
        try: p.terminate()
        except OSError: pass
    deadline = time.monotonic() + GRACE
    while time.monotonic() < deadline and p.poll() is None:
        time.sleep(0.05)
    if p.poll() is not None:
        return False
    log("capture ignored SIGTERM -> forcing it; sensor marked for recovery")
    try: os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        try: p.kill()
        except OSError: pass
    try: p.wait(timeout=2)
    except subprocess.TimeoutExpired: pass
    # wrapper is gone; its children need explicit cleanup
    for sig, pause in ((signal.SIGTERM, 1.0), (signal.SIGKILL, 0.5)):
        if not capture_pids():
            break
        signal_capture_pids(sig)
        time.sleep(pause)
    with lock: state["needs_reinit"] = True
    return True


def find_sensor_usb():
    """sysfs name (e.g. '4-1.3') of the VFS495, or None. Interface dirs contain ':'."""
    for path in glob.glob("/sys/bus/usb/devices/*"):
        name = os.path.basename(path)
        if ":" in name:
            continue
        try:
            with open(path + "/idVendor") as f: vid = f.read().strip()
            with open(path + "/idProduct") as f: pid = f.read().strip()
        except OSError:
            continue
        if (vid, pid) == USB_IDS:
            return name
    return None


def reinit_sensor(reason):
    """Recover from a stale vendor session by re-enumerating the USB device.

    This is a soft replug: no power cycle, no USBDEVFS_RESET (which produced kernel
    descriptor errors -32/-71 on this reader). Returns True on success.
    """
    dev = find_sensor_usb()
    if not dev:
        log(f"recovery ({reason}): sensor is not present on USB")
        return False
    t0 = time.monotonic()
    log(f"recovery ({reason}): re-enumerating USB device {dev}")
    try:
        with open(USB_DRIVER + "/unbind", "w") as f: f.write(dev)
    except OSError as e:
        log(f"recovery failed: unbind {dev}: {e}")
        return False
    for _ in range(30):                     # unbind is synchronous; confirm it took effect
        if find_sensor_usb() != dev:
            break
        time.sleep(0.1)
    else:
        log(f"recovery: {dev} still present after unbind, trying bind anyway")
    time.sleep(0.3)
    try:
        with open(USB_DRIVER + "/bind", "w") as f: f.write(dev)
    except OSError as e:
        log(f"recovery failed: bind {dev}: {e}")
        return False
    for _ in range(50):                     # wait for re-enumeration (up to 5 s)
        if find_sensor_usb() == dev:
            break
        time.sleep(0.1)
    else:
        log("recovery failed: sensor did not re-enumerate")
        return False
    time.sleep(0.5)                          # let the kernel settle the new device node
    log(f"recovery done in {time.monotonic() - t0:.1f}s")
    return True


def archive_scan(w, h, data, std, sat, prefix=""):
    """Keep the 40 delivered scans and the 20 most recent rejected ones (rej-*) for
    offline scoring: rejected frames are exactly what a sensor-health regression looks like."""
    try:
        os.makedirs(SCAN_DIR, mode=0o700, exist_ok=True)
        name = (prefix + time.strftime('%Y%m%d-%H%M%S') + f"-{time.time_ns() % 1_000_000_000:09d}_{w}x{h}"
                f"_std{0 if std is None else std:.0f}_sat{0 if sat is None else sat:.0f}.pgm")
        with open(os.path.join(SCAN_DIR, name), "wb") as f:
            f.write(b"P5\n%d %d\n255\n" % (w, h))
            f.write(data[:w * h])
        if prefix:
            mine = [n for n in os.listdir(SCAN_DIR) if n.startswith(prefix)]
            keep = 20
        else:
            mine = [n for n in os.listdir(SCAN_DIR) if not n.startswith("rej-")]
            keep = 40
        for old in sorted(mine)[:-keep]:
            try: os.unlink(os.path.join(SCAN_DIR, old))
            except OSError: pass
    except Exception as e:
        log(f"archive failed: {e}")


def run_capture(out, timeout=CAPTURE_TIMEOUT):
    """One capture attempt. Returns the wrapper's exit code."""
    p = subprocess.Popen([sys.executable, CAPTURE, out], env={**os.environ, "VFS_TIMEOUT": str(timeout)},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    with lock: state["proc"] = p
    rc = p.wait()
    with lock: state["proc"] = None
    return rc


def _recover(reason):
    with lock: state["needs_reinit"] = False
    ok = reinit_sensor(reason)
    if not ok:
        with lock: state["needs_reinit"] = True   # retry before the next capture
    return ok


def cache_store(w, h, data):
    """Remember a good pre-arm scan: this lock period's unlock swipe, already assembled."""
    with lock:
        state["cache"] = (w, h, data, time.monotonic())


def cache_take():
    """Pop the cached pre-arm scan if it is still fresh (single consumer)."""
    with lock:
        c, state["cache"] = state["cache"], None
    if c is None:
        return None
    w, h, data, ts = c
    if time.monotonic() - ts > PREARM_FRESH:
        log(f"pre-armed scan is {time.monotonic() - ts:.0f}s old -> ignoring it")
        return None
    return c


def deliver_cached(img, gen):
    """Fast path: hand an assembled pre-arm scan to fprintd. Holds the worker slot."""
    w, h, data, ts = img
    try:
        stats, *_ = image_stats(w, h, data)
        deliver(w, h, data)
        log(f"delivered pre-armed scan {w}x{h} {stats} — {time.monotonic() - ts:.1f}s after the swipe")
    except OSError as e:
        log(f"pre-armed scan delivery failed ({e}) -> capturing instead")
        with lock:
            state["gen"] += 1
            gen = state["gen"]
            state["mode"] = "auth"
        threading.Thread(target=capture_worker, args=(gen,), daemon=True).start()
        return
    with lock:
        state["capturing"] = False
        state["mode"] = None
        deferred, state["deferred"] = state["deferred"], False
    if deferred and state["wanted"]:
        start_auth_capture("new finger request arrived during cached delivery")


_bus = None                                 # system bus, set in main(); used by the lock poll

def poll_lock_state():
    """1 s poll of logind's LockedHint — the robust lock source.

    mutter sets LockedHint on every lock/unlock, and the system bus accepts root calls,
    unlike the user session bus where dbus-broker refuses us (the old ScreenSaver
    watcher never connected). Cheap: ListSessions + two property reads per session.
    """
    if _bus is None:
        return True
    try:
        mgr = dbus.Interface(_bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1"),
                             "org.freedesktop.login1.Manager")
        locked = False
        for sess in mgr.ListSessions():
            # the tuple layout is (id, uid, name, seat, path) but has been mis-indexed
            # before (sess[1] is the UInt32 uid!): find the object path by shape instead
            paths = [x for x in sess
                     if isinstance(x, str) and x.startswith("/org/freedesktop/login1/")]
            if not paths:
                continue
            p = dbus.Interface(_bus.get_object("org.freedesktop.login1", paths[0]), PROPS)
            if bool(p.Get(LOGIN1_SESSION, "LockedHint")) and bool(p.Get(LOGIN1_SESSION, "Active")):
                locked = True
                break
        on_lock_changed(locked)
    except dbus.DBusException:
        pass                                    # logind hiccups must never kill the poll
    except Exception as e:
        log(f"lock poll error: {e!r}")
    return True


def maybe_prearm():
    with lock:
        if state["capturing"] or state["wanted"] or state["prearm_done"]:
            return
        state["gen"] += 1
        gen = state["gen"]
        state["capturing"] = True
        state["mode"] = "prearm"
    log("screen locked -> pre-arming the sensor; swipe as soon as the lock screen is up")
    threading.Thread(target=capture_worker, args=(gen,), daemon=True).start()


def start_auth_capture(reason):
    """Become the capture owner for an auth request; a fresh pre-arm scan skips capture."""
    with lock:
        state["gen"] += 1
        gen = state["gen"]
        state["capturing"] = True
        state["mode"] = "auth"
    cached = cache_take()
    if cached is not None:
        log(f"{reason} -> handing over the pre-armed scan (captured while locked)")
        threading.Thread(target=deliver_cached, args=(cached, gen), daemon=True).start()
        return
    log(f"{reason} -> capturing; swipe now")
    threading.Thread(target=capture_worker, args=(gen,), daemon=True).start()


def capture_worker(gen):
    """One capture owner, started by an auth request (mode 'auth') or by the screen lock
    (mode 'prearm'). While fprintd is not waiting (pre-arm) a good scan is cached and
    handed over the instant finger-needed arrives; the moment fprintd IS waiting, every
    good scan is delivered directly and a pre-arm's window no longer applies."""
    os.makedirs(RUN, mode=0o700, exist_ok=True)
    out, last = RUN + "/cap.pgm", RUN + "/last.pgm"
    t0 = time.monotonic()
    delivered = False
    bad_streak = 0
    zero_frames = 0
    sensor_bad = False
    attempts = 0
    try:
        if state["needs_reinit"]:
            _recover("previous capture needed a forced kill")
        while attempts < MAX_ATTEMPTS:
            with lock:
                superseded = state["gen"] != gen
                prearm = state["mode"] == "prearm"
                wanted = state["wanted"]
                locked = state["locked"]
            if superseded:
                log("capture superseded -> exiting"); return
            if prearm and not wanted:
                if not locked:
                    log("pre-arm cancelled (screen unlocked)"); return
                if time.monotonic() - t0 > PREARM_WINDOW:
                    log("pre-arm window expired -> disarming (sensor comfort)"); return
            elif not wanted:
                log("capture cancelled (fprintd no longer waiting)"); return
            if attempts > 0:
                # recovery pause between captures: rapid back-to-back captures make the
                # sensor return tiny/degraded scans and trigger its own USB reset behaviour.
                # Clean captures retry sooner — a missed swipe must not eat the verify window.
                pause = retry_pause(sensor_bad)
                sensor_bad = False
                time.sleep(pause)
                log("retrying capture after %.1fs — swipe again if the finger prompt is still "
                    "showing" % pause)
            attempts += 1
            if prearm:
                left = PREARM_WINDOW - (time.monotonic() - t0) + 5.0
                budget = max(5.0, min(PREARM_BACKSTOP, left))
            else:
                # fprintd cancels the verify after ~30 s; short attempts keep every retry
                # inside the window instead of burning it on one 18 s wait
                budget = max(4.0, min(CAPTURE_TIMEOUT, AUTH_WINDOW - (time.monotonic() - t0)))
            rc = run_capture(out, timeout=budget)
            timing = read_timing(out)
            if rc == EXIT_FORCED:
                log("capture wrapper had to force-kill the vendor tool -> re-enumerating USB")
                _recover("forced kill during capture")
                bad_streak = 0
                sensor_bad = True
                continue
            with lock:
                wanted = state["wanted"]
                locked = state["locked"]
            if not wanted and not (prearm and locked):
                log("capture cancelled (fprintd no longer waiting)"); return
            ok = rc == EXIT_OK
            if ok:
                img = read_pgm(out); os.replace(out, last)
                stats, std, sat, cover = image_stats(*img)
                reason = None
                if img[1] < MIN_ROWS:
                    reason = (f"{img[0]}x{img[1]} is too short — swipe too short/fast, or the sensor is in "
                              "its stuck state (then: full power-off, not a reboot)")
                elif cover is not None and cover < MIN_COVER:
                    reason = f"partial contact ({cover:.0f}% of frame covered — press the whole finger flat)"
                elif std is not None and std > MAX_STD:
                    reason = f"degenerate frame (std {std:.0f})"
                elif sat is not None and sat > MAX_SAT:
                    reason = f"saturated frame ({sat:.1f}%)"
                if reason:
                    log(f"rejected scan {img[0]}x{img[1]}: {reason}{timing_note(timing)}")
                    archive_scan(*img, std, sat, prefix="rej-")
                    ok = False
                    sensor_side = ((std is not None and std > MAX_STD) or
                                   (sat is not None and sat > MAX_SAT))
                    sensor_bad = sensor_side
                    bad_streak = bad_streak + 1 if sensor_side else 0
                    if bad_streak >= 2:
                        log("two sensor-side bad frames in a row -> trying USB re-enumeration")
                        _recover("repeated degenerate frames")
                        bad_streak = 0
                else:
                    bad_streak = 0
                    archive_scan(*img, std, sat)
                    if wanted:
                        try:
                            deliver(*img)
                            delivered = True
                            log(f"delivered scan {img[0]}x{img[1]} {stats} after "
                                f"{time.monotonic()-t0:.1f}s{timing_note(timing)}")
                            return
                        except OSError as e:
                            log(f"deliver failed: {e}"); return
                    else:
                        cache_store(*img)
                        log(f"pre-armed scan ready ({img[0]}x{img[1]} {stats}) — "
                            "fprintd gets it the moment it asks")
                        return
            if not ok:
                last_attempt = attempts >= MAX_ATTEMPTS
                log("no usable finger scan" + (" (give up)" if last_attempt else ", retrying")
                    + timing_note(timing))
                # Two attempts in one prompt with not a single frame = the sensor is not
                # seeing anything (stale session / wedged-ish). Re-enumerate while the
                # prompt is still open instead of burning the round.
                if timing.get("first_frame_s") is None:
                    zero_frames += 1
                    if zero_frames >= 2 and not last_attempt:
                        log("two zero-frame attempts in one prompt -> USB re-enumeration")
                        _recover("zero-frame attempts")
                        zero_frames = 0
                else:
                    zero_frames = 0
    except Exception as e:
        log(f"capture worker error: {e!r}")
    finally:
        try: os.unlink(out)
        except OSError: pass
        with lock:
            was_prearm = state["mode"] == "prearm"
            state["capturing"] = False
            state["mode"] = None
            if was_prearm and state["locked"]:
                state["prearm_done"] = True    # one pre-arm per lock period
            deferred, state["deferred"] = state["deferred"], False
        if deferred and state["wanted"] and not delivered:
            # A new request that arrived while this capture was shutting down must not be lost.
            start_auth_capture("new finger request arrived during shutdown")

def on_needed(reason):
    was_wanted = state["wanted"]
    state["wanted"] = True
    if state["capturing"]:
        if not was_wanted:
            state["deferred"] = True          # may be a fresh request, not the same one
        return
    start_auth_capture(f"finger needed ({reason})")

def on_not_needed():
    if not state["wanted"]: return
    state["wanted"] = False
    with lock:
        prearm = state["mode"] == "prearm"
    if state["capturing"] and not prearm:
        # a pre-arm session outlives a fprintd cancel: the screen is still locked
        state["gen"] += 1; kill_capture()

def on_lock_changed(active, initial=False):
    if active:
        if state["locked"]: return
        state["locked"] = True
        if initial:
            log("screen was already locked")
        maybe_prearm()
    else:
        if not state["locked"]: return
        state["locked"] = False
        log("screen unlocked")
        with lock:
            stop_prearm = state["mode"] == "prearm" and state["capturing"]
            state["cache"] = None
            state["prearm_done"] = False
        if stop_prearm:
            state["gen"] += 1; kill_capture()

def on_props_changed(iface, changed, invalidated, path=None):
    if iface != DEV_IFACE or "finger-needed" not in changed: return
    if bool(changed["finger-needed"]): on_needed("finger-needed")
    else: on_not_needed()

def on_verify_selected(*args, path=None): on_needed("verify started")

VERIFY_STATUS_NAMES = {0: "match", 1: "no match", 100: "retry, scan again",
                       101: "swipe too short", 102: "not centered",
                       103: "remove finger and retry"}

def on_verify_status(code, done, path=None):
    if isinstance(code, str):                     # this fprintd sends strings: 'verify-match', ...
        name = code.removeprefix("verify-").replace("-", " ")
    else:
        name = VERIFY_STATUS_NAMES.get(int(code), "code " + str(int(code)))
    log(f"verify result: {name} (done={bool(done)})")

LOGIN1_SESSION = "org.freedesktop.login1.Session"

def on_login1_props(iface, changed, invalidated, path=None):
    """logind LockedHint is set by mutter/gnome-shell on every lock and unlock. This is
    the primary lock source: it is visible on the system bus (which we already use),
    while root cannot even Hello() on the user's dbus-broker session bus."""
    if iface != LOGIN1_SESSION or "LockedHint" not in changed: return
    on_lock_changed(bool(changed["LockedHint"]))

def _on_sigterm(signum, frame):
    raise SystemExit(0)

def main():
    global _bus
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    _bus = bus
    bus.add_signal_receiver(on_props_changed, signal_name="PropertiesChanged", dbus_interface=PROPS,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_selected, signal_name="VerifyFingerSelected", dbus_interface=DEV_IFACE,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_status, signal_name="VerifyStatus", dbus_interface=DEV_IFACE,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_login1_props, signal_name="PropertiesChanged", dbus_interface=PROPS,
                            bus_name="org.freedesktop.login1", path_keyword="path")
    def check_initial():                                # a scan already pending at startup?
        try:
            mgr = dbus.Interface(bus.get_object(BUS_NAME, "/net/reactivated/Fprint/Manager"), "net.reactivated.Fprint.Manager")
            for dev in mgr.GetDevices():
                p = dbus.Interface(bus.get_object(BUS_NAME, dev), PROPS)
                if bool(p.Get(DEV_IFACE, "finger-needed")): on_needed("pending at startup")
        except dbus.DBusException: pass
        return False
    signal.signal(signal.SIGTERM, _on_sigterm)
    GLib.timeout_add(1500, check_initial)
    poll_lock_state()                                   # covers "started while already locked"
    GLib.timeout_add(1000, poll_lock_state)
    log("idle; waiting for fprintd to need a finger")
    try:
        GLib.MainLoop().run()
    finally:
        state["wanted"] = False
        state["cache"] = None
        if state["capturing"]:
            state["gen"] += 1
            kill_capture()
        log("service stopping")

if __name__ == "__main__": main()

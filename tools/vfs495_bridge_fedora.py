#!/usr/bin/env python3
"""vfs495 bridge (event-driven): stays completely idle until fprintd's device reports
finger-needed=true (a verify or enroll is waiting for a swipe), then runs ONE capture on
the real sensor and delivers the image to libfprint's virtual_image socket. When fprintd
stops needing a finger (timeout, cancel, done) a still-running capture is cancelled, so the
sensor is never held longer than an authentication actually lasts."""
import os, signal, socket, struct, subprocess, sys, threading, time
import dbus, dbus.mainloop.glib
from gi.repository import GLib

SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
CAPTURE = "/home/tousifo/vfs495-linux/tools/vfs495_capture_asm.py"
MIN_ROWS = 180                                # a real swipe assembles to ~200x300; tiny = no usable print
MAX_STD = 85                                # extreme only: real swipes measured 34-80, broken frame 91/99
MAX_SAT = 25                                # % of pixels at the extremes (saturated) — healthy <7%
RUN = "/run/vfs495-fprint"                  # tmpfs, root only; last.pgm = most recent capture (debugging)
SCAN_DIR = RUN + "/scans"                   # archive of delivered scans (for matched/unmatched analysis)
BUS_NAME, DEV_IFACE = "net.reactivated.Fprint", "net.reactivated.Fprint.Device"
PROPS = "org.freedesktop.DBus.Properties"
CAPTURE_PAUSE = 1.5                         # kept for documentation; applied only between retries
RETRY_PAUSE = 2.5                           # wait before retrying after a tiny/failed scan
lock = threading.Lock()
state = {"proc": None, "capturing": False, "wanted": False, "gen": 0}

def log(m): print("[vfs495-bridge] " + m, file=sys.stderr, flush=True)

def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"; w, h = map(int, f.readline().split()); f.readline()
        return w, h, f.read(w * h)


def image_stats(w, h, data):
    """Compact quality metrics used to gate delivery and logged with each scan."""
    try:
        import numpy as np
        a = np.frombuffer(data[:w * h], dtype=np.uint8)
        if a.size != w * h:
            return "", None, None
        sat = float(((a <= 2) | (a >= 253)).mean() * 100)
        txt = (f"mean={a.mean():.0f} std={a.std():.0f} "
               f"dark={(a < 128).mean() * 100:.1f}% sat={sat:.1f}%")
        return txt, float(a.std()), sat
    except Exception:
        return "", None, None

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

def run_capture(out):
    """One capture attempt. Returns True if an image was written to `out`."""
    p = subprocess.Popen([sys.executable, CAPTURE, out], env={**os.environ, "VFS_TIMEOUT": "70"},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    with lock: state["proc"] = p
    rc = p.wait()
    with lock: state["proc"] = None
    return rc == 0

def kill_capture():
    with lock: p = state["proc"]
    if p and p.poll() is None:
        try: os.killpg(p.pid, signal.SIGTERM)
        except OSError: pass
        subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"], stderr=subprocess.DEVNULL)

def archive_scan(w, h, data, std, sat):
    """Keep the last 40 delivered scans so matched and unmatched swipes can be compared later."""
    try:
        os.makedirs(SCAN_DIR, mode=0o700, exist_ok=True)
        name = (f"{time.strftime('%Y%m%d-%H%M%S')}_{w}x{h}"
                f"_std{0 if std is None else std:.0f}_sat{0 if sat is None else sat:.0f}.pgm")
        with open(os.path.join(SCAN_DIR, name), "wb") as f:
            f.write(b"P5\n%d %d\n255\n" % (w, h))
            f.write(data[:w * h])
        for old in sorted(os.listdir(SCAN_DIR))[:-40]:
            try: os.unlink(os.path.join(SCAN_DIR, old))
            except OSError: pass
    except Exception as e:
        log(f"archive failed: {e}")


def capture_and_deliver(gen):
    os.makedirs(RUN, mode=0o700, exist_ok=True)
    out, last = RUN + "/cap.pgm", RUN + "/last.pgm"
    t0 = time.monotonic()
    try:
        for attempt in range(2):                       # a swipe can straddle the window; try twice
            if attempt > 0:
                # recovery pause between captures: rapid back-to-back captures make the
                # sensor return tiny/degraded scans and trigger its own USB reset behaviour
                time.sleep(RETRY_PAUSE)
            ok = run_capture(out)
            if state["gen"] != gen or not state["wanted"]:
                log("capture cancelled (fprintd no longer waiting)"); return
            if ok:
                img = read_pgm(out); os.replace(out, last)
                stats, std, sat = image_stats(*img)
                reason = None
                if img[1] < MIN_ROWS:
                    reason = (f"{img[0]}x{img[1]} is too short — swipe too short/fast, or the sensor is in "
                              "its stuck state (then: full power-off, not a reboot)")
                elif std is not None and std > MAX_STD:
                    reason = f"degenerate frame (std {std:.0f})"
                elif sat is not None and sat > MAX_SAT:
                    reason = f"saturated frame ({sat:.1f}%)"
                if reason:
                    log(f"rejected scan {img[0]}x{img[1]}: {reason}"); ok = False
                else:
                    archive_scan(*img, std, sat)
                    try:
                        deliver(*img); log(f"delivered scan {img[0]}x{img[1]} {stats} after {time.monotonic()-t0:.1f}s"); return
                    except OSError as e:
                        log(f"deliver failed: {e}"); return
            if not ok:
                log("no usable finger scan" + (", retrying" if attempt == 0 else " (give up)"))
    finally:
        try: os.unlink(out)
        except OSError: pass
        state["capturing"] = False

def on_needed(reason):
    state["wanted"] = True
    if state["capturing"]: return
    state["capturing"] = True; state["gen"] += 1
    log(f"finger needed ({reason}) -> capturing; swipe now")
    threading.Thread(target=capture_and_deliver, args=(state["gen"],), daemon=True).start()

def on_not_needed():
    if not state["wanted"]: return
    state["wanted"] = False
    if state["capturing"]:
        state["gen"] += 1; kill_capture()

def on_props_changed(iface, changed, invalidated, path=None):
    if iface != DEV_IFACE or "finger-needed" not in changed: return
    if bool(changed["finger-needed"]): on_needed("finger-needed")
    else: on_not_needed()

def on_verify_selected(*args, path=None): on_needed("verify started")

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    bus.add_signal_receiver(on_props_changed, signal_name="PropertiesChanged", dbus_interface=PROPS,
                            bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_selected, signal_name="VerifyFingerSelected", dbus_interface=DEV_IFACE,
                            bus_name=BUS_NAME, path_keyword="path")
    def check_initial():                                # a scan already pending at startup?
        try:
            mgr = dbus.Interface(bus.get_object(BUS_NAME, "/net/reactivated/Fprint/Manager"), "net.reactivated.Fprint.Manager")
            for dev in mgr.GetDevices():
                p = dbus.Interface(bus.get_object(BUS_NAME, dev), PROPS)
                if bool(p.Get(DEV_IFACE, "finger-needed")): on_needed("pending at startup")
        except dbus.DBusException: pass
        return False
    GLib.timeout_add(1500, check_initial)
    log("idle; waiting for fprintd to need a finger")
    GLib.MainLoop().run()

if __name__ == "__main__": main()

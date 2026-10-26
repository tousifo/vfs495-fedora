#!/usr/bin/env python3
"""Unit tests for the capture-lifecycle hardening (vfs495_capture_asm.py +
vfs495_bridge_fedora.py). Runs without the sensor and without root:

    python3 tools/test_hardening.py

The tests spawn throwaway decoy processes: binaries copied under the names the
session scan matches ("validity-sensor-unlocked", "gdb-*") plus a python decoy
whose command line merely mentions those names. Nothing else may ever be
signalled — matching is by /proc/*/exe, so at worst a real stale capture
leftover is cleaned up, which is exactly what these functions are for.
"""
import os, shutil, signal, subprocess, sys, tempfile, time, unittest

RE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RE, "tools"))
import vfs495_bridge_fedora as bridge
import vfs495_capture_asm as wrapper

# argv[1] == "s" makes the decoy ignore SIGTERM (stubborn), otherwise it exits on it.
DECOY_C = """#include <signal.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 's') signal(SIGTERM, SIG_IGN);
    pause();
    return 0;
}
"""


def compile_decoy(dirpath, name):
    src = os.path.join(dirpath, "decoy.c")
    exe = os.path.join(dirpath, name)
    with open(src, "w") as f:
        f.write(DECOY_C)
    subprocess.run(["gcc", "-O0", "-o", exe, src], check=True)
    return exe


class HardeningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vfs495-test-")
        self.children = []
        self.old_grace_bridge = bridge.GRACE
        self.old_scan_dir = bridge.SCAN_DIR

    def tearDown(self):
        for p in self.children:
            if p.poll() is None:
                p.kill()
                try: p.wait(timeout=2)
                except subprocess.TimeoutExpired: pass
        shutil.rmtree(self.tmp, ignore_errors=True)
        bridge.GRACE = self.old_grace_bridge
        bridge.SCAN_DIR = self.old_scan_dir
        with bridge.lock:
            bridge.state.update(proc=None, needs_reinit=False)

    def spawn(self, argv, **kw):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        self.children.append(p)
        time.sleep(0.2)                      # let it appear in /proc
        return p

    def decoy_vendor(self, stubborn=False):
        """A process whose /proc/exe basename is 'validity-sensor-unlocked'.

        Runs in its own session like the real gdb (start_new_session), so the
        bridge's killpg path is exercised, not just the p.terminate() fallback."""
        exe = compile_decoy(self.tmp, "validity-sensor-unlocked")
        return self.spawn([exe, "s" if stubborn else "x"], start_new_session=True)

    def decoy_gdb(self):
        """A process matching the gdb branch: exe gdb-* running the harvest script."""
        exe = compile_decoy(self.tmp, "gdb-harvest-decoy")
        return self.spawn([exe, "x", bridge.HARVEST], start_new_session=True)

    def decoy_python_mentioning_names(self):
        """A python process whose cmdline text mentions the binary names — must NEVER match."""
        code = ("# talks about /runtime/bin/validity-sensor-unlocked and "
                "/runtime/harvest_assembled.py\nimport time; time.sleep(20)")
        return self.spawn([sys.executable, "-c", code])

    def test_decoy_mentioning_names_is_not_matched(self):
        p = self.decoy_python_mentioning_names()
        self.assertNotIn(p.pid, wrapper.session_pids())
        self.assertNotIn(p.pid, bridge.capture_pids())

    def test_vendor_and_gdb_decoys_are_matched(self):
        pv = self.decoy_vendor()
        pg = self.decoy_gdb()
        for scanner in (wrapper.session_pids, bridge.capture_pids):
            pids = scanner()
            self.assertIn(pv.pid, pids)
            self.assertIn(pg.pid, pids)

    def test_reap_session_stops_politely(self):
        p = self.decoy_vendor()
        self.assertFalse(wrapper.reap_session(grace=1.0))
        self.assertIsNotNone(p.poll())

    def test_reap_session_escalates_for_stubborn_process(self):
        p = self.decoy_vendor(stubborn=True)
        self.assertTrue(wrapper.reap_session(grace=0.5))
        self.assertIsNotNone(p.poll())

    def test_stop_gdb_without_proc_reaps_orphans(self):
        p = self.decoy_gdb()
        self.assertFalse(wrapper.stop_gdb(None, grace=1.0))
        self.assertIsNotNone(p.poll())

    def test_bridge_kill_capture_polite(self):
        bridge.GRACE = 1.0
        p = self.spawn(["/bin/sleep", "30"], start_new_session=True)
        with bridge.lock: bridge.state["proc"] = p
        self.assertFalse(bridge.kill_capture())
        self.assertIsNotNone(p.poll())
        with bridge.lock:
            self.assertFalse(bridge.state["needs_reinit"])
            bridge.state["proc"] = None

    def test_bridge_kill_capture_escalates_and_marks_recovery(self):
        bridge.GRACE = 1.0
        p = self.decoy_vendor(stubborn=True)
        with bridge.lock: bridge.state["proc"] = p
        self.assertTrue(bridge.kill_capture())
        self.assertIsNotNone(p.poll())
        with bridge.lock:
            self.assertTrue(bridge.state["needs_reinit"])
            bridge.state["proc"] = None

    def test_archive_keeps_40_good_and_20_rejected(self):
        bridge.SCAN_DIR = self.tmp
        for i in range(45):
            bridge.archive_scan(200, 300, bytes(200 * 300), 40.0, 0.5)
        for i in range(25):
            bridge.archive_scan(200, 300, bytes(200 * 300), 120.0, 30.0, prefix="rej-")
        names = os.listdir(self.tmp)
        good = [n for n in names if not n.startswith("rej-")]
        rej = [n for n in names if n.startswith("rej-")]
        self.assertEqual(len(good), 40)
        self.assertEqual(len(rej), 20)

    def test_find_sensor_usb_shape(self):
        dev = bridge.find_sensor_usb()
        if dev is not None:
            self.assertNotIn(":", dev)
            self.assertNotIn("/", dev)


class PrearmTest(unittest.TestCase):
    """Pre-arm on screen lock: cache a good scan while locked, hand it to fprintd on
    finger-needed. Everything is stubbed — no sensor, no root, no D-Bus."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vfs495-prearm-")
        self.keep = {k: getattr(bridge, k) for k in
                     ("RUN", "SCAN_DIR", "deliver", "run_capture", "capture_worker",
                      "deliver_cached", "kill_capture", "PREARM_WINDOW", "RETRY_PAUSE")}
        bridge.RUN = self.tmp
        bridge.SCAN_DIR = os.path.join(self.tmp, "scans")
        self.delivered = []
        self.spawned = []                       # what a stubbed worker/killer received
        self.captures = 0
        self.real_worker = bridge.capture_worker        # stubs below must not hide these
        self.real_deliver_cached = bridge.deliver_cached
        bridge.deliver = lambda *a: self.delivered.append(a)
        bridge.run_capture = self.fake_run_capture
        bridge.capture_worker = lambda gen: self.spawned.append(("worker", gen))
        bridge.deliver_cached = lambda img, gen: self.spawned.append(("cache", img, gen))
        bridge.kill_capture = lambda: self.spawned.append("kill") or False
        self.reset_state()

    def tearDown(self):
        for k, v in self.keep.items():
            setattr(bridge, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.reset_state()

    def reset_state(self):
        with bridge.lock:
            bridge.state.update(proc=None, capturing=False, wanted=False, gen=0,
                                deferred=False, needs_reinit=False, locked=False,
                                cache=None, mode=None, prearm_done=False)

    def fake_run_capture(self, out, timeout=None):
        """A healthy synthetic frame: 40 px flat background + 160 px strong texture per row
        (cover 80 %, std ~20, no saturation — passes every gate)."""
        self.captures += 1
        row = bytes([128]) * 40 + bytes([100, 150]) * 80
        with open(out, "wb") as f:
            f.write(b"P5\n200 300\n255\n")
            f.write(row * 300)
        return 0

    def good_img(self):
        return 200, 300, bytes(200 * 300)

    def test_cache_take_is_single_consumer_and_freshness_gated(self):
        self.assertIsNone(bridge.cache_take())
        bridge.cache_store(*self.good_img())
        got = bridge.cache_take()
        self.assertIsNotNone(got)
        self.assertIsNone(bridge.cache_take())          # popped: exactly one consumer
        with bridge.lock:
            bridge.state["cache"] = (200, 300, b"x", time.monotonic() - 999)
        self.assertIsNone(bridge.cache_take())          # stale -> dropped

    def test_prearm_worker_caches_good_scan_instead_of_delivering(self):
        with bridge.lock:
            bridge.state.update(mode="prearm", locked=True, capturing=True)
        self.real_worker(0)
        with bridge.lock:
            self.assertIsNotNone(bridge.state["cache"])
            self.assertFalse(bridge.state["capturing"])
            self.assertIsNone(bridge.state["mode"])
            self.assertTrue(bridge.state["prearm_done"])  # one pre-arm per lock period
        self.assertEqual(self.delivered, [])              # nothing sent to fprintd

    def test_auth_worker_delivers_directly(self):
        with bridge.lock:
            bridge.state.update(mode="auth", wanted=True, capturing=True)
        self.real_worker(0)
        self.assertEqual(len(self.delivered), 1)
        with bridge.lock:
            self.assertIsNone(bridge.state["cache"])

    def test_on_needed_hands_fresh_cache_to_fprintd(self):
        bridge.cache_store(*self.good_img())
        bridge.on_needed("test")
        self.assertEqual([s[0] for s in self.spawned], ["cache"])
        with bridge.lock:
            self.assertIsNone(bridge.state["cache"])      # consumed

    def test_on_needed_falls_back_to_capture_on_stale_cache(self):
        with bridge.lock:
            bridge.state["cache"] = (200, 300, b"x", time.monotonic() - 999)
        bridge.on_needed("test")
        self.assertEqual([s[0] for s in self.spawned], ["worker"])

    def test_on_not_needed_keeps_prearm_but_kills_auth(self):
        with bridge.lock:
            bridge.state.update(mode="prearm", capturing=True, wanted=True)
        bridge.on_not_needed()
        self.assertNotIn("kill", self.spawned)
        with bridge.lock:
            bridge.state.update(mode="auth", capturing=True, wanted=True)
        bridge.on_not_needed()
        self.assertIn("kill", self.spawned)

    def test_unlock_stops_prearm_and_clears_cache_but_spares_auth(self):
        bridge.cache_store(*self.good_img())
        with bridge.lock:
            bridge.state.update(mode="prearm", capturing=True, locked=True)
        bridge.on_lock_changed(False)
        self.assertIn("kill", self.spawned)
        with bridge.lock:
            self.assertIsNone(bridge.state["cache"])
            self.assertFalse(bridge.state["locked"])
        self.spawned.clear()
        with bridge.lock:
            bridge.state.update(mode="auth", capturing=True, locked=True)
        bridge.on_lock_changed(False)
        self.assertNotIn("kill", self.spawned)

    def test_maybe_prearm_gates(self):
        bridge.maybe_prearm()
        with bridge.lock:
            self.assertEqual(bridge.state["mode"], "prearm")
            self.assertTrue(bridge.state["capturing"])
        time.sleep(0.1)                               # the worker thread runs the stub
        self.assertEqual(self.spawned, [("worker", 1)])

        self.reset_state()
        with bridge.lock:
            bridge.state["wanted"] = True                 # fprintd already asking -> no pre-arm
        bridge.maybe_prearm()
        with bridge.lock:
            self.assertFalse(bridge.state["capturing"])

        self.reset_state()
        with bridge.lock:
            bridge.state["prearm_done"] = True            # already pre-armed this lock period
        bridge.maybe_prearm()
        with bridge.lock:
            self.assertFalse(bridge.state["capturing"])

    def test_prearm_window_expires_before_any_capture(self):
        bridge.PREARM_WINDOW = -1.0                       # expired the moment it starts
        with bridge.lock:
            bridge.state.update(mode="prearm", locked=True, capturing=True)
        self.real_worker(0)
        self.assertEqual(self.captures, 0)
        with bridge.lock:
            self.assertFalse(bridge.state["capturing"])

    def test_deliver_cached_failure_falls_back_to_capture(self):
        def boom(*a):
            raise OSError("socket gone")
        bridge.deliver = boom
        with bridge.lock:
            bridge.state.update(mode="auth", capturing=True)
        self.real_deliver_cached(self.good_img() + (time.monotonic(),), 0)
        self.assertEqual([s[0] for s in self.spawned], ["worker"])
        with bridge.lock:
            self.assertEqual(bridge.state["mode"], "auth")
            self.assertTrue(bridge.state["capturing"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

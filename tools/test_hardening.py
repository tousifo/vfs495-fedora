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


if __name__ == "__main__":
    unittest.main(verbosity=2)

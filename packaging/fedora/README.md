# Fedora install: VFS495 fingerprint login (bridge + fprintd virtual_image)

Fedora does not use the Debian `.deb`. On Fedora, stock `fprintd` + `libfprint`
(which already contain libfprint's `virtual_image` debug device) are combined
with the capture bridge installed as a systemd service, plus an authselect
enablement. No Fedora RPM package is required — these few files ARE the Fedora
install. Verified end-to-end on an HP ProBook 645 G4 (VFS495, `138a:003f`),
Fedora 44 with `fprintd-1.94.5` / `libfprint-1.94.100`.

## Files in this directory

| File | Installed to | Purpose |
|------|--------------|---------|
| `vfs495-bridge.service` | `/etc/systemd/system/vfs495-bridge.service` | Runs the capture bridge as root (needs USB + gdb approval) |
| `fprintd.service.d/virtimg.conf` | `/etc/systemd/system/fprintd.service.d/virtimg.conf` | Makes fprintd start its `virtual_image` device at `/run/fprint/virtimg_sock` |
| `system-sleep/vfs495-bridge` | `/usr/lib/systemd/system-sleep/vfs495-bridge` | Suspend hygiene: stop the bridge before sleep, re-enumerate the reader after resume |
| `install-fedora.sh` | — | Copies everything into place, enables the service, sets up authselect |

The bridge script itself lives in the repo at `tools/vfs495_bridge_fedora.py`
and is installed to `/usr/local/libexec/vfs495-fedora-bridge.py`.

## Install

```bash
sudo dnf install fprintd fprintd-pam gdb python3-dbus python3-glib python3-numpy python3-scipy
# one-time capture-harness setup (HP's package + gate patch): runtime/README.md
sudo bash packaging/fedora/install-fedora.sh
fprintd-enroll            # wait ~2 s after each prompt, then swipe slowly, full length, x6 promptly
sudo -k && sudo true      # test: should now ask for a swipe
```

PAM: run `authselect current` — the profile must include `with-fingerprint`
(the stock `local` profile does NOT; without it the login prompt never tries
fingerprints at all). `install-fedora.sh` enables it via
`authselect select local with-fingerprint with-silent-lastlog with-mdns4 --force`
— review that line before running; it rewrites PAM config (password auth stays
as fallback, but you should keep an hour for plan B: password always works).

## How it works / quirks learned so far (Fedora-specific)

- **Thermal guard (fixed).** libfprint's `virtual_image` debug driver simulates device
  heating: the ratio rises while an auth session waits for a finger and, once >0.731,
  every scan fails instantly with `Device disabled to prevent overheating`; it stays
  HOT until the ratio decays below 0.5 (~3 min idle). That simulation is meaningless
  for this pipeline and causes intermittent "fingerprint suddenly stopped working".
  Fix: `FP_VIRTUAL_IMAGE_HOT_SECONDS=-1` in the fprintd drop-in (upstream-documented
  env var; disables the model, "device can run continuously").
- **Quality gate (data-driven, 2026-10-31).** The bridge rejects a frame only when
  it is structurally unusable: shorter than 180 rows (no print area) or covered
  less than 60 % by fingerprint (flat/empty read — measured 0–6/40). Noise
  metrics do NOT block delivery: offline scoring of a boot-login frame with
  std 88 / sat 26 % scored **85/40 = MATCH**, while the old gate threw it away —
  the 40/40 matcher is the real judge, and a degraded frame that matches beats a
  retry the user never swipes for. Frames with std > 85, sat > 25 % or std < 15
  (flat read) are still counted for the USB re-enumeration recovery and logged
  as `[degraded frame — matcher decides]`. Tune cover with `VFS495_MIN_COVER`.
- Dry skin is the other big lever: ridge contrast (`std=`) drops and scores fall
  even at full coverage. Breathing on the fingertip fixed a 3/3 run here.
- Verify prompts are event-driven: fprintd signals `finger-needed` over D-Bus,
  the bridge starts exactly one capture, and a repeat `VerifyStart` inside one
  authentication re-delivers/retries. HP's tool is ready in ~0.5 s (measured),
  so there is nothing to wait for: start the swipe when the prompt appears, but
  keep it slow. fprintd cancels the verify after ~30 s, so the bridge budgets
  its attempts (3 × 10 s, last one takes the remainder) and pauses 1.2 s between
  clean retries / 2.5 s after sensor-side bad frames — a missed swipe no longer
  eats the whole window (the old fixed 18 s attempt did exactly that).
- **Early delivery.** The harvest breakpoint rewrites the assembled image on
  every callback, so the last write IS the final image: the wrapper delivers as
  soon as the assembly has ≥ 180 rows and has been stable for 0.3 s (finger
  lifted), instead of waiting out the vendor tool's ~1 s teardown. Verdict lands
  < 1 s after the finger lifts (was ~2 s). The tool finishes its deinit as a
  background orphan; every cleanup path waits up to 3 s for that natural drain
  before signalling anything — a TERM into a live deinit is the classic wedge.
- **Pre-arm on screen lock.** A 1 s poll of logind's `LockedHint` (mutter sets
  it on every lock; the system bus accepts root where user session buses refuse
  it) starts ONE vendor session per lock period, so the unlock swipe is captured
  *before* PAM asks and handed over the instant `finger-needed` arrives. Journal
  markers: `screen locked -> pre-arming`, `pre-armed scan ready`,
  `delivered pre-armed scan`. Sessions are bounded (VFS495_PREARM_WINDOW, 45 s)
  and torn down politely.
- **Phase timing in the journal.** Every capture logs
  `[first contact +Xs, swipe Ys, teardown Zs]` (or `no frames produced`, the
  wedge signature). Measured on this machine: first contact 1.7–3.3 s (tool
  ~0.5 s + human reaction), swipe 2.0–2.4 s, teardown ~1.0 s, match ~0.3 s.
- libfprint's bozorth3 threshold is 40; genuine full-length slow swipes score
  65–122 here, partial scans (height 194–271) often score < 40. See
  `docs/FINDINGS.md` and the score/height correlation traces in the journal
  (`journalctl -u fprintd | grep score`, `journalctl -u vfs495-bridge`).
- **One print = five sub-templates.** libfprint stores one template per enrollment
  stage (five here) inside the single print file and the matcher tries them in
  order, stopping at the first score ≥ 40. PAM calls `VerifyStart("any")`, so with
  two or more prints enrolled fprintd *identifies* against all of them. That makes
  extra templates a legitimate accuracy lever that does not touch the threshold.
- **Optional second template for the same finger.** fprintd 1.94 refuses
  re-enrolling a finger it can already identify (`enroll-duplicate`), but a print
  can be built offline from archived scans that already score well:
  ```bash
  # 1. copy the enrolled print out (root) for offline scoring
  sudo cp /var/lib/fprint/$USER/virtual_image/0/7 /tmp/enrolled.print
  # 2. score archived scans ~/.local/share/vfs495/scans/*.pgm (or /run/vfs495-fprint/scans)
  python3 tools/vfs495_score_image.py /tmp/enrolled.print /run/vfs495-fprint/scans/*.pgm
  # 3. build an extra print from the five best scans (same physical finger!)
  VFS495_PRINT_FINGER=RIGHT_MIDDLE VFS495_PRINT_USER=$USER \
      python3 tools/vfs495_build_print.py /tmp/extra.print <five-good-scans...>
  # 4. install it as a second gallery print (additive; original stays untouched)
  sudo install -o root -g root -m 644 /tmp/extra.print \
      /var/lib/fprint/$USER/virtual_image/0/8 && sudo restorecon /var/lib/fprint/$USER/virtual_image/0/8
  ```
  Measured on held-out scans: 39/40 → 42/40 and 23/40 → 56/40 (MATCH), while
  genuinely bad swipes stayed bad (17/40, 6/40). The extra print appears in
  `fprintd-verify`'s list as a second finger (`right-middle-finger` here) because
  the filename must match the print's finger metadata; it is the same physical
  finger. Remove it with `sudo rm /var/lib/fprint/$USER/virtual_image/0/8`.
- **Image preprocessing does not help.** CLAHE, percentile stretch, gamma,
  unsharp and morphological variants of six archived scans moved scores by
  -8…+11 with no consistent sign; only one of four failing scans crossed 40 and
  others regressed. Nothing of the sort is applied by the bridge.
- **Suspend/resume hygiene (validated 2026-10-27).** The sleep hook stops the
  bridge before suspend (so no capture is ever killed mid-USB-session) and on
  resume re-enumerates the reader via sysfs unbind/bind (a soft replug — never
  `USBDEVFS_RESET`, which produced kernel descriptor errors -32/-71 here) before
  restarting it. Measured on a real S3 cycle: bridge idle again 2 s after resume,
  healthy frames (std 28), `verify-match` 20 s after resume — where the
  pre-hardening pipeline degenerated (std > 90) and wedged the sensor until a
  full power-off. The bridge also recovers on its own: a forced kill or two
  consecutive degenerate frames trigger the same unbind/bind mid-session.
- "Stuck state": after many rapid captures the sensor returns tiny scans
  (height < 180, e.g. 200x12/200x15). `MIN_ROWS=180` in the bridge rejects those
  and retries twice. A sensor that is *already wedged* (zero frames despite
  swipes) still needs a **full power-off**; warm reboot / USB re-enumeration
  does NOT heal it. The hardening (graceful shutdown + automatic re-enumeration)
  exists to stop the pipeline from reaching that state in the first place.
- Debug scores: `journalctl -u fprintd | grep 'score'` (threshold `n/40`).
  Raw last delivered image: `/run/vfs495-fprint/last.pgm` (root-only).

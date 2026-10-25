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
- **Quality gate.** The bridge rejects a frame when it is shorter than 180 rows,
  has clearly unusable pixel statistics (std > 85 or > 25 % saturated pixels), or
  covers less than 60 % of the frame with fingerprint (`cover=` in the log).
  Calibration on this sensor: every swipe at ≥ 61 % coverage matched
  (scores 40–122); every swipe at ≤ 58 % failed (best 39/40). The gate turns a
  guaranteed failed attempt into an immediate retry while the prompt is still
  open. Tune with `VFS495_MIN_COVER` (e.g. `65` during enrollment).
- Dry skin is the other big lever: ridge contrast (`std=`) drops and scores fall
  even at full coverage. Breathing on the fingertip fixed a 3/3 run here.
- Verify prompts are event-driven: fprintd signals `finger-needed` over D-Bus,
  the bridge starts exactly one capture, and a repeat `VerifyStart` inside one
  authentication re-delivers/retries. HP's tool is ready in ~0.5 s (measured),
  so there is nothing to wait for: start the swipe when the prompt appears, but
  keep it slow. The bridge retries up to 3 × 18 s inside one prompt.
- Repeated back-to-back captures can push the sensor into short/degraded scans and
  even trigger USB re-enumeration; the bridge waits 2.5 s before retrying.
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
- "Stuck state": after many rapid captures the sensor returns tiny scans
  (height < 180, e.g. 200x12/200x15). `MIN_ROWS=180` in the bridge rejects those
  and retries twice. Only a **full power-off** clears the stuck sensor; warm
  reboot / USB re-enumeration does NOT.
- Debug scores: `journalctl -u fprintd | grep 'score'` (threshold `n/40`).
  Raw last delivered image: `/run/vfs495-fprint/last.pgm` (root-only).

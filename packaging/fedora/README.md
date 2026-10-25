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
- **Quality gate.** The bridge rejects frames whose height is < 180 rows or whose
  pixel statistics are clearly unusable (std > 85 or > 25 % saturated pixels).
  Delivered real swipes measured std 34–80 / < 7 % saturated; the broken frame
  measured std 91–99 / 25–50 %. The gate is deliberately conservative: rejecting a
  good swipe costs an attempt, while delivering a bad one only costs one no-match.
- Verify prompts are event-driven: fprintd signals `finger-needed` over D-Bus,
  the bridge starts exactly one capture, and a repeat `VerifyStart` inside one
  authentication re-delivers/retries. Swipes made before the sensor arms (~2 s)
  are missed; swipe again.
- Repeated back-to-back captures can push the sensor into short/degraded scans and
  even trigger USB re-enumeration; the bridge waits 2.5 s before retrying.
- libfprint's bozorth3 threshold is 40; genuine full-length slow swipes score
  65–122 here, partial scans (height 194–271) often score < 40. See
  `docs/FINDINGS.md` and the score/height correlation traces in the journal
  (`journalctl -u fprintd | grep score`, `journalctl -u vfs495-bridge`).
- "Stuck state": after many rapid captures the sensor returns tiny scans
  (height < 180, e.g. 200x12/200x15). `MIN_ROWS=180` in the bridge rejects those
  and retries twice. Only a **full power-off** clears the stuck sensor; warm
  reboot / USB re-enumeration does NOT.
- Debug scores: `journalctl -u fprintd | grep 'score'` (threshold `n/40`).
  Raw last delivered image: `/run/vfs495-fprint/last.pgm` (root-only).

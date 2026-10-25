#!/usr/bin/env python3
"""Synchronize one fprintd verification with exactly one virtual-image PGM frame.

Run as the normal enrolled user, not root:
    python3 vfs495_verify_once.py --pgm /tmp/vfs495_fresh.pgm

The program uses sudo -n ONLY for a short-lived Unix-socket sender because
/run/fprint has root-only permissions in this project's systemd override.
It never modifies authentication settings or stored fingerprints.
"""
import argparse
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


def read_pgm(path):
    buf = Path(path).read_bytes()
    i = 0

    def token():
        nonlocal i
        while i < len(buf):
            if buf[i] in b' \t\r\n\f\v':
                i += 1
            elif buf[i] == 35:
                e = buf.find(b'\n', i)
                if e == -1:
                    raise ValueError('Incomplete PGM header comment')
                i = e + 1
            else:
                break
        a = i
        while i < len(buf) and buf[i] not in b' \t\r\n\f\v#':
            i += 1
        if a == i:
            raise ValueError('Missing PGM header token')
        return buf[a:i]

    if token() != b'P5':
        raise ValueError('Expected P5 grayscale PGM')
    w, h, maxval = (int(token()), int(token()), int(token()))
    if not (1 <= w <= 5000 and 1 <= h <= 5000 and maxval == 255):
        raise ValueError('Invalid 8-bit PGM dimensions/maxval')
    if i >= len(buf) or buf[i] not in b' \t\r\n\f\v':
        raise ValueError('Missing raster separator')
    i += 2 if buf[i:i+2] == b'\r\n' else 1
    pixels = buf[i:]
    if len(pixels) != w * h:
        raise ValueError(f'Wrong pixel count: {len(pixels)} versus {w*h}')
    return w, h, pixels


def send_only(args):
    w, h, pix = read_pgm(args.pgm)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(args.socket)
        s.sendall(struct.pack('=ii', w, h) + pix)
        print(f'SENT {w}x{h} ({len(pix)} pixels)', flush=True)
        s.settimeout(None)
        # Keep the socket open until the parent has received a verify result.
        sys.stdin.readline()
    return 0


def pump(tag, stream, results):
    try:
        for line in stream:
            results.put((tag, line.rstrip('\r\n')))
    finally:
        results.put((tag, None))


def main(args):
    if os.geteuid() == 0:
        print('ERROR: run the orchestrator as your normal enrolled Linux user, not with sudo.', file=sys.stderr)
        return 2
    try:
        w, h, pix = read_pgm(args.pgm)
    except (ValueError, OSError) as e:
        print(f'ERROR: invalid PGM: {e}', file=sys.stderr)
        return 2
    print(f'Target: {args.finger}; PGM: {args.pgm} ({w}x{h}); bytes={len(pix)}', flush=True)
    results = queue.Queue()
    verify = subprocess.Popen(
        ['stdbuf', '-oL', '-eL', 'fprintd-verify', '-f', args.finger],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    threading.Thread(target=pump, args=('VERIFY', verify.stdout, results), daemon=True).start()
    sender = None
    seen_start = False
    seen_verifying = False
    sent = False
    final = None
    verify_end = False
    sender_end = False
    deadline = time.monotonic() + args.timeout
    try:
        while time.monotonic() < deadline:
            try:
                tag, line = results.get(timeout=0.2)
            except queue.Empty:
                if verify.poll() is not None and verify_end:
                    break
                continue
            if line is None:
                if tag == 'VERIFY':
                    verify_end = True
                    if final is None:
                        print(f'[VERIFY] Process exited with code {verify.poll()} before a final result', flush=True)
                    break
                if tag == 'SENDER':
                    sender_end = True
                continue
            print(f'[{tag}] {line}', flush=True)
            if tag == 'VERIFY':
                if 'Verify started!' in line:
                    seen_start = True
                if 'Verifying:' in line:
                    seen_verifying = True
                if 'Verify result:' in line:
                    final = line
                    break
                if seen_start and seen_verifying and not sent:
                    # The root sender is restricted to connect+send; verify runs as the real user.
                    sender = subprocess.Popen(
                        ['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                         '--send-only', '--socket', args.socket, '--pgm', args.pgm],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, bufsize=1,
                    )
                    threading.Thread(target=pump, args=('SENDER', sender.stdout, results), daemon=True).start()
                    sent = True
        if final is None:
            print('No final verify result before timeout/exit.', flush=True)
        print(f'TEST SUMMARY: sent={sent}, sender_exited={sender_end}, result={final or "UNKNOWN"}', flush=True)
        return 0 if final and sent and 'verify-match (done)' in final else 1
    finally:
        if sender is not None:
            if sender.stdin:
                try:
                    sender.stdin.write('\n')
                    sender.stdin.flush()
                    sender.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                sender.wait(timeout=2)
            except subprocess.TimeoutExpired:
                sender.terminate()
        if verify.poll() is None:
            verify.terminate()
            try:
                verify.wait(timeout=3)
            except subprocess.TimeoutExpired:
                verify.kill()
                verify.wait()


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pgm', default='/tmp/vfs495_fresh.pgm')
    p.add_argument('--socket', default='/run/fprint/virtimg_sock')
    p.add_argument('--finger', default='right-index-finger')
    p.add_argument('--timeout', type=int, default=25)
    p.add_argument('--send-only', action='store_true', help=argparse.SUPPRESS)
    a = p.parse_args()
    try:
        sys.exit(send_only(a) if a.send_only else main(a))
    except Exception as ex:
        print(f'ERROR: {type(ex).__name__}: {ex}', file=sys.stderr)
        sys.exit(2)

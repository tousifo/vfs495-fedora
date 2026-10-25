#!/usr/bin/env python3
"""VFS495/libfprint persistent virtual-image socket probe.

Runs locally on the fingerprint host. Does not capture fingerprints or change
any fprintd/SELinux settings. Requires an existing binary P5/8-bit PGM file.
"""
import argparse
import os
import socket
import struct
import sys
import time
from pathlib import Path


def read_pgm(path):
    blob = Path(path).read_bytes()
    pos = 0

    def token():
        nonlocal pos
        while pos < len(blob):
            if blob[pos] in b' \t\r\n\v\f':
                pos += 1
            elif blob[pos] == ord('#'):
                end = blob.find(b'\n', pos)
                if end < 0:
                    raise ValueError('Unterminated PGM comment')
                pos = end + 1
            else:
                break
        start = pos
        while pos < len(blob) and blob[pos] not in b' \t\r\n\v\f#':
            pos += 1
        if start == pos:
            raise ValueError('Missing PGM header token')
        return blob[start:pos]

    if token() != b'P5':
        raise ValueError('Expected binary PGM (P5), not P2 or another format')
    try:
        w = int(token())
        h = int(token())
        maxval = int(token())
    except ValueError as exc:
        raise ValueError('Malformed PGM dimensions/maxval') from exc
    if w < 1 or h < 1 or w > 5000 or h > 5000:
        raise ValueError(f'Invalid dimensions {w}x{h}')
    if maxval != 255:
        raise ValueError(f'Expected 8-bit PGM maxval 255, got {maxval}')
    if pos >= len(blob) or blob[pos] not in b' \t\r\n\v\f':
        raise ValueError('Missing whitespace delimiter after PGM header')
    # PGM spec: exactly one whitespace character separates maxval from raster;
    # treat a CRLF line ending as one delimiter.
    if blob[pos:pos+2] == b'\r\n':
        pos += 2
    else:
        pos += 1
    pixels = blob[pos:]
    if len(pixels) != w*h:
        raise ValueError(f'Pixel length mismatch: expected {w*h}, received {len(pixels)}')
    return w, h, pixels


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--socket', default='/run/fprint/virtimg_sock')
    ap.add_argument('--pgm', default='/tmp/vfs495_cap.pgm')
    ap.add_argument('--count', type=int, default=5, help='maximum images to send')
    ap.add_argument('--interval', type=float, default=0.0,
                    help='seconds between sends; 0 means wait for Enter before each send')
    args = ap.parse_args()
    if args.count < 1 or args.count > 100:
        ap.error('--count must be between 1 and 100')
    if args.interval < 0:
        ap.error('--interval must be >= 0')
    print('This uses one connection for all frames. Start fprintd-enroll first.', flush=True)
    print('PGM images may contain biometric data: do not upload without considering privacy.', flush=True)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(args.socket)
        s.settimeout(None)
        print(f'Connected to {args.socket}', flush=True)
        try:
            for i in range(args.count):
                if args.interval == 0:
                    input(f'[{i+1}/{args.count}] Press Enter to send PGM after enrollment prompts for a scan (Ctrl+C exits): ')
                elif i:
                    time.sleep(args.interval)
                w, h, pixels = read_pgm(args.pgm)  # reload to support new captures
                print(f'PGM: {w}x{h}, {len(pixels)} bytes; range {min(pixels)}..{max(pixels)}', flush=True)
                s.sendall(struct.pack('=ii', w, h) + pixels)
                print(f'Sent image {i+1} on same socket', flush=True)
            print('Frames sent. Check enroll output before ending the connection.', flush=True)
            if args.interval == 0:
                input('Press Enter to close the probe after enrollment is complete or cancelled: ')
        finally:
            s.close()
    except (OSError, ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f'Probe ended: {exc or type(exc).__name__}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())

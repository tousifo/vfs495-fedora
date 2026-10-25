#!/usr/bin/env python3
"""Feed DISTINCT pre-captured PGM scans to libfprint virtual_image on one socket.

Run fprintd-enroll -f right-index-finger as your ordinary user in Terminal A.
Run this sender with sudo -n in Terminal B. Press Enter for each new stage.
It never captures hardware, deletes enrollments, or changes system settings.
"""
import argparse
import hashlib
import re
import socket
import struct
import sys
from pathlib import Path


def read_pgm(path):
    blob = path.read_bytes()
    pos = 0
    def token():
        nonlocal pos
        while pos < len(blob):
            if blob[pos] in b' \t\r\n\v\f':
                pos += 1
            elif blob[pos] == ord('#'):
                end = blob.find(b'\n', pos)
                if end == -1:
                    raise ValueError('Unterminated PGM comment')
                pos = end + 1
            else:
                break
        start = pos
        while pos < len(blob) and blob[pos] not in b' \t\r\n\v\f#':
            pos += 1
        if start == pos:
            raise ValueError('Missing PGM token')
        return blob[start:pos]
    if token() != b'P5':
        raise ValueError('Expected P5 binary PGM')
    w, h, maxval = int(token()), int(token()), int(token())
    if not (1 <= w <= 5000 and 1 <= h <= 5000 and maxval == 255):
        raise ValueError('Invalid dimensions or bit depth')
    if pos >= len(blob) or blob[pos] not in b' \t\r\n\v\f':
        raise ValueError('Missing PGM raster delimiter')
    pos += 2 if blob[pos:pos+2] == b'\r\n' else 1
    pixels = blob[pos:]
    if len(pixels) != w*h:
        raise ValueError(f'Bad pixel count: got {len(pixels)}, expected {w*h}')
    return w, h, pixels


def sort_key(path):
    m = re.search(r'(\d+)(?=\.pgm$)', path.name)
    return (int(m.group(1)) if m else 999999, path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scans-dir', default=str(Path.home() / 'vfs495-linux/test-scans'))
    parser.add_argument('--socket', default='/run/fprint/virtimg_sock')
    parser.add_argument('--pattern', default='scan_*.pgm')
    args = parser.parse_args()

    directory = Path(args.scans_dir)
    paths = sorted(directory.glob(args.pattern), key=sort_key)
    if not paths:
        parser.error(f'No scan files found in {directory} matching {args.pattern}')

    scans = []
    seen = {}
    for path in paths:
        try:
            w, h, pixels = read_pgm(path)
        except (OSError, ValueError) as exc:
            parser.error(f'{path.name}: {exc}')
        digest = hashlib.sha256(pixels).hexdigest()
        if digest in seen:
            parser.error(f'Duplicate pixel data: {seen[digest]} and {path.name}. Capture a fresh swipe.')
        seen[digest] = path.name
        scans.append((path, w, h, pixels, digest))

    print(f'{len(scans)} distinct PGM images ready. Each image is sent once.', flush=True)
    for path, w, h, _, digest in scans:
        print(f'  {path.name}: {w}x{h}, pixel sha256={digest[:16]}', flush=True)
    print('Biometric images stay on this computer. Start fprintd-enroll in Terminal A FIRST.', flush=True)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(args.socket)
        print(f'Connected to {args.socket}', flush=True)
        for n, (path, w, h, pixels, digest) in enumerate(scans, 1):
            try:
                answer = input(f'[{n}/{len(scans)}] After Terminal A requests another scan, Enter=send {path.name}; q=quit: ').strip().lower()
            except EOFError:
                print('No input; closing socket', flush=True)
                return 0
            if answer == 'q':
                print('Stopped without sending additional images.', flush=True)
                return 0
            if answer:
                print('Only Enter or q is accepted; closing without sending.', flush=True)
                return 1
            try:
                s.sendall(struct.pack('=ii', w, h) + pixels)
            except BrokenPipeError:
                print('Socket closed by fprintd (possibly enrollment ended); inspect Terminal A.', file=sys.stderr)
                return 1
            print(f'SENT {path.name}: {w}x{h}, sha256={digest[:16]}', flush=True)
        print('All distinct scans sent. If enrollment is unfinished, capture additional images; do not replay scans.', flush=True)
        try:
            input('Press Enter to close after Terminal A finishes or is cancelled: ')
        except EOFError:
            pass
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, KeyboardInterrupt) as exc:
        print(f'Feeder stopped: {exc or type(exc).__name__}', file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Regenerates the decoder's test fixtures with the reference zstd CLI.

Run: python3 zstd-decoder/src/test/fixtures/generate.py. It writes the .zst files,
dictionaries and MANIFEST into zstd-decoder/src/test/resources/zstd/. Each input is chosen to
reach a different part of the format (see the comments); the MANIFEST records each fixture's
decoded size and SHA-256, so the inputs themselves are not stored.
"""
import hashlib
import os
import random
import shutil
import struct
import subprocess
import tempfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'resources', 'zstd')
WORDS = ('the of and to in is that for it as with was on be by at this from or an are not have '
         'proxy request response header body chunk socket thread virtual connection server client '
         'cache window frame block literal sequence offset match length huffman entropy table').split()


def text(r, n):
    out = []
    size = 0
    while size < n:
        w = r.choice(WORDS) + ('\n' if r.random() < 0.08 else ' ')
        out.append(w)
        size += len(w)
    return ''.join(out).encode()[:n]


def zstd(args, data):
    return subprocess.run(['zstd', '-q', '-c'] + args, input=data, capture_output=True, check=True).stdout


def zstd_file(args, data, work):
    path = os.path.join(work, 'input')
    with open(path, 'wb') as f:
        f.write(data)
    return subprocess.run(['zstd', '-q', '-c'] + args + [path], capture_output=True, check=True).stdout


def main():
    os.makedirs(OUT, exist_ok=True)
    r = random.Random(20261008)
    manifest = []
    work = tempfile.mkdtemp()

    def add(name, data, args, stdin=False, dictionary=None, frames=None):
        if frames is None:
            extra = ['-D', os.path.join(OUT, dictionary)] if dictionary else []
            frames = zstd(args + extra, data) if stdin else zstd_file(args + extra, data, work)
        with open(os.path.join(OUT, name + '.zst'), 'wb') as f:
            f.write(frames)
        manifest.append('%s %d %s %s' % (name, len(data), hashlib.sha256(data).hexdigest(), dictionary or '-'))

    prose = text(r, 200_000)
    add('empty', b'', ['-3'])                                         # single segment, empty raw block
    add('byte', b'a', ['-3'])                                         # one-byte content size
    add('prose-1', prose, ['-1'])                                     # predefined and FSE tables, 4 streams
    add('prose-19', prose, ['-19'])                                   # optimal parser: repeat offsets, treeless literals
    add('prose-22-long', prose * 2, ['--ultra', '-22', '--long=24'])  # large window
    add('prose-stream', prose, ['-3', '--no-check'], stdin=True)      # no content size, no checksum
    add('prose-tiny-window', prose, ['--zstd=wlog=10'])               # 1 KiB window: history buffer shifts
    add('prose-rle-tables', prose[:60000], ['-6', '--zstd=wlog=12,hlog=10'])
    add('zeros', bytes(1_000_000), ['-3'])                            # long overlapping matches
    add('random', bytes(r.getrandbits(8) for _ in range(20_000)), ['-3'])  # raw blocks
    runs = b''.join(bytes([r.randrange(256)]) * r.randrange(1, 300) for _ in range(800))
    add('runs', runs, ['-6', '--zstd=wlog=12,hlog=10'])               # RLE-mode sequence tables
    add('few-symbols', bytes(r.choices(range(3), [1, 1 / 8, 1 / 27], k=4000)), ['-19'])  # direct Huffman weights
    chunk = bytes(r.getrandbits(8) for _ in range(5000))
    parts = [chunk]
    for _ in range(400):
        s = r.randrange(0, 4000)
        parts.append(chunk[s:s + r.randrange(200, 1000)] + b'x')
    add('rle-literals', b''.join(parts), ['-19'])                     # RLE literals section
    vocab = [bytes(r.getrandbits(8) for _ in range(3)) for _ in range(8)]
    tokens = b''.join(r.choice(vocab) + bytes([r.randrange(256)]) for _ in range(34000))
    add('many-sequences', tokens, ['--zstd=mml=3,strat=9'])           # three-byte sequence count

    mixed = b''.join(prose[i:i + 3000] + bytes(r.getrandbits(8) for _ in range(2000)) for i in range(0, 36000, 3000))
    add('mixed-fast', mixed, ['--fast=5'])                            # large raw literals sections
    skewed = bytes(r.choices(range(40), [1 / (i + 1) ** 1.5 for i in range(40)], k=150_000))
    add('skewed-3', skewed, ['-3'])                                   # 4-byte literal headers, treeless
    add('skewed-19', skewed, ['-19'])                                 # 5-byte literal headers
    parts = [chunk]
    for _ in range(1000):
        s = r.randrange(0, 4000)
        parts.append(chunk[s:s + r.randrange(200, 1000)] + b'x')
    add('rle-literals-long', b''.join(parts), ['-19'])
    add('runs-3', runs, ['-3'])                                       # RLE offsets table
    tokens = b''.join(r.choice(vocab) + bytes([r.randrange(256)]) for _ in range(70000))
    add('many-sequences-long', tokens, ['--zstd=mml=3,strat=9'])      # more than 0x7F00 sequences in a block
    records = b''.join(b'{"id":%d,"name":"user%04d","score":%d,"ok":%s}\n' % (
        i, r.randrange(10000), r.randrange(100), r.choice([b'true', b'false'])) for i in range(6000))
    add('records', records, ['-19'])                                  # repeat offset "rep0 - 1"
    ints = b''.join(r.randrange(0, 1 << 20).to_bytes(4, 'little') for _ in range(8000))
    add('ints', ints, ['-19'])                                        # RLE match lengths table

    small = b'hello, zstd\n'
    skippable = struct.pack('<II', 0x184D2A5A, 5) + b'skip!'
    add('two-frames', prose[:5000] + small, [],
        frames=zstd(['-3'], prose[:5000]) + skippable + zstd(['-3'], small))

    samples = []
    for i in range(300):
        samples.append(('{"id": %d, "user": "u%d", "tags": ["%s"], "active": %s}\n' % (
            i, r.randrange(10000), r.choice(WORDS), r.choice(['true', 'false']))).encode() * 3)
    sample_paths = []
    for i, s in enumerate(samples):
        path = os.path.join(work, 'sample%03d' % i)
        with open(path, 'wb') as f:
            f.write(s)
        sample_paths.append(path)
    subprocess.run(['zstd', '-q', '-f', '--train', '--maxdict=2048', '-o', os.path.join(OUT, 'trained.dict')]
                   + sample_paths, check=True, capture_output=True)
    with open(os.path.join(OUT, 'raw.dict'), 'wb') as f:
        f.write(b''.join(samples[:5]))
    add('dict-trained', samples[250], ['-3'], dictionary='trained.dict')
    add('dict-trained-19', samples[251] + samples[252], ['-19'], dictionary='trained.dict')
    add('dict-raw', samples[250], ['-3'], dictionary='raw.dict')

    version = subprocess.run(['zstd', '--version'], capture_output=True, text=True).stdout.strip()
    with open(os.path.join(OUT, 'MANIFEST'), 'w') as f:
        f.write('# name decoded-size sha256 dictionary; generated by src/test/fixtures/generate.py\n')
        f.write('# with %s\n' % version)
        f.write('\n'.join(manifest) + '\n')
    shutil.rmtree(work)


if __name__ == '__main__':
    main()

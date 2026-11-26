#!/usr/bin/env python3
"""Write the canonical capsule archive recipe documented in keccak-004/capsule/README.md.

Sorted relative names (including capsule.json), regular USTAR members only,
mode 0644, uid/gid/mtime 0, empty owner/group names, implicit directories;
gzip level 9, mtime 0, empty filename. Producer tooling only: the gate never
runs it and it selects nothing. Reproducing the keccak-004 archive digest
from its extracted capsule checks the recipe.

usage: python3 -I -B pack_archive.py CAPSULE_DIR OUTPUT.tar.gz
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path


def main(capsule, output):
    capsule, output = Path(capsule).absolute(), Path(output).absolute()
    if output.exists():
        raise SystemExit('output exists')
    index = json.loads((capsule / 'capsule.json').read_bytes())
    names = sorted([*index['files'], 'capsule.json'])
    found = sorted(p.relative_to(capsule).as_posix() for p in capsule.rglob('*') if p.is_file())
    if found != names:
        raise SystemExit('capsule file inventory differs from capsule.json')
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in names:
            data = (capsule / name).read_bytes()
            if name != 'capsule.json' and hashlib.sha256(data).hexdigest() != index['files'][name]:
                raise SystemExit('capsule payload changed: ' + name)
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o644, 0, 0, 0
            info.uname = info.gname = ''
            info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))
    stream = raw.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', compresslevel=9, fileobj=out, mtime=0) as gz:
        gz.write(stream)
    output.write_bytes(out.getvalue())
    print(json.dumps({'members': len(names), 'payload_bytes': sum((capsule / n).stat().st_size for n in names),
                      'ustar_bytes': len(stream), 'compressed_bytes': len(out.getvalue()),
                      'archive_sha256': hashlib.sha256(out.getvalue()).hexdigest(),
                      'capsule_sha256': hashlib.sha256((capsule / 'capsule.json').read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main(*sys.argv[1:])

#!/usr/bin/env python3
"""Authenticate and extract a selected regular-file USTAR capsule, without tools."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import unicodedata

HERE = Path(__file__).absolute().parent
SCHEMA = 'microproxy.keccak004-retained-capsule/1'
SCOPE = 'retained-Darwin-arm64-cold-evidence-only'


class CapsuleError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CapsuleError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def expected_digest(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
            'explicit external SHA256 digest required')
    return value


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute canonical input/output path required')
    for item in [path, *path.parents]:
        require(not item.is_symlink(), 'symlink input/output path forbidden')
    return path


def identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino


def output_admission(output, archive):
    output = absolute(output)
    require(not os.path.lexists(output), 'fresh output required')
    require(output.parent.is_dir(), 'output parent must already exist')
    ancestors = {identity(p) for p in output.parents if p.exists()}
    for source in [archive.parent, HERE]:
        source = absolute(source)
        require(not output.is_relative_to(source) and not source.is_relative_to(output)
                and identity(source) not in ancestors, 'output overlaps archive/source directory')
    return output


def member_path(name):
    require(isinstance(name, str) and name and not name.startswith('/') and
            '\\' not in name and ':' not in name and
            not any(ord(c) < 32 or ord(c) == 127 for c in name), 'unsafe member path')
    parts = name.split('/')
    require(all(p not in ('', '.', '..') for p in parts), 'unsafe member path')
    require(unicodedata.normalize('NFC', name) == name, 'noncanonical member path alias')
    return parts


def regular_members(compressed):
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as error:
        raise CapsuleError('invalid gzip envelope') from error
    require(len(raw) % 512 == 0, 'truncated tar blocks')
    members, aliases = {}, {}
    position = 0
    while position < len(raw):
        header = raw[position:position + 512]
        if header == bytes(512):
            require(len(raw) - position >= 1024 and not any(raw[position:]),
                    'invalid tar end marker or nonzero trailing data')
            break
        try:
            info = tarfile.TarInfo.frombuf(header, encoding='utf-8', errors='strict')
        except (tarfile.HeaderError, UnicodeError, ValueError) as error:
            raise CapsuleError('invalid tar header') from error
        require(header[257:263] == b'ustar\0', 'unsupported tar header format')
        require(info.type in (tarfile.REGTYPE, tarfile.AREGTYPE), 'only regular tar members allowed')
        parts = member_path(info.name)
        require(info.name not in members, 'duplicate tar member')
        for length in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:length])
            folded = unicodedata.normalize('NFC', prefix.casefold())
            require(folded not in aliases or aliases[folded] == prefix, 'member case alias')
            aliases[folded] = prefix
        require(info.size >= 0, 'invalid tar member size')
        start = position + 512
        end = start + info.size
        position = start + ((info.size + 511) // 512) * 512
        require(position <= len(raw) and not any(raw[end:position]), 'truncated tar payload/padding')
        members[info.name] = raw[start:end]
    else:
        raise CapsuleError('missing tar end marker')
    require(members, 'empty tar capsule')
    for name in members:
        require(not any('/'.join(name.split('/')[:i]) in members
                        for i in range(1, len(name.split('/')))), 'tar file/directory conflict')
    return members


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def authenticate_capsule(members, expected):
    require('capsule.json' in members, 'missing capsule.json')
    require(digest(members['capsule.json']) == expected, 'capsule digest mismatch')
    try:
        capsule = json.loads(members['capsule.json'], object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CapsuleError('invalid capsule JSON') from error
    require(type(capsule) is dict and set(capsule) ==
            {'schema', 'qualification', 'scope', 'policy_map_sha256', 'root_map', 'files'} and
            capsule['schema'] == SCHEMA and capsule['qualification'] is False and
            capsule['scope'] == SCOPE and type(capsule['root_map']) is dict,
            'capsule schema/scope mismatch')
    expected_digest(capsule['policy_map_sha256'])
    files = capsule['files']
    require(type(files) is dict and files, 'invalid capsule file inventory')
    require('capsule.json' not in files, 'capsule cannot index itself')
    for name, pin in files.items():
        member_path(name)
        expected_digest(pin)
    require(set(members) == set(files) | {'capsule.json'}, 'capsule payload inventory mismatch')
    for name, pin in files.items():
        require(digest(members[name]) == pin, 'capsule payload digest mismatch: ' + name)
    return {**files, 'capsule.json': expected}


def extract_capsule(archive, expected_archive_sha256, expected_capsule_sha256, output):
    expected_archive_sha256 = expected_digest(expected_archive_sha256)
    expected_capsule_sha256 = expected_digest(expected_capsule_sha256)
    archive = absolute(archive)
    metadata = archive.stat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, 'archive must be regular without hardlink alias')
    compressed = archive.read_bytes()
    require(digest(compressed) == expected_archive_sha256, 'archive digest mismatch')
    output = output_admission(output, archive)
    members = regular_members(compressed)
    wanted = authenticate_capsule(members, expected_capsule_sha256)
    # All compressed bytes, headers, paths, payloads and the exact index are checked
    # before the first directory is created. No tar extraction API is used.
    output.mkdir(mode=0o700)
    for name, raw in sorted(members.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(target, flags, 0o644)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
    actual = {}
    for path in output.rglob('*'):
        value = path.lstat()
        require(not stat.S_ISLNK(value.st_mode), 'extracted symlink forbidden')
        if stat.S_ISDIR(value.st_mode):
            continue
        require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, 'extracted special/alias forbidden')
        actual[path.relative_to(output).as_posix()] = digest(path.read_bytes())
    require(actual == wanted, 'extracted capsule file map differs')
    after = archive.stat()
    require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
            == (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns, 1)
            and digest(archive.read_bytes()) == expected_archive_sha256,
            'archive changed during extraction')
    return {'schema': 'microproxy.keccak004-capsule-extraction/1', 'status': 'complete',
            'qualification': False, 'scope': 'capsule-delivery-only', 'archive': str(archive),
            'archive_sha256': expected_archive_sha256, 'capsule_sha256': expected_capsule_sha256,
            'compressed_bytes': len(compressed), 'regular_members': len(members),
            'payload_bytes': sum(map(len, members.values())), 'output': str(output),
            'archive_before_after_match': True, 'parent_policy_admission': 'separate required step'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-archive-sha256', required=True)
    parser.add_argument('--expected-capsule-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = extract_capsule(args.archive, args.expected_archive_sha256,
                             args.expected_capsule_sha256, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (CapsuleError, OSError) as error:
        print('CAPSULE EXTRACTION FAILED: ' + str(error), file=__import__('sys').stderr)
        raise SystemExit(1)

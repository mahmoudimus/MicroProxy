"""Small data and raw-source admission helpers; no proof authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    path = Path(path).absolute()
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError('symlink input component: ' + str(cursor))
    if not path.is_file():
        raise ValueError('missing regular input: ' + str(path))
    return path


def relative(name):
    p = Path(name)
    if p.is_absolute() or not p.parts or any(x in ('.', '..') for x in p.parts) or '\\' in name:
        raise ValueError('noncanonical relative input: ' + name)
    return p


def load_module(name, path, expected):
    """Compile the SAME authenticated bytes; SourceFileLoader/.pyc is never used."""
    path = regular(path)
    raw = path.read_bytes()
    if digest(raw) != expected:
        raise ValueError('raw Python source pin mismatch: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def authenticate(repo, manifest, expected):
    raw = regular(manifest).read_bytes()
    if digest(raw) != expected:
        raise ValueError('externally selected manifest hash mismatch')
    data = json.loads(raw)
    if data['schema'] != 'microproxy.hkdf-source-traces-inputs/v2':
        raise ValueError('unsupported HKDF manifest schema')
    for name, pin in data['inputs'].items():
        if sha(regular(repo / relative(name))) != pin:
            raise ValueError('authenticated input mismatch: ' + name)
    # New executable/helper/control files cannot be silently omitted from pins.
    component = repo / 'formal/source/hkdf'
    actual = {str(p.relative_to(repo)) for p in component.rglob('*')
              if p.is_file() and not (p.suffix == '.pyc' and '__pycache__' in p.parts)
              and p != manifest
              and p != component / 'SOURCE-EVIDENCE-v2.json'
              }
    selected = {n for n in data['inputs'] if n.startswith('formal/source/hkdf/')}
    if actual != selected:
        raise ValueError('incomplete/extra HKDF package input map')
    return data


def apply_recipe(base, recipe):
    if digest(base.encode()) != recipe['base_sha256']:
        raise ValueError('mutation base drift')
    lines = base.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(recipe['edits']):
        start, end = edit['start'], edit['end']
        if not 0 <= start <= end <= previous or lines[start:end] != edit['old']:
            raise ValueError('overlapping/wrong mutation edit')
        lines[start:end] = edit['new']
        previous = start
    result = ''.join(lines)
    if digest(result.encode()) != recipe['sha256']:
        raise ValueError('materialized mutation pin mismatch')
    return result


def child_environment(root):
    root = Path(root)
    for name in ('home', 'tmp', 'config', 'cache'):
        (root / name).mkdir(parents=True, exist_ok=False)
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'HOME': str(root / 'home'), 'TMPDIR': str(root / 'tmp'),
            'TMP': str(root / 'tmp'), 'TEMP': str(root / 'tmp'),
            'XDG_CONFIG_HOME': str(root / 'config'), 'XDG_CACHE_HOME': str(root / 'cache')}


def output_isolation_error(output, roots):
    """Reject both containment directions against every declared input/tool root.

    This is a read-only check. The caller must perform it before creating even
    its output root, private HOME or build directories.
    """
    output = Path(output)
    if not output.is_absolute():
        return 'output must be absolute'
    cursor = Path(output.anchor)
    for part in output.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            return 'output has a symlink component'
    resolved = output.resolve(strict=False)
    for label, root in roots.items():
        # Compare lexical and resolved spellings. A tool launcher alias must
        # not make its actual installation writable as the output directory.
        lexical = Path(os.path.abspath(root))
        for protected in (lexical, lexical.resolve(strict=False)):
            if resolved.is_relative_to(protected) or protected.is_relative_to(resolved):
                return 'output overlaps input/tool root in either direction: ' + label
    if output.exists():
        return 'output already exists'
    if any(os.path.lexists(p / '.git') for p in resolved.parents):
        return 'output has a Git ancestor'
    return None


def tree_snapshot(root):
    """Snapshot a JDK tree without following any symlink, including directories.

    Values are typed triples: [file, {size,mode}, SHA256],
    [directory, {mode}, null], [symlink, literal-link-text, null]. Link targets
    must be lexically inside the selected tree; target contents are captured at
    their own regular paths, never through the link. Broken/cyclic internal
    links are recorded literally, not traversed. Special files fail closed.
    """
    root = Path(root)
    if not root.is_absolute():
        raise ValueError('JDK snapshot root must be absolute')
    cursor = Path(root.anchor)
    for part in root.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError('symlink JDK root/ancestor')
    if not root.is_dir():
        raise ValueError('missing JDK directory')
    result = {}

    def visit_fd(fd, directory):
        # os.scandir on an FD does not follow a replacement of directory's path.
        # Use dir_fd for every metadata/open operation below for the same reason.
        with os.scandir(fd) as listing:
            names = sorted(entry.name for entry in listing)
        for name in names:
            path = directory / name
            rel = str(path.relative_to(root))
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(name, dir_fd=fd)
                if not Path(os.path.abspath(path.parent / target)).is_relative_to(root):
                    raise ValueError('JDK symlink escapes selected tree: ' + rel)
                result[rel] = ['symlink', target, None]
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    current = os.fstat(child)
                    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError('JDK directory changed during snapshot')
                    result[rel] = ['directory', {'mode': stat.S_IMODE(current.st_mode)}, None]
                    visit_fd(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                with os.fdopen(child, 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                        raise ValueError('JDK file changed during snapshot')
                    value = hashlib.file_digest(stream, 'sha256').hexdigest()
                    after = os.fstat(stream.fileno())
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise ValueError('JDK file changed while hashing')
                    result[rel] = ['file', {'size': after.st_size, 'mode': stat.S_IMODE(after.st_mode)}, value]
            else:
                raise ValueError('special JDK tree entry: ' + rel)

    # The root itself is opened without following a link. No walk follows a
    # symbolic directory, hashes a link target, or enters an external tree.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        result['.'] = ['directory', {'mode': stat.S_IMODE(info.st_mode)}, None]
        visit_fd(fd, root)
    finally:
        os.close(fd)
    return dict(sorted(result.items()))

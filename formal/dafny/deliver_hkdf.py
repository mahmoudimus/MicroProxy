#!/usr/bin/env python3
"""Check or renew the committed generated-HKDF sources and their exact class hook.

Default mode is a drift gate: verify and translate the pinned kernel, then require the
committed production package to be byte-identical to fresh compiler output. `--update`
is the deliberate renewal path; it prints the reviewed change list, replaces only the
generated package, and rewrites `hkdf/GENERATED.json`. It never edits generated Java by
hand and never touches the SHAKE/ML-KEM namespaces.

`--jar PATH` additionally requires every generated/adapter class entry to exist in an
already-built JAR with the exact bytes compiled here. Class/JAR identity is only a
build-reproducibility check, not a proof of JVM behavior.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from zipfile import ZipFile

import run

HERE = run.HERE
ROOT = run.ROOT
GENERATED_PINS = HERE / 'hkdf' / 'GENERATED.json'
COMPILE_INPUTS = tuple(run.PRODUCTION_INPUTS)
JAVAC_ARGS = ['--release', '21', '-g:lines,vars,source', '-encoding', 'UTF-8',
              '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes']


def source_map(root):
    return {str(path.relative_to(root)): run.digest(path)
            for path in sorted(root.rglob('*.java'))}


def changes(old, new):
    return {
        'added': sorted(set(new) - set(old)),
        'removed': sorted(set(old) - set(new)),
        'changed': sorted(name for name in set(old) & set(new) if old[name] != new[name]),
    }


def print_changes(label, old, new):
    difference = changes(old, new)
    if not any(difference.values()):
        print(f'{label}: unchanged', flush=True)
        return False
    print(f'{label}:', flush=True)
    for name in difference['added']:
        print(f'  + {name} sha256={new[name]}', flush=True)
    for name in difference['removed']:
        print(f'  - {name} sha256={old[name]}', flush=True)
    for name in difference['changed']:
        print(f'  ~ {name} {old[name]} -> {new[name]}', flush=True)
    return True


def generate(dafny, workspace):
    output = workspace / run.OUTPUT_NAME
    status, log = run.execute(
        [dafny, 'translate', 'java', '--outer-module', run.OUTER_MODULE, '--output', output,
         HERE / 'hkdf/Hkdf.dfy', *run.FLAGS], workspace / 'generation.log', timeout=300)
    verified = run.check_verified(status, log, 21)
    generated = Path(str(output) + '-java')
    if not (generated / run.GENERATED_PACKAGE / '__default.java').is_file():
        raise RuntimeError('Pinned translation did not produce the expected package')
    aggregator = generated / f'{run.OUTPUT_NAME}.java'
    if not aggregator.is_file():
        raise RuntimeError('Pinned translation did not produce its top-level file')
    run.check_aggregator(aggregator)
    return generated, verified, aggregator, generated / f'{run.OUTPUT_NAME}-java.dtr'


def check_receipt(source, aggregator, metadata, classes):
    if not GENERATED_PINS.is_file():
        raise RuntimeError('Missing generated receipt; run with --update after review')
    receipt = json.loads(GENERATED_PINS.read_text())
    expected = {
        'schema': 'microproxy.hkdf-generated/v1',
        'outer_module': run.OUTER_MODULE,
        'output_name': run.OUTPUT_NAME,
        'module': run.GENERATED_MODULE,
        'source': source,
        'aggregator_sha256': run.digest(aggregator),
        'translation_metadata_sha256': run.digest(metadata),
        'classes': classes,
    }
    differences = sorted(name for name, value in expected.items() if receipt.get(name) != value)
    if differences:
        raise RuntimeError(f'Generated receipt is stale or changed: {differences}')


def compile_classes(java_home, runtime, generated, workspace):
    classes = workspace / 'classes'
    classes.mkdir()
    sources = [generated / run.GENERATED_PACKAGE / name
               for name in source_map(generated / run.GENERATED_PACKAGE)]
    sources += [ROOT / name for name in COMPILE_INPUTS]
    status, log = run.execute(
        [java_home / 'bin/javac', *JAVAC_ARGS, '-cp', runtime, '-d', classes, *sources],
        workspace / 'javac.log', timeout=300)
    if status or log.strip():
        raise RuntimeError('Generated/adapter Java compilation failed or warned: ' + log[-4000:])
    return run.snapshot(classes, '*.class')


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def check_jar(path, class_map):
    with ZipFile(path) as jar:
        names = {name for name in jar.namelist() if name.endswith('.class')}
        missing = sorted(set(class_map) - names)
        if missing:
            raise RuntimeError(f'JAR is missing compiled HKDF/adapter classes: {missing}')
        mismatched = sorted(name for name, sha in class_map.items()
                            if sha256_bytes(jar.read(name)) != sha)
        if mismatched:
            raise RuntimeError(f'JAR class bytes differ from pinned compilation: {mismatched}')


def update_inputs():
    path = HERE / 'inputs.json'
    old = json.loads(path.read_text())['inputs']
    pins = {name: run.digest(ROOT / name) for name in sorted(run.input_inventory())}
    changed = print_changes('inputs.json', old, pins)
    path.write_text(json.dumps({'schema': 1, 'inputs': pins}, indent=2) + '\n')
    return changed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update', action='store_true', help='replace the committed generated package')
    parser.add_argument('--update-inputs', action='store_true', help='renew inputs.json after review')
    parser.add_argument('--jar', type=Path, help='require exact class entries in this built JAR')
    parser.add_argument('--cache', type=Path,
                        default=Path(os.environ.get('MICROPROXY_FORMAL_CACHE', Path.home() / '.cache/microproxy-formal')))
    parser.add_argument('--java-home', type=Path,
                        default=Path(os.environ.get('JAVA_HOME', '')))
    args = parser.parse_args(argv)
    java_home = args.java_home.expanduser().resolve()
    if not (java_home / 'bin/javac').is_file():
        parser.error('Set JAVA_HOME (or pass --java-home) to a JDK 21+ installation')
    dafny, runtime, tools, asset = run.install(args.cache)
    with tempfile.TemporaryDirectory(prefix='hkdf-delivery-') as name:
        workspace = Path(name)
        status, version = run.execute([dafny, '--version'], workspace / 'dafny-version.log')
        if status or not version.strip().startswith(tools['version'] + '+'):
            raise RuntimeError('Unexpected Dafny version')
        generated, verified, aggregator, metadata = generate(dafny, workspace)
        fresh = source_map(generated / run.GENERATED_PACKAGE)
        committed = source_map(run.GENERATED_SOURCE)
        changed = print_changes('generated package', committed, fresh)
        classes = compile_classes(java_home, runtime, generated, workspace)
        if not args.update:
            check_receipt(fresh, aggregator, metadata, classes)
        if args.jar:
            check_jar(args.jar, classes)
            print(f'JAR hook: {args.jar} matches {len(classes)} pinned class entries', flush=True)
        if changed and not args.update:
            raise RuntimeError('Generated package drift; review above, then rerun with --update')
        if args.update:
            run.GENERATED_SOURCE.mkdir(parents=True, exist_ok=True)
            for name in set(committed) - set(fresh):
                (run.GENERATED_SOURCE / name).unlink()
            for name in fresh:
                target = run.GENERATED_SOURCE / name
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_suffix('.java.tmp')
                shutil.copyfile(generated / run.GENERATED_PACKAGE / name, temporary)
                temporary.replace(target)
            receipt = {
                'schema': 'microproxy.hkdf-generated/v1',
                'outer_module': run.OUTER_MODULE,
                'output_name': run.OUTPUT_NAME,
                'module': run.GENERATED_MODULE,
                'verified': verified,
                'dafny': {'version': tools['version'], 'asset_sha256': asset['sha256'],
                           'runtime_sha256': asset['runtime_sha256']},
                'javac': {'release': 21, 'args': JAVAC_ARGS},
                'source': fresh,
                'aggregator_sha256': run.digest(aggregator),
                'translation_metadata_sha256': run.digest(metadata),
                'classes': classes,
            }
            GENERATED_PINS.write_text(json.dumps(receipt, indent=2) + '\n')
            print(f'Updated {run.GENERATED_SOURCE} and {GENERATED_PINS}', flush=True)
        if args.update_inputs:
            update_inputs()
        elif changed:
            print('WARNING: inputs.json still pins the old generated sources; rerun with '
                  '--update-inputs after reviewing the change list', flush=True)
        if not args.update:
            print(f'Checked {len(fresh)} generated sources, {len(classes)} classes; '
                  f'{verified} proof obligations', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

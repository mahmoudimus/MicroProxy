#!/usr/bin/env python3
"""Check a minimized bundle against the full canonical library delivery receipt.

The receipt must come from delivery.py check in the same build. This checks
artifact identity and actual runtime loading, not a new cryptographic theorem.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import unquote, urlparse
from zipfile import ZipFile

import delivery

CRYPTO_PREFIXES = (
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/',
    'io/github/mahmoudimus/quic/internal/verifiedhkdf/',
    'io/github/mahmoudimus/verifiedcrypto/',
    'io/github/mahmoudimus/quic/Hkdf',
    'io/github/mahmoudimus/quic/tls/Shake',
    'io/github/mahmoudimus/quic/tls/MlKem768',
)
REQUIRED_ROOTS = {
    'io/github/mahmoudimus/quic/Hkdf.class',
    'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.class',
    'io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf/__default.class',
    'io/github/mahmoudimus/quic/internal/verifiedcrypto/NativeMlKem/__default.class',
    'io/github/mahmoudimus/verifiedcrypto/JdkHmac.class',
    'io/github/mahmoudimus/quic/tls/Shake.class',
    'io/github/mahmoudimus/quic/tls/MlKem768.class',
}
RESOURCES = ('META-INF/LICENSE-dafny.txt', 'META-INF/LICENSE-go-mlkem.txt', 'META-INF/NOTICE-crypto.txt')


def canonical_from_stage(stage, runtime, output):
    """Derive the full expected map from verified generation and strict source compilation.

    The full delivery check separately replays the proofs. Here we validate the
    same stage's inputs and regenerate the handwritten side of its class map;
    neither the library nor its declared receipt supplies the expected bytes.
    """
    manifest = json.loads((delivery.HERE / 'delivery.json').read_text())
    args = argparse.Namespace(stage=stage, runtime=runtime,
        cache=Path.home() / '.cache/microproxy-formal', timeout=1800)
    receipt, data = delivery.load_stage(args, manifest)
    delivery.production_sources(manifest, data['delivered_sources'])
    handwritten = delivery.compile_handwritten(delivery.ROOT / manifest['destination'],
        manifest['namespace'], Path(data['jdk_home']), [stage / 'classes', runtime],
        output, manifest['javac'], existing_generated_sources=manifest['existing_generated_sources'],
        existing_generated_dependencies=manifest.get('existing_generated_dependencies', {}))
    expected = dict(data['canonical_classes'])
    for name, value in handwritten['classes'].items():
        if name in expected and expected[name] != value:
            raise RuntimeError('Canonical provider class conflict: ' + name)
        expected[name] = value
    delivery.load_stage(args, manifest)
    if delivery.handwritten_inventory(delivery.ROOT / manifest['destination'],
            manifest['namespace'], manifest['existing_generated_sources']) != handwritten['sources']:
        raise RuntimeError('Handwritten source inventory changed during canonical compilation')
    return {'classes': expected, 'stage_receipt_sha256': delivery.digest(receipt),
            'generated_class_count': len(data['canonical_classes']),
            'handwritten_sources': len(handwritten['sources']), 'handwritten_lint': handwritten['lint'],
            'existing_generated_sources': manifest['existing_generated_sources'],
            'comparison': 'exact class bytes including all debug attributes'}, handwritten['sources']


def inspect(library, bundle, receipt, runtime, canonical):
    if any(receipt.get(key) != value for key, value in canonical.items()):
        raise RuntimeError('Delivery receipt differs from independently compiled canonical classes/stage')
    classes = receipt.get('classes')
    if (receipt.get('status') != 'checked' or not isinstance(classes, dict) or not classes
            or type(receipt.get('class_count')) is not int or receipt['class_count'] != len(classes)
            or any(not isinstance(h, str) or not delivery.SHA256.fullmatch(h) for h in classes.values())
            or delivery.digest(library) != receipt.get('jar_sha256')):
        raise RuntimeError('Require the full canonical class map and matching checked library JAR')
    if delivery.jar_class_map(library, ['']) != classes:
        raise RuntimeError('Library class entries differ from the canonical delivery receipt')
    expected = {n: h for n, h in classes.items() if n.startswith(CRYPTO_PREFIXES)}
    if not REQUIRED_ROOTS.issubset(expected):
        raise RuntimeError('Canonical receipt lacks required generated crypto roots')
    for path in (library, bundle):
        with ZipFile(path) as jar:
            names = jar.namelist()
            if len(names) != len(set(names)):
                raise RuntimeError('Duplicate JAR entries: ' + str(path))
            for name in names:
                override = re.fullmatch(r'META-INF/versions/[0-9]+/(.+\.class)', name)
                # module-info is declarative and ignored on this classpath. No
                # versioned executable class may override the smoke's code.
                if override and override[1] != 'module-info.class':
                    raise RuntimeError('Unverified multi-release class override: ' + name)
            for name in RESOURCES:
                source = delivery.ROOT / 'quic/src/main/resources' / name
                if jar.read(name) != source.read_bytes():
                    raise RuntimeError('Crypto license/notice differs: ' + name)
    if delivery.jar_class_map(bundle, CRYPTO_PREFIXES) != expected:
        raise RuntimeError('Minimized bundle crypto classes differ from canonical delivery')
    retained = delivery.jar_class_map(bundle, (
        'io/github/mahmoudimus/quic/', 'io/github/mahmoudimus/verifiedcrypto/'))
    if any(classes.get(name) != value for name, value in retained.items()):
        raise RuntimeError('Minimized bundle retained library class differs from canonical delivery')
    manifest = json.loads((delivery.HERE / 'delivery.json').read_text())
    delivery.check_runtime(runtime, manifest)
    runtime_classes = delivery.jar_class_map(runtime, ['dafny/'])
    bundled_runtime = delivery.jar_class_map(bundle, ['dafny/'])
    if not {'dafny/Helpers.class', 'dafny/TypeDescriptor.class', 'dafny/DafnySequence.class'}.issubset(bundled_runtime):
        raise RuntimeError('Minimized bundle lacks required runtime classes')
    if any(runtime_classes.get(name) != h for name, h in bundled_runtime.items()):
        raise RuntimeError('Minimized bundle runtime differs from the pinned Maven runtime')
    return {'crypto_classes': expected, 'retained_library_classes': retained, 'runtime_classes': bundled_runtime,
            'resources': {n: delivery.digest(delivery.ROOT / 'quic/src/main/resources' / n) for n in RESOURCES}}


def assert_load_origins(log, bundle, fixtures, harness):
    """Check every loaded project/runtime class, including non-crypto callees."""
    loaded = {}
    for owner, source in re.findall(r'\] (\S+) source: ([^\r\n]+)', log):
        if not owner.startswith(('io.github.mahmoudimus.', 'dafny.')):
            continue
        url = urlparse(source)
        if url.scheme != 'file':
            # HotSpot reports the host of generated lambda/type-switch classes
            # instead of a file URL. That host must already have passed the
            # ordinary origin check. These bootstraps remain JVM trust.
            generated = re.fullmatch(r'(.+)\$\$(?:Lambda|TypeSwitch)/0x[0-9a-fA-F]+', owner)
            host = generated[1] if generated else ''
            if (generated and source in loaded
                    and (host == source or host.startswith(source + '$'))):
                loaded[owner] = 'JVM generated class defined by ' + source
                continue
            raise RuntimeError('Unexpected class-load origin: ' + owner + ' ' + source)
        actual = Path(unquote(url.path)).resolve()
        entry = owner.replace('.', '/') + '.class'
        if entry in harness:
            expected = harness[entry]
        elif entry in fixtures:
            expected = fixtures[entry]
        else:
            expected = bundle
        if actual != expected.resolve():
            raise RuntimeError('Unexpected class-load origin: ' + owner + ' ' + source)
        loaded[owner] = source
    if not any(n.startswith('dafny.') for n in loaded) or not any('verifiedhkdf.' in n for n in loaded):
        raise RuntimeError('Class-load log lacks generated HKDF/runtime evidence')
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--delivery-receipt', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True,
                        help='same complete canonical stage used by delivery.py check')
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'microproxy.crypto-current-bundle/v1', 'status': 'incomplete',
              'scope': 'Complete scoped-crypto and retained QUIC-library class identity plus an origin-checked full-handshake smoke; other bundle dependencies and compiler/runtime/providers trusted. No timing or whole-system security theorem',
              'commands': []}

    def call(label, argv):
        result = subprocess.run(list(map(str, argv)), text=True, capture_output=True, timeout=180)
        text = result.stdout + result.stderr
        (out / (label + '.log')).write_text(text)
        report['commands'].append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode,
                                   'log_sha256': delivery.digest(out / (label + '.log'))})
        if result.returncode:
            raise RuntimeError(label + ' failed: ' + text[-2000:])
        return text

    try:
        sources = {name: path.resolve() for name, path in {
            'library.jar': args.library, 'bundle.jar': args.bundle, 'delivery.json': args.delivery_receipt,
            'runtime-reference.jar': args.runtime}.items()}
        report['artifact_inputs'] = {name: delivery.digest(path) for name, path in sources.items()}
        for name, path in sources.items():
            shutil.copy2(path, out / name)
        receipt = json.loads((out / 'delivery.json').read_text())
        canonical, handwritten_inputs = canonical_from_stage(args.stage.resolve(), out / 'runtime-reference.jar',
                                                            out / 'canonical-handwritten')
        report['canonical'] = canonical
        report['handwritten_inputs'] = handwritten_inputs
        report.update(inspect(out / 'library.jar', out / 'bundle.jar', receipt,
                              out / 'runtime-reference.jar', canonical))
        report['stage_receipt_sha256'] = receipt['stage_receipt_sha256']
        report['library_jar_sha256'] = report['artifact_inputs']['library.jar']
        report['bundle_jar_sha256'] = report['artifact_inputs']['bundle.jar']
        fixtures = delivery.class_map(delivery.ROOT / 'quic/target/test-classes', [
            'io/github/mahmoudimus/quic/tls/Handshakes', 'io/github/mahmoudimus/quic/tls/TestCerts'])
        if len(fixtures) < 4:
            raise RuntimeError('Missing handshake fixtures')
        delivery.freeze_inputs(delivery.ROOT / 'quic/target/test-classes', fixtures, out / 'fixtures')
        report['fixture_classes'] = fixtures
        junit = [Path.home() / '.m2/repository' / name for name in [
            'org/junit/jupiter/junit-jupiter-api/5.11.4/junit-jupiter-api-5.11.4.jar',
            'org/junit/platform/junit-platform-commons/1.11.4/junit-platform-commons-1.11.4.jar',
            'org/opentest4j/opentest4j/1.3.0/opentest4j-1.3.0.jar',
            'org/apiguardian/apiguardian-api/1.1.2/apiguardian-api-1.1.2.jar']]
        report['junit_inputs'] = {str(p): delivery.digest(p) for p in junit}
        report['test_trust'] = 'JUnit fixture assertions and compiler are trusted test inputs; hashes recorded, not a cryptographic proof'
        jdks = {}
        for i, path in enumerate(args.java_home):
            version = call('version-' + str(i), [path / 'bin/java', '-version'])
            major = re.search(r'version "(\d+)', version)[1]
            if major in jdks:
                raise RuntimeError('Duplicate JDK version')
            jdks[major] = path.resolve()
        if set(jdks) != {'21', '25'}:
            raise RuntimeError('Require JDK21 and25')
        report['jdk_inputs'] = {str(p): delivery.tool_tree(p) for p in jdks.values()}
        harness = out / 'harness'
        harness.mkdir()
        java_sources = [delivery.HERE / 'adoption' / n for n in ['HybridHandshakeBenchmark.java', 'HkdfHandshakeBenchmark.java']]
        report['source_inputs'] = {str(p.relative_to(delivery.ROOT)): delivery.digest(p)
                                  for p in [Path(__file__).resolve(), delivery.HERE / 'delivery.py', *java_sources]}
        cp = os.pathsep.join(map(str, [out / 'bundle.jar', out / 'fixtures', *junit, harness]))
        call('compile-harness', [jdks['21'] / 'bin/javac', '--release', '21', '-g', '-cp', cp, '-d', harness, *java_sources])
        report['harness_classes'] = delivery.class_map(harness, [''])
        report['runs'] = {}
        for major, jdk in jdks.items():
            log = call('jdk' + major + '-bundle-smoke', [jdk / 'bin/java',
                '-Xlog:class+load=info:file=' + str(out / ('jdk' + major + '-classload.log')),
                '-cp', cp, 'io.github.mahmoudimus.quic.tls.HkdfHandshakeBenchmark',
                out / 'bundle.jar', out / 'bundle.jar', out / 'fixtures', harness,
                'true', '0', '1', out / 'bundle.jar'])
            rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
            samples = [row for row in rows if 'completed_full_handshakes' in row]
            if len(samples) != 9 or any(row['completed_full_handshakes'] != 1 for row in samples):
                raise RuntimeError('Incomplete full-handshake smoke')
            report['runs'][major] = {'completed_full_handshakes': 9,
                'classload_sha256': delivery.digest(out / ('jdk' + major + '-classload.log'))}
            report['runs'][major]['loaded_classes'] = assert_load_origins(
                (out / ('jdk' + major + '-classload.log')).read_text(), out / 'bundle.jar',
                {n: out / 'fixtures' for n in fixtures},
                {n: harness for n in report['harness_classes']})
        for name, path in sources.items():
            if delivery.digest(path) != report['artifact_inputs'][name] or delivery.digest(out / name) != report['artifact_inputs'][name]:
                raise RuntimeError('Artifact changed during smoke: ' + name)
        delivery.check_pins(delivery.ROOT, report['source_inputs'])
        manifest = json.loads((delivery.HERE / 'delivery.json').read_text())
        if delivery.handwritten_inventory(delivery.ROOT / manifest['destination'], manifest['namespace'],
                manifest['existing_generated_sources']) != handwritten_inputs:
            raise RuntimeError('Handwritten source inventory changed during bundle acceptance')
        stage_args = argparse.Namespace(stage=args.stage.resolve(), runtime=out / 'runtime-reference.jar',
            cache=Path.home() / '.cache/microproxy-formal', timeout=1800)
        stage_receipt, _ = delivery.load_stage(stage_args, manifest)
        if delivery.digest(stage_receipt) != canonical['stage_receipt_sha256']:
            raise RuntimeError('Canonical stage changed during bundle acceptance')
        delivery.check_tree(out / 'fixtures', fixtures)
        delivery.check_tree(harness, report['harness_classes'])
        for p, h in report['junit_inputs'].items():
            if delivery.digest(Path(p)) != h:
                raise RuntimeError('JUnit changed during smoke')
        for p, hashes in report['jdk_inputs'].items():
            if delivery.tool_tree(Path(p)) != hashes:
                raise RuntimeError('JDK changed during smoke')
        report['status'] = 'complete'
    except BaseException as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(out / 'receipt.json')


if __name__ == '__main__':
    main()

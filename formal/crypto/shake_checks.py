#!/usr/bin/env python3
"""Scoped SHAKE proof/control/generated-Java replay; no production adoption claim.

Every included Dafny source is audited and verified as a root. Mutants and build
outputs are isolated below --output. A receipt is emitted only after every gate
passes and source, tool, generated-source, and class hashes remain unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import ssl
import subprocess
import sys
import tempfile
import _hashlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLCHAIN = ROOT / 'formal/dafny/toolchain.py'
EXPECTED_TESTS = {'vectors': 198, 'partitions': 198, 'slices': 24,
                  'word_cases': 36864, 'assertions': 47663}
FLAGS = ['--verification-time-limit', '30', '--resource-limit', '50000000', '--cores', '2']
SUMMARY = r'Dafny program verifier finished with (\d+) (?:assertions )?verified, (\d+) errors?\s*$'
BAD_DIAGNOSTIC = re.compile(r'warning:|timed out|time out|out of resource|resource limit|'
                            r'resolution/type errors|parse errors', re.I)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(paths, relative_to=None):
    return {str(p.relative_to(relative_to) if relative_to else p): sha(p)
            for p in sorted(set(paths))}


def tree(path, suffix='*'):
    return snapshot((p for p in path.rglob(suffix) if p.is_file()), path)


def closure(entry):
    """Resolve the complete local include graph, refusing a repository escape."""
    found = set()

    def visit(path):
        path = path.resolve()
        path.relative_to(ROOT)
        if path in found:
            return
        found.add(path)
        source = path.read_text()
        includes = re.findall(r'^\s*include\s+"([^"\n]+)"\s*$', source, re.M)
        if len(includes) != len(re.findall(r'^\s*include\b', source, re.M)):
            raise RuntimeError('Unsupported include syntax: '+str(path))
        for name in includes:
            visit(path.parent/name)

    visit(entry)
    return sorted(found)


def proof_result(status, output, negative=False):
    match = re.search(SUMMARY, output)
    if not match or BAD_DIAGNOSTIC.search(output):
        raise RuntimeError('Missing clean proof summary or forbidden diagnostic')
    verified, errors = map(int, match.groups())
    if negative:
        semantic = re.search(r'could not be proved|assertion might not hold', output)
        if status != 4 or errors < 1 or not semantic:
            raise RuntimeError('Expected an actual semantic verification failure')
    elif status != 0 or errors or verified < 1:
        raise RuntimeError('Expected nonempty, completely verified proof coverage')
    return {'verified': verified, 'errors': errors}


def vectors(path):
    """198 independent hashlib vectors spanning both sides of rate boundaries."""
    rows = []
    inventory = []
    for rate in (136, 168):
        sizes = (0, 1, 7, 8, rate-2, rate-1, rate, rate+1, 2*rate-1, 2*rate, 2*rate+1)
        lengths = (0, 1, 7, 8, rate-1, rate, rate+1, 2*rate, 2*rate+1)
        for size in sizes:
            data = bytes((131*i+17*size+rate) % 256 for i in range(size))
            for length in lengths:
                xof = hashlib.shake_128 if rate == 168 else hashlib.shake_256
                rows.append(f'{rate}\t{data.hex()}\t{xof(data).hexdigest(length)}\n')
                inventory.append({'rate': rate, 'input_bytes': size, 'output_bytes': length})
    if len(rows) != 198:
        raise RuntimeError('Vector inventory changed')
    path.write_text(''.join(rows))
    return inventory


# Mutations change executable behavior, leaving the mathematical specification
# intact. Caller-domain controls separately narrow only method preconditions.
CONTROLS = [
    ('padding-suffix', 'Shake', 'VerifiedShake.Pad.',
     'var lanes := XorByte(s.lanes,s.position,0x1f);',
     'var lanes := XorByte(s.lanes,s.position,0x06);'),
    ('padding-final-bit', 'Shake', 'VerifiedShake.Pad.',
     'lanes := XorByte(lanes,s.rate-1,0x80);',
     'lanes := XorByte(lanes,s.rate-1,0x00);'),
    ('padding-shared-octet', 'Shake', 'VerifiedShake.Pad.',
     'lanes := XorByte(lanes,s.rate-1,0x80);',
     'if s.position == s.rate-1 { lanes := s.lanes; }\n    lanes := XorByte(lanes,s.rate-1,0x80);'),
    ('zero-read-phase', 'Shake', 'VerifiedShake.Read.',
     'var initial := s;',
     'if length == 0 { r := S.ReadResult(s,[]); return; }\n    var initial := s;'),
    ('input-after-output', 'Shake', 'VerifiedShake.Update.',
     'if s.squeezing { r := S.InputAfterOutput; return; }\n    var current := s;',
     'if s.squeezing { r := S.Updated(s); return; }\n    var current := s;'),
    ('absorb-boundary', 'Shake', 'VerifiedShake.AbsorbOne.',
     'if s.position+1 == s.rate {', 'if s.position == s.rate {'),
    ('squeeze-boundary', 'Shake', 'VerifiedShake.Next.',
     'if ready.position == ready.rate {', 'if false {'),
    ('absorb-byte-order', 'Shake', 'VerifiedShake.XorByte.',
     '{ r := lanes[at/8 := lanes[at/8] ^ ((value as bv64) << (8*(at%8)))]; }',
     '{ r := lanes[at/8 := lanes[at/8] ^ ((value as bv64) << (8*(7-at%8)))]; }'),
    ('squeeze-byte-order', 'Shake', 'VerifiedShake.Next.',
     'var value := ((ready.lanes[ready.position/8] >> (8*(ready.position%8))) & 255) as bv8;',
     'var value := ((ready.lanes[ready.position/8] >> (8*(7-ready.position%8))) & 255) as bv8;'),
    ('domain-rates', 'Shake', 'ShakePublicDomain.AllRates.',
     'method New(rate: int) returns (r: S.State)\n    requires S.ValidRate(rate)',
     'method New(rate: int) returns (r: S.State)\n    requires rate == 136'),
    ('domain-states', 'Shake', 'ShakePublicDomain.AllReads.',
     'method Read(s: S.State, length: nat) returns (r: S.ReadResult)\n    requires S.Valid(s)',
     'method Read(s: S.State, length: nat) returns (r: S.ReadResult)\n    requires S.Valid(s) && s.position < s.rate'),
    ('domain-slices', 'Shake', 'ShakePublicDomain.AllSlices.',
     'method UpdateSlice(s: S.State, input: seq<bv8>, offset: int, length: int) returns (r: S.UpdateResult)\n    requires S.Valid(s)',
     'method UpdateSlice(s: S.State, input: seq<bv8>, offset: int, length: int) returns (r: S.UpdateResult)\n    requires S.Valid(s) && length >= 0'),
    ('domain-output-lengths', 'Shake', 'ShakePublicDomain.AllReads.',
     'method Read(s: S.State, length: nat) returns (r: S.ReadResult)\n    requires S.Valid(s)',
     'method Read(s: S.State, length: nat) returns (r: S.ReadResult)\n    requires S.Valid(s) && length > 0'),
    ('domain-input-lengths', 'Shake', 'ShakePublicDomain.AllUpdates.',
     'method {:isolate_assertions} Update(s: S.State, input: seq<bv8>) returns (r: S.UpdateResult)\n    requires S.Valid(s)',
     'method {:isolate_assertions} Update(s: S.State, input: seq<bv8>) returns (r: S.UpdateResult)\n    requires S.Valid(s) && |input| > 0'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=Path.home()/'.cache/microproxy-formal')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True,
                        help='Exactly two homes, JDK 21 followed by JDK 25')
    args = parser.parse_args()
    if len(args.java_home) != 2:
        parser.error('Supply --java-home for JDK 21 and JDK 25, in that order')
    homes = [p.resolve(strict=True) for p in args.java_home]
    args.output.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='shake-', dir=args.output.resolve()))
    print('output '+str(out), flush=True)
    receipt = {'scope': 'SHAKE functional proof and finite generated-Java checks only',
               'commands': [], 'proofs': {}, 'audits': {}, 'controls': {}, 'java': []}
    sources = closure(HERE/'shake_domain.dfy')
    harness = HERE/'shake_java/io/github/mahmoudimus/quic/tls/GeneratedShakeTest.java'
    reference = ROOT/'formal/crypto/reference/Shake.java'
    inputs = sources+[Path(__file__).resolve(), harness, reference, TOOLCHAIN,
                      ROOT/'formal/dafny/tools.json',HERE/'reference/provenance.json']
    before = snapshot(inputs, ROOT)
    spec = importlib.util.spec_from_file_location('shake_pinned_toolchain', TOOLCHAIN)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    dafny, runtime, manifest, asset = module.install(args.cache)
    if manifest['version'] != '4.9.1':
        raise RuntimeError('Expected official pinned Dafny 4.9.1')
    solver = dafny.parent/'z3/bin/z3-4.12.1'
    flags = [*FLAGS, '--solver-path', str(solver)]
    distribution = dafny.parent.parent
    oracle_paths = [Path(sys.executable).resolve(), Path(hashlib.__file__).resolve(),
                    Path(_hashlib.__file__).resolve()]

    def tools_snapshot():
        return {'dafny_distribution': tree(distribution),
                'dafny_archive_sha256': sha(args.cache/asset['archive']),
                'java_homes': [{'home': str(p), 'files': tree(p)} for p in homes],
                'python_oracle': snapshot(oracle_paths)}

    tool_before = tools_snapshot()

    def call(label, command):
        command = list(map(str, command))
        print(label, flush=True)
        process = subprocess.Popen(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=600)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                output, _ = process.communicate()
                (out/(label+'.log')).write_text(output)
            raise
        (out/(label+'.log')).write_text(output)
        receipt['commands'].append({'label': label, 'command': command, 'exit': process.returncode})
        return process.returncode, output

    status, version = call('dafny-version', [dafny, '--version'])
    if status or not version.startswith('4.9.1+'):
        raise RuntimeError('Dafny version mismatch')
    status, version = call('z3-version', [solver, '--version'])
    if status or 'Z3 version 4.12.1' not in version:
        raise RuntimeError('Z3 version mismatch')
    for source in sources:
        label = source.stem
        status, output = call('audit-'+label, [dafny, 'audit', source])
        if status or BAD_DIAGNOSTIC.search(output) or 'Dafny auditor completed with 0 findings' not in output:
            raise RuntimeError('Assumption audit failed: '+str(source))
        receipt['audits'][str(source.relative_to(ROOT))] = 0
        status, output = call('proof-'+label, [dafny, 'verify', source, *flags])
        receipt['proofs'][str(source.relative_to(ROOT))] = proof_result(status, output)

    for name, stem, symbol, old, new in CONTROLS:
        folder = out/name
        for source in sources:
            target = folder/source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = source.read_text()
            if source == HERE/(stem+'.dfy'):
                if content.count(old) != 1:
                    raise RuntimeError('Mutation anchor changed: '+name)
                content = content.replace(old,new)
                if name == 'absorb-byte-order':
                    # A legal counterexample only in this mutant copy; the
                    # positive method/domain retain arbitrary lanes/offset/byte.
                    signature = 'method XorByte(lanes: seq<bv64>, at: int, value: bv8) returns (r: seq<bv64>)'
                    if content.count(signature) != 1:
                        raise RuntimeError('Byte-order witness anchor changed')
                    content = content.replace(signature, signature+'\n    requires at == 0 && value == 1')
            target.write_text(content)
        target = folder/'formal/crypto'/('shake_domain.dfy' if name.startswith('domain-') else stem+'.dfy')
        mutant_hashes = tree(folder,'*.dfy')
        status, output = call('control-'+name, [dafny, 'verify', target, '--filter-symbol', symbol, *flags])
        receipt['controls'][name] = proof_result(status, output, negative=True)
        if tree(folder,'*.dfy') != mutant_hashes:
            raise RuntimeError('Mutant sources changed during verification: '+name)
        receipt['controls'][name]['inputs'] = mutant_hashes
        if name == 'absorb-byte-order':
            receipt['controls'][name]['negative_control_witness'] = {'at': 0, 'value': 1}

    vector_file = out/'hashlib-vectors.tsv'
    inventory = vectors(vector_file)
    vector_hash = sha(vector_file)
    status, output = call('generate-java', [dafny, 'translate', 'java', HERE/'Shake.dfy', HERE/'ByteLanes.dfy',
                                          '--output', out/'Shake', *flags])
    receipt['generation'] = proof_result(status, output)
    generated = out/'Shake-java'
    generated_hashes = tree(generated, '*.java')
    if not generated_hashes:
        raise RuntimeError('No generated Java files')
    classes = out/'classes'
    classes.mkdir()
    status, output = call('javac', [homes[0]/'bin/javac', '--release', '21', '-cp', runtime,
                                  '-d', classes, *sorted(generated.rglob('*.java')), harness, reference])
    if status or 'warning:' in output.lower():
        raise RuntimeError('Generated Java compilation failed or warned')
    class_hashes = tree(classes, '*.class')
    for major, home in zip((21,25), homes):
        status, version = call(f'java-{major}-version', [home/'bin/java', '-version'])
        if status or not re.search(r'version "'+str(major)+r'[.\"]',version):
            raise RuntimeError('Expected JDK '+str(major))
        status, output = call(f'java-{major}', [home/'bin/java', '-Xmx1024m', '-ea', '-cp',
                                              str(classes)+os.pathsep+str(runtime),
                                              'io.github.mahmoudimus.quic.tls.GeneratedShakeTest', vector_file])
        matches = re.findall(r'^PASS GeneratedShakeTest (\{.*\})$', output, re.M)
        if status or len(matches) != 1 or json.loads(matches[0]) != EXPECTED_TESTS:
            raise RuntimeError('Generated Java check or exact test inventory failed')
        receipt['java'].append({'version': version, 'tests': json.loads(matches[0])})

    if snapshot(inputs,ROOT) != before or closure(HERE/'shake_domain.dfy') != sources:
        raise RuntimeError('Source, include graph, harness, reference, or manifest changed')
    if tools_snapshot() != tool_before:
        raise RuntimeError('Compiler, solver, runtime, Java, or Python oracle inputs changed')
    if tree(generated,'*.java') != generated_hashes or tree(classes,'*.class') != class_hashes:
        raise RuntimeError('Generated or compiled artifacts changed during replay')
    if sha(vector_file) != vector_hash:
        raise RuntimeError('Independent vectors changed during replay')
    receipt.update({'inputs': before, 'tools': tool_before, 'toolchain_asset': asset,
                    'python': sys.version, 'openssl': ssl.OPENSSL_VERSION, 'platform': platform.platform(),
                    'generated_java': generated_hashes, 'compiled_classes': class_hashes,
                    'vectors': {'sha256': vector_hash, 'count': len(inventory), 'inventory': inventory},
                    'runtime_sha256': sha(runtime)})
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'output': str(out), 'proofs': receipt['proofs'],
                      'controls': {name: {k: v for k, v in result.items() if k != 'inputs'}
                                   for name, result in receipt['controls'].items()},
                      'java': receipt['java']},indent=2))


if __name__ == '__main__':
    main()

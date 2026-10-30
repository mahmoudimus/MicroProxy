#!/usr/bin/env python3
"""Focused codec/sampling proof, semantic controls, and generated-Java checks.

This does not register or change the repository's shared replay inventory.
Outputs and mutant sources live in an explicitly selected scratch directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
EXPECTED_TESTS = {'scalars': 40713, 'encodings': 7044, 'malformed': 1820,
                  'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 207513}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='codec-sampling-', dir=args.output))
    solver = args.dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--verification-time-limit', '30', '--resource-limit', '50000000',
             '--cores', '2', '--solver-path', str(solver)]
    receipt = {'commands': [], 'proofs': {}, 'controls': {}, 'java': [], 'inputs': {}}
    refs = [ROOT/'formal/crypto/reference'/name for name in ('Shake.java','MlKem768.java')]
    inputs = [HERE/file for file in ('Codec.dfy','Sampling.dfy','codec_domain.dfy','sampling_domain.dfy',
                                    'codec_sampling_checks.py','codec_sampling_test.java')]+refs+[HERE/'reference/provenance.json']
    before = {str(p.relative_to(ROOT)): sha(p) for p in inputs}

    def call(label, command):
        command = list(map(str, command))
        print(label, flush=True)
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=600)
        output = result.stdout + result.stderr
        (out / (label+'.log')).write_text(output)
        receipt['commands'].append({'label': label, 'command': command, 'exit': result.returncode})
        return result.returncode, output

    def proved(label, target):
        status, output = call(label, [args.dafny, 'verify', target, *flags])
        match = re.search(r'verifier finished with (\d+) verified, 0 errors\s*$', output)
        if status or not match or 'Warning:' in output:
            raise RuntimeError(f'{label} did not fully verify: {out / (label+".log")}')
        receipt['proofs'][label] = int(match[1])

    status, version = call('dafny-version', [args.dafny, '--version'])
    if status or not version.startswith('4.9.1+'):
        raise RuntimeError('Dafny version mismatch')
    status, version = call('z3-version', [solver, '--version'])
    if status or 'Z3 version 4.12.1' not in version:
        raise RuntimeError('Z3 version mismatch')
    for stem in ('Codec', 'Sampling'):
        status, output = call('audit-'+stem, [args.dafny, 'audit', HERE/(stem+'.dfy')])
        if status or 'Warning:' in output or 'Dafny auditor completed with 0 findings' not in output:
            raise RuntimeError('Audit findings: '+stem)
        proved('proof-'+stem, HERE/(stem+'.dfy'))
    for stem in ('codec_domain', 'sampling_domain'):
        proved(stem, HERE/(stem+'.dfy'))

    mutations = [
        ('compress-rounding', 'Codec', 'VerifiedCodec.Compress.', 'r := ((S.Pow2(d)*x + 1664)/3329)%S.Pow2(d);', 'r := (S.Pow2(d)*x/3329)%S.Pow2(d);'),
        ('decompress-half-tie', 'Codec', 'VerifiedCodec.Decompress.', 'r := (3329*y + S.Pow2(d)/2)/S.Pow2(d);', 'r := (3329*y)/S.Pow2(d);'),
        ('encode-bit', 'Codec', 'VerifiedCodec.Encode.', 'a[i] := S.EncodedByte(f,d,i);', 'a[i] := S.EncodedByte(f,d,i) ^ 1;'),
        ('decode-modulus', 'Codec', 'VerifiedCodec.Decode.', 'if d == 12 && !S.Canonical(f) { return S.ModulusError; }', 'if false { return S.ModulusError; }'),
        ('cbd-sign', 'Sampling', 'VerifiedSampling.Cbd2.', 'a[i] := (low-high)%3329;', 'a[i] := (high-low)%3329;'),
        ('feed-order', 'Sampling', 'VerifiedSampling.Feed.', 'var x := (b[off] as int)+256*((b[off+1] as int)%16);\n      var y := (b[off+1] as int)/16+16*(b[off+2] as int);', 'var y := (b[off] as int)+256*((b[off+1] as int)%16);\n      var x := (b[off+1] as int)/16+16*(b[off+2] as int);'),
        ('feed-reject-q', 'Sampling', 'VerifiedSampling.Feed.', 'if x < C.Q {', 'if x <= C.Q {'),
        ('feed-cap', 'Sampling', 'VerifiedSampling.Feed.', 'if |f| < C.N && y < C.Q { f := f+[y]; }', 'if y < C.Q { f := f+[y]; }'),
        ('feed-consumption', 'Sampling', 'VerifiedSampling.Feed.', 'off := off+3;', 'off := off+6;'),
        ('full-domain', 'Codec', 'CodecPublicDomain.Scalars.', 'method Compress(x: int, d: int) returns (r: int)\n    requires 0 <= x < S.Q', 'method Compress(x: int, d: int) returns (r: int)\n    requires 0 <= x < S.Q-1'),
    ]
    for name, stem, symbol, old, new in mutations:
        folder = out/name
        folder.mkdir()
        for file in ('Codec.dfy', 'Sampling.dfy', 'codec_domain.dfy', 'sampling_domain.dfy'):
            source = (HERE/file).read_text()
            if file == stem+'.dfy':
                if source.count(old) != 1:
                    raise RuntimeError('Mutation anchor changed: '+name)
                source = source.replace(old,new)
                if name == 'feed-reject-q':
                    # Negative control only: a legal three-byte witness encoding
                    # d1=q. The production method and positive domain harness
                    # remain total, with no input restriction. This avoids an
                    # SMT byte/int countermodel search being counted as failure.
                    signature = 'method Feed(current: seq<int>, b: seq<bv8>) returns (r: S.FeedResult)'
                    source = source.replace(signature, signature+'\n    requires b == [1 as bv8,13 as bv8,0 as bv8]')
            (folder/file).write_text(source)
        target = folder/('codec_domain.dfy' if name == 'full-domain' else stem+'.dfy')
        extra = []
        focus = {'feed-reject-q': 'assert x < C.Q;', 'feed-cap': 'assert |f| <= C.N;',
                 'feed-consumption': 'assert off <= |b|;'}.get(name)
        if focus:
            lines = target.read_text().splitlines()
            matches = [i+1 for i,line in enumerate(lines) if line.strip() == focus]
            if len(matches) != 1:
                raise RuntimeError('Control focus changed: '+name)
            extra = ['--isolate-assertions', '--filter-position', f'{target.name}:{matches[0]}']
        status, output = call('control-'+name, [args.dafny, 'verify', target, '--filter-symbol', symbol, *extra, *flags])
        match = re.search(r'verifier finished with (\d+) (?:assertions )?verified, ([1-9]\d*) errors?\s*$', output)
        bad = ('out of resource', 'timed out', 'resolution/type errors', 'parse errors', 'Warning:')
        semantic = 'could not be proved' in output or 'assertion might not hold' in output
        if status != 4 or not match or any(term in output for term in bad) or not semantic:
            raise RuntimeError('Control did not produce a semantic proof failure: '+name)
        receipt['controls'][name] = {'verified': int(match[1]), 'errors': int(match[2])}
        if name == 'feed-reject-q':
            receipt['controls'][name]['negative_control_witness_bytes'] = [1,13,0]

    prefix = out/'CodecSampling'
    status, output = call('generate-java', [args.dafny, 'translate', 'java', HERE/'Codec.dfy', HERE/'Sampling.dfy', '--output', prefix, *flags])
    if status or not re.search(r'verifier finished with (\d+) verified, 0 errors\s*$',output):
        raise RuntimeError('Generation failed')
    generated = out/'CodecSampling-java'
    classes = out/'classes'
    classes.mkdir()
    runtime = args.dafny.parent/'DafnyRuntime.jar'
    sources = sorted(generated.rglob('*.java'))+[HERE/'codec_sampling_test.java',*refs]
    status, output = call('javac', [args.java_home[0]/'bin/javac', '--release', '21', '-cp', runtime, '-d', classes, *sources])
    if status:
        raise RuntimeError('Generated Java compilation failed')
    for index, home in enumerate(args.java_home):
        status, version = call(f'java-{index}-version', [home/'bin/java','-version'])
        if status:
            raise RuntimeError('JVM version check failed')
        status, output = call(f'java-{index}', [home/'bin/java','-Xmx1024m','-ea','-cp',str(classes)+os.pathsep+str(runtime), 'io.github.mahmoudimus.quic.tls.codec_sampling_test'])
        matches = re.findall(r'^PASS codec_sampling_test (\{.*\})$',output,re.M)
        if status or len(matches) != 1:
            raise RuntimeError('Generated Java tests failed')
        tests = json.loads(matches[0])
        if tests != EXPECTED_TESTS:
            raise RuntimeError('Generated Java test inventory changed')
        receipt['java'].append({'version': version, 'tests': tests})
    receipt['inputs'] = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
    if receipt['inputs'] != before:
        raise RuntimeError('Proof or reference inputs changed during replay')
    receipt['generated_java'] = {str(p.relative_to(generated)): sha(p) for p in sorted(generated.rglob('*.java'))}
    receipt['compiled_classes'] = {str(p.relative_to(classes)): sha(p) for p in sorted(classes.rglob('*.class'))}
    receipt['runtime_sha256'] = sha(runtime)
    receipt['footprint'] = {'generated_java_bytes': sum(p.stat().st_size for p in generated.rglob('*.java')),
                            'compiled_classes_bytes': sum(p.stat().st_size for p in classes.rglob('*.class')),
                            'runtime_bytes': runtime.stat().st_size}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'output': str(out), 'proofs': receipt['proofs'], 'controls': receipt['controls'], 'java': receipt['java']},indent=2))


if __name__ == '__main__':
    main()

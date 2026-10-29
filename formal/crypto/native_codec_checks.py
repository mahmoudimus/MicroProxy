#!/usr/bin/env python3
"""Native-array codec/sampling proof, semantic controls, and generated-Java checks.

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
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
EXPECTED_TESTS = {'scalars': 40713, 'encodings': 7044, 'malformed': 1820,
                  'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='native-codec-', dir=args.output))
    solver = args.dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--verification-time-limit', '30', '--resource-limit', '50000000',
             '--cores', '2', '--solver-path', str(solver), '--solver-option', 'O:smt.case_split=0']
    receipt = {'commands': [], 'proofs': {}, 'controls': {}, 'java': [], 'inputs': {}}
    refs = [ROOT/'quic/src/main/java/io/github/mahmoudimus/quic/tls'/name for name in ('Shake.java','MlKem768.java')]
    inputs = [HERE/file for file in ('NativeTypes.dfy','Codec.dfy','Sampling.dfy','NativeCodec.dfy','NativeSampling.dfy',
                                    'native_codec_domain.dfy','native_sampling_domain.dfy','native_codec_checks.py','native_codec_test.java')]+refs
    before = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
    receipt['inputs_before'] = before
    receipt['toolchain_sha256'] = {'dafny':sha(args.dafny),'solver':sha(solver)}
    for source in inputs:
        saved = out/'inputs'/source.relative_to(ROOT)
        saved.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source,saved)

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
    for stem in ('NativeCodec', 'NativeSampling'):
        status, output = call('audit-'+stem, [args.dafny, 'audit', HERE/(stem+'.dfy')])
        if status or 'Warning:' in output or 'Dafny auditor completed with 0 findings' not in output:
            raise RuntimeError('Audit findings: '+stem)
        proved('proof-'+stem, HERE/(stem+'.dfy'))
    for stem in ('native_codec_domain', 'native_sampling_domain'):
        proved(stem, HERE/(stem+'.dfy'))

    mutations = [
        ('compress-rounding', 'NativeCodec', 'NativeCodec.Compress.', '((p*x + 1664)/3329)%p', '(p*x/3329)%p'),
        ('decompress-half-tie', 'NativeCodec', 'NativeCodec.Decompress.', '(3329*y + p/2)/p', '(3329*y)/p'),
        ('encode-bit', 'NativeCodec', 'NativeCodec.Encode.', 'b[i] := EncodedByte(f,d,i);', 'b[i] := EncodedByte(f,d,i) ^ 1;'),
        # Narrow the high-word multiplication before widening its result. The
        # mathematical value is unchanged, but legal d=10 words overflow int.
        ('native-int-overflow', 'NativeCodec', 'NativeCodec.GroupValue.', '1073741824*(f[k+3] as T.L)', '((1073741824*f[k+3]) as T.L)'),
        ('decode-modulus', 'NativeCodec', 'NativeCodec.Decode.', 'if d == 12 && !valid { Wipe(a); return ModulusError; }', 'if false { return ModulusError; }'),
        ('wipe', 'NativeCodec', 'NativeCodec.Wipe.', '{ a[i] := 0; }', '{ a[i] := 1; }'),
        ('cbd-sign', 'NativeSampling', 'NativeSampling.Cbd2.', 'f[i] := (3329+low-high)%3329;', 'f[i] := (3329+high-low)%3329;'),
        ('feed-order', 'NativeSampling', 'NativeSampling.Feed.', 'var x: T.I := (b[off] as T.I)+256*((b[off+1] as T.I)%16);\n      var y: T.I := (b[off+1] as T.I)/16+16*(b[off+2] as T.I);', 'var y: T.I := (b[off] as T.I)+256*((b[off+1] as T.I)%16);\n      var x: T.I := (b[off+1] as T.I)/16+16*(b[off+2] as T.I);'),
        ('feed-reject-q', 'NativeSampling', 'NativeSampling.Feed.', 'if x < 3329 {', 'if x <= 3329 {'),
        ('feed-cap', 'NativeSampling', 'NativeSampling.Feed.', 'if used < 256 && y < 3329 {', 'if y < 3329 {'),
        ('feed-consumption', 'NativeSampling', 'NativeSampling.Feed.', 'off := off+3;', 'off := off+6;'),
        ('full-domain', 'NativeCodec', 'NativeCodecPublicDomain.Scalars.', 'requires 0 <= x < 3329 && 1 <= d <= 11', 'requires 0 <= x < 3328 && 1 <= d <= 11'),
    ]
    for name, stem, symbol, old, new in mutations:
        folder = out/name
        folder.mkdir()
        for file in ('NativeTypes.dfy','Codec.dfy','Sampling.dfy','NativeCodec.dfy','NativeSampling.dfy','native_codec_domain.dfy','native_sampling_domain.dfy'):
            source = (HERE/file).read_text()
            if file == stem+'.dfy':
                if source.count(old) != 1:
                    raise RuntimeError('Mutation anchor changed: '+name)
                source = source.replace(old,new)
                if name in ('feed-reject-q', 'feed-cap', 'feed-consumption'):
                    # A concrete legal witness only in the negative-control copy;
                    # positive public domains remain unrestricted.
                    signature = 'method {:isolate_assertions} Feed(current: array<T.I>, b: array<bv8>) returns(r: FeedResult)'
                    witness = 'b.Length == 3 && T.Bytes(b) == [1 as bv8,13 as bv8,0 as bv8]' if name == 'feed-reject-q' else 'b.Length == 3 && T.Bytes(b) == [0 as bv8,0 as bv8,0 as bv8]'
                    if name == 'feed-cap':
                        witness += ' && current.Length == 255 && forall i: int :: 0 <= i < current.Length ==> current[i] == 0'
                    source = source.replace(signature, signature+'\n    requires '+witness)
            (folder/file).write_text(source)
        target = folder/('native_codec_domain.dfy' if name == 'full-domain' else stem+'.dfy')
        extra = []
        focus = {'feed-reject-q': 'assert x < 3329;', 'feed-cap': 'a[used] := y; used := used+1;',
                 'feed-consumption': 'assert off <= size;'}.get(name)
        if focus:
            lines = target.read_text().splitlines()
            matches = [i+1 for i,line in enumerate(lines) if line.strip() == focus]
            if len(matches) != 1:
                raise RuntimeError('Control focus changed: '+name)
            extra = ['--isolate-assertions', '--filter-position', f'{target.name}:{matches[0]}']
        status, output = call('control-'+name, [args.dafny, 'verify', target, '--filter-symbol', symbol, *extra, *flags])
        match = re.search(r'verifier finished with (\d+) (?:assertions )?verified, ([1-9]\d*) errors?\s*$', output)
        bad = ('out of resource', 'timed out', 'resolution/type errors', 'parse errors', 'Warning:')
        semantic = any(term in output for term in ('could not be proved','assertion might not hold','index out of range'))
        if name == 'native-int-overflow':
            semantic = "result of operation might violate newtype constraint for 'I'" in output
        if not status or not match or any(term in output for term in bad) or not semantic:
            raise RuntimeError('Control did not produce a semantic proof failure: '+name)
        receipt['controls'][name] = {'verified': int(match[1]), 'errors': int(match[2])}
        if name == 'native-int-overflow':
            receipt['controls'][name]['failure_kind'] = 'native_int_range'
        if name == 'feed-reject-q':
            receipt['controls'][name]['negative_control_witness_bytes'] = [1,13,0]

    prefix = out/'NativeCodecSampling'
    status, output = call('generate-java', [args.dafny, 'translate', 'java', HERE/'NativeCodec.dfy', HERE/'NativeSampling.dfy', '--output', prefix, *flags])
    if status or not re.search(r'verifier finished with (\d+) verified, 0 errors\s*$',output):
        raise RuntimeError('Generation failed')
    generated = out/'NativeCodecSampling-java'
    classes = out/'classes'
    classes.mkdir()
    runtime = args.dafny.parent/'DafnyRuntime.jar'
    sources = sorted(generated.rglob('*.java'))+[HERE/'native_codec_test.java',*refs]
    status, output = call('javac', [args.java_home[0]/'bin/javac', '--release', '21', '-cp', runtime, '-d', classes, *sources])
    if status:
        raise RuntimeError('Generated Java compilation failed')
    for index, home in enumerate(args.java_home):
        status, version = call(f'java-{index}-version', [home/'bin/java','-version'])
        if status:
            raise RuntimeError('JVM version check failed')
        status, output = call(f'java-{index}', [home/'bin/java','-Xmx1024m','-ea','-cp',str(classes)+os.pathsep+str(runtime), 'io.github.mahmoudimus.quic.tls.native_codec_test'])
        matches = re.findall(r'^PASS native_codec_test (\{.*\})$',output,re.M)
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
    shutil.copy2(runtime,out/'DafnyRuntime.jar')
    status, helpers = call('runtime-euclidean-bytecode', [args.java_home[0]/'bin/javap','-c','-p','-cp',runtime,'dafny.DafnyEuclidean'])
    if status:
        raise RuntimeError('Cannot inspect native division runtime')
    receipt['inputs_after'] = receipt['inputs']
    # Only the executable native module bodies carry secrets. Mathematical
    # reference modules are generated for differential tests, never called by
    # native runtime methods. Constant-zero newtype allocation boxing is listed
    # separately and does not depend on coefficients or input bytes.
    native_sources = [generated/stem/'__default.java' for stem in ('NativeCodec','NativeSampling')]
    for source in native_sources:
        if re.search(r'BigInteger|DafnySequence|Integer\.valueOf|Long\.valueOf|Byte\.valueOf', source.read_text()):
            raise RuntimeError('Non-native runtime expression: '+str(source))
    status, bytecode = call('native-bytecode', [args.java_home[0]/'bin/javap','-c','-p','-cp',classes,
        'NativeCodec.__default','NativeSampling.__default'])
    if status or re.search(r'BigInteger|DafnySequence|Long.valueOf',bytecode):
        raise RuntimeError('Non-native bytecode')
    # The compiler boxes only the fixed I.Witness zero passed when allocating
    # int arrays; reject boxing any computed/native input value.
    lines = bytecode.splitlines()
    boxings = []
    for index,line in enumerate(lines):
        if 'Integer.valueOf' in line:
            if index == 0 or 'NativeTypes/I.Witness:I' not in lines[index-1]:
                raise RuntimeError('Value-dependent integer boxing: '+line)
            boxings.append({'instruction':line.strip(),'source':'constant NativeTypes.I.Witness zero'})
        if 'Byte.valueOf' in line:
            if index == 0 or 'iconst_0' not in lines[index-1]:
                raise RuntimeError('Value-dependent byte boxing: '+line)
            boxings.append({'instruction':line.strip(),'source':'constant byte zero'})
    receipt['native_runtime_audit'] = {'sources': [str(p.relative_to(generated)) for p in native_sources],
        'big_integer_or_sequence_calls':0, 'secret_value_boxings':0, 'constant_zero_allocation_boxings':boxings,
        'coefficient_type':'int', 'packing_accumulator_type':'long', 'packing_upper_bound_exclusive':1099511627776}

    receipt['footprint'] = {'generated_java_bytes': sum(p.stat().st_size for p in generated.rglob('*.java')),
                            'compiled_classes_bytes': sum(p.stat().st_size for p in classes.rglob('*.class')),
                            'runtime_bytes': runtime.stat().st_size}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'output': str(out), 'proofs': receipt['proofs'], 'controls': receipt['controls'], 'java': receipt['java']},indent=2))


if __name__ == '__main__':
    main()

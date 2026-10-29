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
EXPECTED_RUNTIME_SHA = 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6'
EXPECTED_FIELD_SHA = 'f6fb7911a9be3559d06b241cc2ca7ebb2acc98e0ff5444979f8459ff503eaa92'
DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
EXPECTED_TESTS = {'scalars': 40713, 'encodings': 7044, 'malformed': 1820,
                  'cbd': 384, 'feeds': 19320, 'java_samples': 224, 'assertions': 334753}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()



# Primitive argument policies are the existing API's public metadata boundary:
# widths, counts, and group/byte indices are public; payload scalars/arrays are
# secret. This checker follows actual JVM stack/local data flow and all CFG edges.
PUBLIC_ARGUMENTS = {
    'Width': {0}, 'Pow2': {0}, 'GroupWords': {0}, 'GroupBytes': {0},
    'DecompressionScale': {0}, 'BytePower': {0}, 'WordPower': {0,1}, 'PublicDiv': {0,1}, 'PublicMod': {0,1},
    'Shift': {1}, 'EncodeTenByte': {4}, 'EncodeTwelveByte': {2}, 'DecodeTenWord': {5}, 'DecodeTwelveWord': {3}, 'Extract': {1,2}, 'Compress': {1}, 'Decompress': {1},
    'GroupValue': {1,2}, 'EncodedByte': {1,2}, 'Encode': {1},
    'ByteGroup': {1,2}, 'DecodedWord': {1,2}, 'Decode': {1},
    'CompressAndEncode': {1}, 'DecodeAndDecompress': {1},
}
PUBLIC_RESULTS = {'DecompressionScale','Width','Pow2','GroupWords','GroupBytes','BytePower','WordPower','PublicDiv','PublicMod'}


def descriptor_types(descriptor):
    def one(at):
        start = at
        while descriptor[at] == '[': at += 1
        if descriptor[at] == 'L': at = descriptor.index(';',at)+1
        else: at += 1
        return descriptor[start:at],at
    at=1; args=[]
    while descriptor[at] != ')':
        value,at=one(at); args.append(value)
    result,_=one(at+1)
    return args,result


def native_dataflow(bytecode):
    methods=[]; owner=None; method=None
    for line in bytecode.splitlines():
        found=re.match(r'public class ([\w.$]+)',line)
        if found: owner=found[1].replace('.','/'); method=None
        if re.match(r'\s+(?:public|private|protected).*\([^)]*\);$',line):
            name=line.split('(',1)[0].split()[-1].split('.')[-1]
            method={'owner':owner,'name':name,'static':' static ' in line,'ops':{}}
            methods.append(method)
        elif method and 'descriptor:' in line: method['descriptor']=line.split('descriptor:',1)[1].strip()
        elif method:
            found=re.match(r'\s*(\d+):\s+(\w+)\s*(.*)',line)
            if found: method['ops'][int(found[1])]=(found[2],found[3])
    checked_calls=[]; arithmetic=[]
    for method in methods:
        ops=method['ops']
        if not ops: continue
        name=method['name']; owner=method['owner']; args,_=descriptor_types(method['descriptor'])
        public=PUBLIC_ARGUMENTS.get(name,set()) if owner=='NativeCodec/__default' else set()
        local={}; slot=0
        # Each value carries (payload taint, JVM slot width, array-length taint).
        # Input array lengths are public API metadata. Reject secret allocation
        # sizes at their origin so a native call cannot reset length taint by
        # receiving a payload-sized array as an input. Unknown returned/loaded
        # references have secret length until a precise summary applies.
        if not method['static']: local[0]=(False,1,True); slot=1
        for index,kind in enumerate(args):
            width=2 if kind in ('J','D') else 1
            local[slot]=(index not in public,width,not kind.startswith('[')); slot+=width
        first=min(ops); states={first:((),local)}; pending=[first]; order=sorted(ops)
        following={at:order[i+1] if i+1<len(order) else None for i,at in enumerate(order)}
        while pending:
            at=pending.pop(); stack,locals_in=states[at]; stack=list(stack); local=dict(locals_in)
            op,text=ops[at]; successors=[following[at]]
            def pop():
                if not stack: raise RuntimeError(f'Bytecode stack underflow {owner}.{name}@{at}')
                return stack.pop()
            def push(secret,width=1,length_secret=True): stack.append((secret,width,length_secret))
            if re.fullmatch(r'[ialfd]load_\d',op) or op in ('iload','lload','aload','fload','dload'):
                index=int(op.rsplit('_',1)[1]) if '_' in op else int(text.split()[0])
                if index not in local: raise RuntimeError(f'Untracked JVM local {owner}.{name}@{at}')
                stack.append(local[index])
            elif re.fullmatch(r'[ialfd]store_\d',op) or op in ('istore','lstore','astore','fstore','dstore'):
                index=int(op.rsplit('_',1)[1]) if '_' in op else int(text.split()[0]); local[index]=pop()
            elif op.startswith(('iconst_','fconst_')) or op in ('bipush','sipush','aconst_null','ldc','ldc_w'):
                push(False)
            elif op.startswith(('lconst_','dconst_')) or op=='ldc2_w': push(False,2)
            elif op in ('iadd','isub','imul','iand','ior','ixor','ladd','lsub','lmul','land','lor','lxor','idiv','irem','ldiv','lrem'):
                b=pop(); a=pop()
                if op in ('idiv','irem','ldiv','lrem'):
                    if name not in ('PublicDiv','PublicMod') or owner!='NativeCodec/__default' or a[0] or b[0]:
                        raise RuntimeError(f'Payload division/remainder {owner}.{name}@{at}: {op}')
                    arithmetic.append(f'{owner}.{name}@{at}:{op}')
                push(a[0] or b[0],2 if op.startswith('l') else 1)
            elif op in ('ishl','ishr','iushr','lshl','lshr','lushr'):
                count=pop(); value=pop()
                if count[0]: raise RuntimeError(f'Payload shift distance {owner}.{name}@{at}')
                push(value[0],2 if op.startswith('l') else 1)
            elif op in ('ineg','lneg','i2b','i2c','i2s','i2l','l2i'):
                value=pop(); push(value[0],2 if op in ('lneg','i2l') else 1)
            elif op in ('lcmp','fcmpl','fcmpg','dcmpl','dcmpg'):
                a=pop(); b=pop(); push(a[0] or b[0])
            elif op=='iinc':
                index=int(text.split(',')[0]); local[index]=(local[index][0],1,True)
            elif op in ('iaload','baload','aaload','laload'):
                pop(); pop(); push(True,2 if op=='laload' else 1)
            elif op in ('iastore','bastore','aastore','lastore'): pop(); pop(); pop()
            elif op=='arraylength': value=pop(); push(value[2])
            elif op in ('newarray','anewarray'):
                size=pop()
                if size[0]: raise RuntimeError(f'Payload array allocation size {owner}.{name}@{at}: {op}')
                push(False,length_secret=False)
            elif op=='new': push(False)
            elif op=='checkcast': pass
            elif op=='instanceof': value=pop(); push(value[0])
            elif op=='dup': stack.append(stack[-1])
            elif op=='dup2':
                if stack[-1][1]==2: stack.append(stack[-1])
                else: stack.extend(stack[-2:])
            elif op=='pop': pop()
            elif op=='getstatic':
                # Only public constants/default descriptors are allowed here.
                if not re.search(r'NativeTypes/I.Witness:I|NativeField/__default\.(?:Q|MaxReduce):|dafny/TypeDescriptor\.',text):
                    raise RuntimeError(f'Unreviewed static field {owner}.{name}@{at}: {text}')
                push(False,2 if text.endswith(':J') else 1)
            elif op=='getfield': pop(); push(True,2 if text.endswith(':J') else 1)
            elif op.startswith('invoke'):
                found=re.search(r'// (?:InterfaceMethod|Method) ([^:]+):(\([^ ]+)',text)
                if not found: raise RuntimeError(f'Untracked JVM invocation {owner}.{name}@{at}: {text}')
                target,descriptor=found.groups(); parameters,result=descriptor_types(descriptor)
                values=[pop() for _ in parameters][::-1]
                if op!='invokestatic': receiver=pop()
                else: receiver=(False,1,True)
                if '.' in target: target_owner,target_name=target.rsplit('.',1)
                else: target_owner,target_name=owner,target
                target_name=target_name.strip('"')
                external = {
                    'java/lang/Object': {'<init>'},
                    'java/lang/Byte': {'toUnsignedInt','toUnsignedLong','valueOf'},
                    'java/lang/Integer': {'signum','valueOf'},
                    'dafny/Helpers': {'toInt','toIntChecked','bv64ShiftRight'},
                    'dafny/DafnyEuclidean': {'EuclideanDivision','EuclideanModulus'},
                    'dafny/TypeDescriptor': {'newArray','fillThenReturnArray'},
                    'NativeTypes/I': {'_typeDescriptor'},
                    'NativeCodec/DecodeResult': {'Default','create_InvalidWidth','create_InvalidLength','create_ModulusError','create_Decoded','is_Decoded','dtor_words'},
                    'NativeSampling/FeedResult': {'Default','create_InvalidPrefix','create_InvalidBlockLength','create_Full','create_NeedMore'},
                }
                if target_owner not in ('NativeCodec/__default','NativeSampling/__default','NativeField/__default') and target_name not in external.get(target_owner,set()):
                    raise RuntimeError(f'Unreviewed arithmetic callee {owner}.{name}@{at} -> {target_owner}.{target_name}')
                if target_owner=='NativeCodec/__default':
                    for index in PUBLIC_ARGUMENTS.get(target_name,set()):
                        if values[index][0]: raise RuntimeError(f'Payload reaches public metadata {owner}.{name}@{at} -> {target_name} argument {index}')
                    if target_name in ('PublicDiv','PublicMod'):
                        checked_calls.append(f'{owner}.{name}@{at}->{target_name}: public operands')
                if target_owner=='dafny/DafnyEuclidean':
                    if owner!='NativeCodec/__default' or name not in ('PublicDiv','PublicMod') or any(x[0] for x in values):
                        raise RuntimeError(f'Payload Euclidean arithmetic {owner}.{name}@{at}')
                    arithmetic.append(f'{owner}.{name}@{at}:{target_name}')
                if target_owner=='dafny/Helpers' and target_name=='bv64ShiftRight':
                    if values[1][0]: raise RuntimeError(f'Payload helper shift distance {owner}.{name}@{at}')
                if target_owner=='dafny/TypeDescriptor' and target_name=='newArray':
                    # The dimension-vector overload would require element/heap
                    # taint tracking. No native kernel uses it; fail closed.
                    if descriptor!='(I)Ljava/lang/Object;':
                        raise RuntimeError(f'Unreviewed array allocation signature {owner}.{name}@{at}: {descriptor}')
                    if values[0][0]: raise RuntimeError(f'Payload array allocation size {owner}.{name}@{at}: TypeDescriptor.newArray')
                if result!='V':
                    if target_owner=='NativeCodec/__default' and target_name in PUBLIC_RESULTS: secret=False
                    elif target_owner in ('java/lang/Byte','java/lang/Integer','java/lang/Long','dafny/Helpers','dafny/TypeDescriptor','NativeTypes/I'):
                        secret=receiver[0] or any(x[0] for x in values)
                    else: secret=True
                    length_secret=True
                    if target_owner=='dafny/TypeDescriptor' and target_name=='newArray':
                        length_secret=values[0][0]
                    elif target_owner=='dafny/TypeDescriptor' and target_name=='fillThenReturnArray':
                        length_secret=values[0][2]
                    push(secret,2 if result in ('J','D') else 1,length_secret)
            elif op.startswith('if'):
                condition=pop()[0]
                if op.startswith(('if_icmp','if_acmp')): condition=pop()[0] or condition
                validation = (owner=='NativeCodec/__default' and name in ('IsCanonical','Decode','DecodeAndDecompress')) or (owner=='NativeSampling/__default' and name in ('IsPrefix','Feed'))
                if condition and not validation:
                    raise RuntimeError(f'Payload arithmetic branch {owner}.{name}@{at}')
                successors.append(int(text.split()[0]))
            elif op in ('goto','goto_w'): successors=[int(text.split()[0])]
            elif op in ('ireturn','lreturn','areturn','freturn','dreturn'): pop(); successors=[]
            elif op in ('return','athrow'): successors=[]
            elif op=='nop': pass
            else: raise RuntimeError(f'Untracked bytecode instruction {owner}.{name}@{at}: {op}')
            for successor in successors:
                if successor is None: continue
                new=(tuple(stack),local)
                if successor in states:
                    previous_stack,previous_local=states[successor]
                    if len(previous_stack)!=len(stack) or any(a[1]!=b[1] for a,b in zip(previous_stack,stack)):
                        raise RuntimeError(f'JVM merge shape changed {owner}.{name}@{successor}')
                    merged_stack=tuple((a[0] or b[0],a[1],a[2] or b[2]) for a,b in zip(previous_stack,stack))
                    merged_local={i:(previous_local[i][0] or local[i][0],local[i][1],previous_local[i][2] or local[i][2]) for i in previous_local.keys() & local.keys()}
                    new=(merged_stack,merged_local)
                if successor not in states or states[successor]!=new:
                    states[successor]=new; pending.append(successor)
    return {'methods_checked':len(methods),'public_arithmetic_sites':sorted(set(arithmetic)),
            'metadata_calls_checked':sorted(set(checked_calls)),'payload_division_remainder_sites':0,
            'scope':'Explicit operand-stack/local data flow over every bytecode control-flow edge; no JVM timing theorem'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    args = parser.parse_args()
    runtime=args.runtime.resolve()
    if sha(runtime) != EXPECTED_RUNTIME_SHA or sha(HERE/'NativeField.dfy') != EXPECTED_FIELD_SHA:
        raise RuntimeError('Pinned Maven runtime or NativeField checksum mismatch')
    args.output.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='native-codec-', dir=args.output))
    solver = args.dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--verification-time-limit', '30', '--resource-limit', '50000000',
             '--cores', '2', '--solver-path', str(solver), '--solver-option', 'O:smt.case_split=0']
    receipt = {'commands': [], 'proofs': {}, 'controls': {}, 'java': [], 'inputs': {}}
    refs = [HERE/'reference'/name for name in ('Shake.java','MlKem768.java')]
    inputs = [HERE/file for file in ('NativeTypes.dfy','NativeField.dfy','Codec.dfy','Sampling.dfy','NativeCodec.dfy','NativeSampling.dfy',
                                    'native_codec_domain.dfy','native_sampling_domain.dfy','native_codec_checks.py','native_codec_test.java')]+[ROOT/'formal/primitives/Field.dfy',HERE/'reference/provenance.json']+refs
    before = {str(p.relative_to(ROOT)): sha(p) for p in inputs}
    receipt['inputs_before'] = before
    receipt['runtime_path'] = str(runtime)
    receipt['expected_runtime_sha256'] = EXPECTED_RUNTIME_SHA
    (out/'primitives').mkdir()
    shutil.copy2(ROOT/'formal/primitives/Field.dfy',out/'primitives/Field.dfy')
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
    for stem in ('NativeField','NativeCodec', 'NativeSampling'):
        status, output = call('audit-'+stem, [args.dafny, 'audit', HERE/(stem+'.dfy')])
        if status or 'Warning:' in output or 'Dafny auditor completed with 0 findings' not in output:
            raise RuntimeError('Audit findings: '+stem)
        proved('proof-'+stem, HERE/(stem+'.dfy'))
    for stem in ('native_codec_domain', 'native_sampling_domain'):
        proved(stem, HERE/(stem+'.dfy'))

    mutations = [
        ('compress-rounding', 'NativeCodec', 'NativeCodec.Compress.', 'var dividend: T.I := p*x + 1664;', 'var dividend: T.I := p*x;' ),
        ('decompress-half-tie', 'NativeCodec', 'NativeCodec.Decompress.', 'var dividend: T.I := 3329*y + PublicDiv(p,2);', 'var dividend: T.I := 3329*y;' ),
        ('encode-bit', 'NativeCodec', 'NativeCodec.Encode.', 'b[i] := EncodedByte(f,d,i);', 'b[i] := EncodedByte(f,d,i) ^ 1;'),
        # Narrow the high-word multiplication before widening its result. The
        # mathematical value is unchanged, but legal d=10 words overflow int.
        ('native-int-overflow', 'NativeCodec', 'NativeCodec.GroupValue.', '1073741824*(f[k+3] as T.L)', '((1073741824*f[k+3]) as T.L)'),
        ('decode-modulus', 'NativeCodec', 'NativeCodec.Decode.', 'if d == 12 && !valid { Wipe(a); return ModulusError; }', 'if false { return ModulusError; }'),
        ('wipe', 'NativeCodec', 'NativeCodec.Wipe.', '{ a[i] := 0; }', '{ a[i] := 1; }'),
        ('cbd-sign', 'NativeSampling', 'NativeSampling.Cbd2.', 'f[i] := F.ReduceOnce(3329+low-high);', 'f[i] := F.ReduceOnce(3329+high-low);'),
        ('feed-order', 'NativeSampling', 'NativeSampling.Feed.', 'var x: T.I := (b[off] as T.I)+256*N.Extract(b[off+1] as T.L,0,4);\n      var y: T.I := N.Extract(b[off+1] as T.L,4,4)+16*(b[off+2] as T.I);', 'var y: T.I := (b[off] as T.I)+256*N.Extract(b[off+1] as T.L,0,4);\n      var x: T.I := N.Extract(b[off+1] as T.L,4,4)+16*(b[off+2] as T.I);'),
        ('feed-reject-q', 'NativeSampling', 'NativeSampling.Feed.', 'if x < 3329 {', 'if x <= 3329 {'),
        ('feed-cap', 'NativeSampling', 'NativeSampling.Feed.', 'if used < 256 && y < 3329 {', 'if y < 3329 {'),
        ('feed-consumption', 'NativeSampling', 'NativeSampling.Feed.', 'off := off+3;', 'off := off+6;'),
        ('extract-shift', 'NativeCodec', 'NativeCodec.Extract.', 'var shifted := word >> shift;', 'var shifted := word >> (shift+1);'),
        ('extract-mask', 'NativeCodec', 'NativeCodec.Extract.', 'var masked := shifted & ((Pow2(bits)-1) as bv64);', 'var masked := shifted & ((Pow2(bits)-2) as bv64);'),
        ('compress-reciprocal', 'NativeCodec', 'NativeCodec.Compress.', '(dividend as T.L)*5039;', '(dividend as T.L)*5000;'),
        ('full-domain', 'NativeCodec', 'NativeCodecPublicDomain.Scalars.', 'requires 0 <= x < 3329 && 1 <= d <= 11', 'requires 0 <= x < 3328 && 1 <= d <= 11'),
    ]
    for name, stem, symbol, old, new in mutations:
        folder = out/name
        folder.mkdir()
        for file in ('NativeTypes.dfy','NativeField.dfy','Codec.dfy','Sampling.dfy','NativeCodec.dfy','NativeSampling.dfy','native_codec_domain.dfy','native_sampling_domain.dfy'):
            source = (HERE/file).read_text()
            if file == stem+'.dfy':
                if source.count(old) != 1:
                    raise RuntimeError('Mutation anchor changed: '+name)
                source = source.replace(old,new)
                if name in ('extract-shift','extract-mask'):
                    source = source.replace('opaque function {:isolate_assertions} Extract(value: T.L, shift: T.I, bits: T.I): T.I',
                        'opaque function {:isolate_assertions} Extract(value: T.L, shift: T.I, bits: T.I): T.I\n    requires value == 1 && shift == 0 && bits == 1')
                if name == 'compress-rounding':
                    source = source.replace('method {:isolate_assertions} Compress(x: T.I, d: T.I) returns (r: T.I)',
                        'method {:isolate_assertions} Compress(x: T.I, d: T.I) returns (r: T.I)\n    requires x == 833 && d == 1')
                if name == 'decompress-half-tie':
                    source = source.replace('method {:isolate_assertions} Decompress(y: T.I, d: T.I) returns (r: T.I)',
                        'method {:isolate_assertions} Decompress(y: T.I, d: T.I) returns (r: T.I)\n    requires y == 1 && d == 1')
                if name == 'compress-reciprocal':
                    source = source.replace('method {:isolate_assertions} Compress(x: T.I, d: T.I) returns (r: T.I)',
                        'method {:isolate_assertions} Compress(x: T.I, d: T.I) returns (r: T.I)\n    requires x == 3328 && d == 11')
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
        focus = {'compress-rounding': 'assert dividend as int == S.Pow2(d as int)*(x as int)+S.Q/2;',
                 'decompress-half-tie': 'assert dividend as int == 3329*(y as int)+S.Pow2(d as int)/2;',
                 'feed-reject-q': 'assert x < 3329;', 'feed-cap': 'a[used] := y; used := used+1;',
                 'feed-consumption': 'assert off <= size;',
                 'compress-reciprocal': 'assert product as int == (dividend as int)*5039;'}.get(name)
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
        witnesses = {'compress-rounding': {'x':833,'d':1}, 'decompress-half-tie': {'y':1,'d':1}, 'compress-reciprocal': {'x':3328,'d':11}, 'extract-shift': {'value':1,'shift':0,'bits':1}, 'extract-mask': {'value':1,'shift':0,'bits':1}}
        if name in witnesses: receipt['controls'][name]['negative_control_witness'] = witnesses[name]
        if name == 'feed-reject-q':
            receipt['controls'][name]['negative_control_witness_bytes'] = [1,13,0]

    prefix = out/'NativeCodecSampling'
    status, output = call('generate-java', [args.dafny, 'translate', 'java', HERE/'NativeCodec.dfy', HERE/'NativeSampling.dfy', '--output', prefix, *flags])
    if status or not re.search(r'verifier finished with (\d+) verified, 0 errors\s*$',output):
        raise RuntimeError('Generation failed')
    generated = out/'NativeCodecSampling-java'
    classes = out/'classes'
    classes.mkdir()
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
    status, bytecode = call('native-bytecode', [args.java_home[0]/'bin/javap','-c','-p','-s','-cp',classes,
        'NativeCodec.__default','NativeSampling.__default','NativeField.__default'])
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
    receipt['native_dataflow'] = native_dataflow(bytecode)
    receipt['native_runtime_audit'] = {'sources': [str(p.relative_to(generated)) for p in native_sources],
        'big_integer_or_sequence_calls':0, 'secret_value_boxings':0, 'constant_zero_allocation_boxings':boxings,
        'coefficient_type':'int', 'packing_accumulator_type':'long', 'packing_upper_bound_exclusive':1099511627776}

    status, helpers = call('runtime-shift-bytecode', [args.java_home[0]/'bin/javap','-c','-p','-s','-cp',runtime,'dafny.Helpers'])
    if status:
        raise RuntimeError('Cannot inspect selected runtime shift helper')
    helper = helpers.split('public static long bv64ShiftRight(long, byte);',1)[1].split('\n  public ',1)[0]
    helper_ops = re.findall(r'^\s*\d+:\s+(\w+)',helper,re.M)
    if helper_ops != ['iload_2','bipush','if_icmpne','lconst_0','lreturn','lload_0','iload_2','lushr','lreturn'] or not re.search(r'1: bipush\s+64',helper):
        raise RuntimeError('Selected shift helper changed; re-review operand dependence')
    receipt['native_dataflow']['shift_helper'] = 'Only public shift-distance==64 guard; payload uses lushr'
    base_source = (generated/'NativeCodec/__default.java').read_text()
    body = re.search(r'public static int Compress\(int x, int d\)\s*\{',base_source)
    start=body.end()-1; end=start+1; depth=1
    while depth:
        depth += (base_source[end]=='{')-(base_source[end]=='}'); end+=1
    receipt['bytecode_controls'] = {}
    for label,replacement,expected in (
        ('payload-idiv','return x / 3329;','Payload division/remainder'),
        ('payload-euclidean','return dafny.DafnyEuclidean.EuclideanDivision(x,3329);','Payload Euclidean arithmetic'),
        ('payload-metadata','return PublicDiv(x,2);','Payload reaches public metadata'),
        ('payload-array-length','int[] payloadSized = new int[x]; return PublicDiv(payloadSized.length,2);','Payload array allocation size'),
        ('payload-runtime-array-length','int[] payloadSized = (int[]) NativeTypes.I._typeDescriptor().newArray(x); return PublicDiv(payloadSized.length,2);','Payload array allocation size'),
        ('payload-array-feed','byte[] payloadSized = new byte[x]; NativeSampling.__default.Feed(new int[0],payloadSized); return 0;','Payload array allocation size'),
        ('payload-reference-array','Object[] payloadSized = new Object[x]; return PublicDiv(payloadSized.length,2);','Payload array allocation size'),
        ('payload-runtime-dimensions','int[] dimensions = new int[]{x}; int[] payloadSized = (int[]) NativeTypes.I._typeDescriptor().newArray(dimensions); return PublicDiv(payloadSized.length,2);','Unreviewed array allocation signature'),
    ):
        folder=out/('bytecode-'+label); source_dir=folder/'NativeCodec'; source_dir.mkdir(parents=True)
        source=source_dir/'__default.java'; source.write_text(base_source[:start]+'{ '+replacement+' }'+base_source[end:])
        target_classes=folder/'classes'; target_classes.mkdir()
        cp=str(classes)+os.pathsep+str(runtime)
        status,_=call('compile-'+label,[args.java_home[0]/'bin/javac','--release','21','-cp',cp,'-d',target_classes,source])
        if status: raise RuntimeError('Bytecode control did not compile: '+label)
        status,mutant_code=call('inspect-'+label,[args.java_home[0]/'bin/javap','-c','-p','-s','-cp',str(target_classes)+os.pathsep+cp,
            'NativeCodec.__default','NativeSampling.__default','NativeField.__default'])
        if status: raise RuntimeError('Bytecode control inspection failed: '+label)
        try:
            native_dataflow(mutant_code)
        except RuntimeError as error:
            if expected not in str(error): raise
            receipt['bytecode_controls'][label]={'rejected':str(error)}
        else: raise RuntimeError('Bytecode guard accepted payload arithmetic: '+label)

    receipt['footprint'] = {'generated_java_bytes': sum(p.stat().st_size for p in generated.rglob('*.java')),
                            'compiled_classes_bytes': sum(p.stat().st_size for p in classes.rglob('*.class')),
                            'runtime_bytes': runtime.stat().st_size}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'output': str(out), 'proofs': receipt['proofs'], 'controls': receipt['controls'], 'java': receipt['java']},indent=2))


if __name__ == '__main__':
    main()

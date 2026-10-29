#!/usr/bin/env python3
"""Native SHAKE functional proof, semantic controls, and generated-Java replay.

No timing, physical-erasure, facade-encapsulation, or production-adoption claim.
Receipts require complete source/tool/generated/class before-after stability.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import hashlib
import _hashlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLCHAIN = ROOT/'formal/dafny/toolchain.py'
SHARED = HERE/'shake_checks.py'
EXPECTED_TESTS = {'vectors':198, 'partitions':198, 'permutations':1728, 'slices':24, 'assertions':25218}
FLAGS = ['--verification-time-limit','30','--resource-limit','50000000','--cores','2',
         '--solver-option','O:smt.case_split=0']


def load(name,path):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shared = load('native_shake_shared',SHARED)
sha,tree,snapshot,closure = shared.sha,shared.tree,shared.snapshot,shared.closure


def proof_result(status,output,negative=False):
    if not negative:
        return shared.proof_result(status,output)
    match = re.search(shared.SUMMARY,output)
    semantic = re.search(r'could not be proved|assertion might not hold|index out of range|might violate newtype constraint',output)
    if not match or shared.BAD_DIAGNOSTIC.search(output) or status != 4 or int(match[2]) < 1 or not semantic:
        raise RuntimeError('Expected semantic failure, never parser/time/resource failure')
    return {'verified':int(match[1]),'errors':int(match[2])}


# name, changed source, verified symbol, exact old/new executable text.
# Mathematical specifications are unchanged, including in domain controls.
CONTROLS = [
 ('padding-suffix','NativeShake','NativeShake.Sponge.Start.',
  'XorByte(position,0x1f); XorByte(rate-1,0x80);','XorByte(position,0x06); XorByte(rate-1,0x80);'),
 ('padding-final-bit','NativeShake','NativeShake.Sponge.Start.',
  'XorByte(position,0x1f); XorByte(rate-1,0x80);','XorByte(position,0x1f); XorByte(rate-1,0x00);'),
 ('padding-shared-octet','NativeShake','NativeShake.Sponge.Start.',
  'XorByte(position,0x1f); XorByte(rate-1,0x80);',
  'if position != rate-1 { XorByte(position,0x1f); } XorByte(rate-1,0x80);'),
 ('zero-read-phase','NativeShake','NativeShake.Sponge.Read.',
  '      Start();\n      ghost var initial := Model();',
  '      if output.Length == 0 { return; }\n      Start();\n      ghost var initial := Model();'),
 ('input-after-output','NativeShake','NativeShake.Sponge.Update.',
  'if squeezing { return 1; }','if squeezing { return 0; }'),
 ('overflow-safe-slices','NativeShake','NativeShake.Sponge.Update.',
  'length > size-offset','offset+length > size'),
 ('absorb-boundary','NativeShake','NativeShake.Sponge.AbsorbOne.',
  'if position+1 == rate {','if position == rate {'),
 ('squeeze-boundary','NativeShake','NativeShake.Sponge.Next.',
  'if position == rate { Permute(); position := 0; }','if false { Permute(); position := 0; }'),
 ('absorb-byte-order','NativeShake','NativeShake.XorWord.',
  '{ word ^ ((value as bv64) << (8*(at%8))) }','{ word ^ ((value as bv64) << (8*(7-at%8))) }'),
 ('squeeze-byte-order','NativeShake','NativeShake.Sponge.Next.',
  'value := ((lanes[position/8] >> (8*(position%8))) & 255) as bv8;',
  'value := ((lanes[position/8] >> (8*(7-position%8))) & 255) as bv8;'),
 ('wipe-scratch','NativeShake','NativeShake.Sponge.Destroy.',
  'K.Wipe(lanes); K.Wipe(scratch); K.Wipe(parity);','K.Wipe(lanes); K.Wipe(parity);'),
 ('wipe-parity','NativeShake','NativeShake.Sponge.Destroy.',
  'K.Wipe(lanes); K.Wipe(scratch); K.Wipe(parity);','K.Wipe(lanes); K.Wipe(scratch);'),
 ('round-constant','NativeKeccak','NativeKeccak.Constant.',
  '{ if i == 0 then 0x0000000000000001','{ if i == 0 then 0x0000000000000000'),
 ('rotation-table','NativeKeccak','NativeKeccak.Offset.',
  'else if i == 2 then 62','else if i == 2 then 61'),
 ('source-table','NativeKeccak','NativeKeccak.Source.',
  'else if i == 1 then 6','else if i == 1 then 7'),
 ('round-count','NativeKeccak','NativeKeccak.PermuteScratch.',
  'for i: T.I := 0 to 24','for i: T.I := 0 to 23'),
 ('domain-rates','NativeShake','NativeShakePublicDomain.AllRates.',
  'constructor(r: T.I)\n      requires S.ValidRate(r as int)',
  'constructor(r: T.I)\n      requires r == 136'),
 ('domain-empty-reads','NativeShake','NativeShakePublicDomain.AllReads.',
  'requires Valid() && T.JavaLength(output.Length)',
  'requires Valid() && T.JavaLength(output.Length) && output.Length > 0'),
 ('domain-squeeze-boundary','NativeShake','NativeShakePublicDomain.AllReads.',
  'requires Valid() && T.JavaLength(output.Length)',
  'requires Valid() && T.JavaLength(output.Length) && position < rate'),
 ('domain-input','NativeShake','NativeShakePublicDomain.AllUpdates.',
  'requires Valid() && T.JavaLength(input.Length)',
  'requires Valid() && T.JavaLength(input.Length) && input.Length > 0'),
 ('domain-slices','NativeShake','NativeShakePublicDomain.AllUpdates.',
  'requires Valid() && T.JavaLength(input.Length)',
  'requires Valid() && T.JavaLength(input.Length) && 0 <= offset && 0 <= length'),
 ('domain-output-length','NativeShake','NativeShakePublicDomain.AllXofs.',
  'requires S.ValidRate(rate as int) && T.JavaLength(input.Length) && 0 <= length',
  'requires S.ValidRate(rate as int) && T.JavaLength(input.Length) && 0 < length'),
]


def mutations(folder,sources,name,stem,old,new,source_root=ROOT):
    witness = None
    for source in sources:
        content = source.read_text()
        relative = source.relative_to(source_root)
        if relative == Path('formal/crypto')/(stem+'.dfy'):
            if content.count(old) != 1:
                raise RuntimeError('Mutation anchor changed: '+name)
            content = content.replace(old,new)
            if name == 'absorb-byte-order':
                anchor = 'function XorWord(word: bv64, at: T.I, value: bv8): bv64'
                if content.count(anchor) != 1:
                    raise RuntimeError('Witness anchor changed')
                content = content.replace(anchor,anchor+'\n    requires at == 0 && value == 1')
                witness = {'at':0,'value':1,'word':'arbitrary bv64'}
        target = folder/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(content)
    return witness


def expected_inventory(inventory):
    assertions = 48+1728  # two checks per slice and one per permutation
    for row in inventory:
        assertions += 67
        for size,modulus in ((row['input_bytes'],23),(row['output_bytes'],37)):
            at = 0
            while at < size:
                at += min(size-at,1+at%modulus)
                assertions += 2
    result = dict(EXPECTED_TESTS,assertions=assertions,vectors=len(inventory),partitions=len(inventory))
    if result != EXPECTED_TESTS:
        raise RuntimeError('Independent Java assertion inventory changed')
    return result


def native_audit(generated,bytecode):
    paths = [generated/'NativeKeccak/__default.java',generated/'NativeShake/__default.java',
             generated/'NativeShake/Sponge.java']
    exceptions = []
    size_expression = re.compile(r'dafny\.Helpers\.toIntChecked\(\(java\.math\.BigInteger\.valueOf\((?:25|5)L\)\), "Java arrays may be no larger than the maximum 32-bit signed int"\)')
    zero_expression = 'dafny.Helpers.toInt((java.math.BigInteger.ZERO))'
    for path in paths:
        text = path.read_text()
        for number,line in enumerate(text.splitlines(),1):
            clean,count = size_expression.subn('PUBLIC_ARRAY_SIZE',line)
            if count:
                if '.newArray(PUBLIC_ARRAY_SIZE)' not in clean or count != 1:
                    raise RuntimeError('Unexpected public array-size consumer')
                exceptions.append({'file':str(path.relative_to(generated)),'line':number,'kind':'public array size','text':line.strip()})
            if zero_expression in clean:
                if path != paths[0] or clean.count(zero_expression) != 1 or '(a)[('+zero_expression+')]' not in clean:
                    raise RuntimeError('Unexpected public zero index consumer')
                exceptions.append({'file':str(path.relative_to(generated)),'line':number,'kind':'public lane zero index','text':line.strip()})
                clean = clean.replace(zero_expression,'PUBLIC_ZERO_INDEX')
            if re.search(r'BigInteger|DafnySequence|DafnyMap|DafnySet|DafnyMultiset|IntegerRange|(?:Integer|Long|Byte)\.valueOf',clean):
                raise RuntimeError('Non-native expression: '+str(path)+':'+str(number)+':'+line)
    # This generated unused range helper is not an execution entry point. Its
    # body is checked for the exact compiler spelling and all native callers
    # above must contain zero references. The reachable initializer is audited.
    types = (generated/'NativeTypes/I.java').read_text()
    range_helper = '''  public static java.util.ArrayList<java.lang.Integer> IntegerRange(java.math.BigInteger lo, java.math.BigInteger hi) {
    java.util.ArrayList<java.lang.Integer> arr = new java.util.ArrayList<>();
    for (java.math.BigInteger j = lo; j.compareTo(hi) < 0; j = j.add(java.math.BigInteger.ONE)) { arr.add(java.lang.Integer.valueOf(j.intValue())); }
    return arr;
  }
'''
    witness = 'public static int Witness = ((java.lang.Number) (java.math.BigInteger.ZERO)).intValue();'
    if types.count(range_helper) != 1 or types.count(witness) != 1:
        raise RuntimeError('NativeTypes helper/initializer changed')
    cleaned = types.replace(range_helper,'').replace(witness,'PUBLIC_ZERO_WITNESS')
    if re.search(r'BigInteger|DafnySequence|(?:Integer|Long|Byte)\.valueOf',cleaned):
        raise RuntimeError('Unexpected NativeTypes runtime expression')
    lines = bytecode.splitlines()
    bytecode_exceptions = []
    external_calls = {
        'NativeTypes/I._typeDescriptor:()Ldafny/TypeDescriptor;',
        'dafny/DafnyEuclidean.EuclideanDivision:(II)I',
        'dafny/DafnyEuclidean.EuclideanModulus:(II)I',
        'dafny/Helpers.bv64ShiftLeft:(JB)J','dafny/Helpers.bv64ShiftRight:(JB)J',
        'dafny/Helpers.toInt:(I)I','dafny/Helpers.toInt:(Ljava/math/BigInteger;)I',
        'dafny/Helpers.toIntChecked:(JLjava/lang/String;)I',
        'dafny/Helpers.toIntChecked:(Ljava/math/BigInteger;Ljava/lang/String;)I',
        'dafny/TypeDescriptor.fillThenReturnArray:(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;',
        'dafny/TypeDescriptor.newArray:(I)Ljava/lang/Object;',
        'java/lang/Byte.toUnsignedLong:(B)J','java/lang/Byte.valueOf:(B)Ljava/lang/Byte;',
        'java/lang/Integer.signum:(I)I','java/lang/Integer.valueOf:(I)Ljava/lang/Integer;',
        'java/lang/Long.valueOf:(J)Ljava/lang/Long;','java/lang/Object."<init>":()V',
        'java/math/BigInteger.valueOf:(J)Ljava/math/BigInteger;',
    }
    called = sorted(set(re.findall(r'// (?:InterfaceMethod|Method) (\S+)',bytecode)))
    for call in called:
        method = call.split(':',1)[0]
        if '.' not in method:  # another method of this fully audited class
            continue
        if method.split('.',1)[0] in ('NativeKeccak/__default','NativeShake/__default','NativeShake/Sponge'):
            continue
        if call not in external_calls:
            raise RuntimeError('Unexpected native runtime callee: '+call)
    if 'invokedynamic' in bytecode:
        raise RuntimeError('Unexpected dynamic native runtime call')
    for index,line in enumerate(lines):
        if re.search(r'DafnySequence|DafnyMap|DafnySet|DafnyMultiset|IntegerRange|(?:SpongeSpec|KeccakSpec|VerifiedKeccak)/',line):
            raise RuntimeError('Native bytecode calls a non-native operation')
        previous = lines[index-1] if index else ''
        if re.search(r'(?:Integer|Long|Byte)\.valueOf',line) and 'BigInteger' not in line:
            allowed = ('Integer.valueOf' in line and 'NativeTypes/I.Witness:I' in previous or
                       'Long.valueOf' in line and 'lconst_0' in previous or
                       'Byte.valueOf' in line and 'iconst_0' in previous)
            if not allowed:
                raise RuntimeError('Value-dependent primitive boxing: '+line)
            bytecode_exceptions.append({'instruction':line.strip(),'source':previous.strip()})
        if 'java/math/BigInteger' in line:
            if 'BigInteger.valueOf' in line:
                if not re.search(r'// long (25|5)l',previous):
                    raise RuntimeError('Nonconstant BigInteger construction: '+line)
                context = '\n'.join(lines[index+1:index+5])
                if 'dafny/Helpers.toIntChecked:(Ljava/math/BigInteger;Ljava/lang/String;)I' not in context or 'dafny/TypeDescriptor.newArray:(I)Ljava/lang/Object;' not in context:
                    raise RuntimeError('Unexpected fixed array-size consumer')
            elif 'BigInteger.ZERO:' in line:
                if index+1 >= len(lines) or 'dafny/Helpers.toInt:(Ljava/math/BigInteger;)I' not in lines[index+1]:
                    raise RuntimeError('Unexpected constant-zero consumer')
            elif 'dafny/Helpers.toIntChecked:' in line:
                if not any('BigInteger.valueOf' in x for x in lines[max(0,index-3):index]):
                    raise RuntimeError('Nonconstant BigInteger array size')
            elif 'dafny/Helpers.toInt:' in line:
                if 'BigInteger.ZERO:' not in previous:
                    raise RuntimeError('Nonconstant BigInteger index')
            else:
                raise RuntimeError('Unexpected BigInteger instruction: '+line)
            bytecode_exceptions.append({'instruction':line.strip(),'source':'public constant array size or index'})
    return {'sources':[str(p.relative_to(generated)) for p in paths]+['NativeTypes/I.java'],
            'secret_big_integer_sequence_or_value_boxings':0,
            'public_constant_source_exceptions':exceptions,
            'public_constant_bytecode_exceptions':bytecode_exceptions,
            'called_methods':called,
            'native_types_initializer':'fixed zero Witness; primitive descriptor',
            'excluded_helper':'NativeTypes.I.IntegerRange: exact generated body checked, zero native call sites',
            'scope':'Native execution classes; generated mathematical modules are not runtime callees'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,default=Path.home()/'.cache/microproxy-formal')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--java-home',type=Path,action='append',required=True,
                        help='Exactly two homes: JDK 21, then JDK 25')
    parser.add_argument('--runtime-jar',type=Path,help='Exact delivered runtime instead of the compiler bundle')
    parser.add_argument('--runtime-sha256',help='Required SHA256 when selecting --runtime-jar')
    args = parser.parse_args()
    if bool(args.runtime_jar) != bool(args.runtime_sha256):
        parser.error('--runtime-jar and --runtime-sha256 must be supplied together')
    if len(args.java_home) != 2:
        parser.error('Supply JDK 21 and JDK 25 homes in that order')
    homes = [p.resolve(strict=True) for p in args.java_home]
    args.output.mkdir(parents=True,exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='native-shake-',dir=args.output.resolve()))
    print('output '+str(out),flush=True)
    receipt = {'scope':__doc__,'commands':[],'proofs':{},'audits':{},'controls':{},'java':[]}
    sources = closure(HERE/'native_shake_domain.dfy')
    harness = HERE/'native_shake_java/io/github/mahmoudimus/quic/tls/NativeShakeTest.java'
    reference = ROOT/'formal/crypto/reference/Shake.java'
    inputs = sources+[Path(__file__).resolve(),SHARED,harness,reference,TOOLCHAIN,ROOT/'formal/dafny/tools.json',HERE/'reference/provenance.json']
    before = snapshot(inputs,ROOT)
    frozen = out/'inputs'
    for source in inputs:
        target = frozen/source.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target)
    frozen_inputs = [frozen/source.relative_to(ROOT) for source in inputs]
    frozen_sources = [frozen/source.relative_to(ROOT) for source in sources]
    if snapshot(frozen_inputs,frozen) != before or snapshot(inputs,ROOT) != before:
        raise RuntimeError('Inputs changed while creating the immutable replay snapshot')
    # Proof, mutation, translation, harness compilation, and vector generation
    # consume only this checked snapshot. Live files are rechecked at the end.
    oracle = load('native_shake_frozen_oracle',frozen/'formal/crypto/shake_checks.py')
    module = load('native_shake_pinned_toolchain',frozen/'formal/dafny/toolchain.py')
    dafny,runtime,manifest,asset = module.install(args.cache)
    if args.runtime_jar:
        runtime = args.runtime_jar.resolve(strict=True)
        if not re.fullmatch(r'[0-9a-f]{64}',args.runtime_sha256) or sha(runtime) != args.runtime_sha256:
            raise RuntimeError('Selected runtime SHA256 mismatch')
    if manifest['version'] != '4.9.1':
        raise RuntimeError('Expected official pinned Dafny 4.9.1')
    solver = dafny.parent/'z3/bin/z3-4.12.1'
    flags = [*FLAGS,'--solver-path',str(solver)]
    oracle_paths = [Path(sys.executable).resolve(),Path(hashlib.__file__).resolve(),Path(_hashlib.__file__).resolve()]

    def tool_snapshot():
        return {'dafny_distribution':tree(dafny.parent.parent),
                'dafny_archive_sha256':sha(args.cache/asset['archive']),
                'selected_runtime':{'path':str(runtime),'sha256':sha(runtime)},
                'java_homes':[{'home':str(p),'files':tree(p)} for p in homes],
                'python_oracle':snapshot(oracle_paths)}
    tool_before = tool_snapshot()

    def call(label,command):
        command = list(map(str,command))
        print(label,flush=True)
        process = subprocess.Popen(command,cwd=ROOT,text=True,stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,start_new_session=True)
        try:
            output,_ = process.communicate(timeout=600)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL)
            output,_ = process.communicate()
            (out/(label+'.log')).write_text(output)
            raise
        (out/(label+'.log')).write_text(output)
        receipt['commands'].append({'label':label,'command':command,'exit':process.returncode})
        return process.returncode,output

    status,version = call('dafny-version',[dafny,'--version'])
    if status or not version.startswith('4.9.1+'):
        raise RuntimeError('Dafny version mismatch')
    status,version = call('z3-version',[solver,'--version'])
    if status or 'Z3 version 4.12.1' not in version:
        raise RuntimeError('Z3 version mismatch')
    for source in sources:
        target = frozen/source.relative_to(ROOT)
        status,output = call('audit-'+source.stem,[dafny,'audit',target])
        if status or shared.BAD_DIAGNOSTIC.search(output) or 'Dafny auditor completed with 0 findings' not in output:
            raise RuntimeError('Assumption audit failed: '+str(source))
        receipt['audits'][str(source.relative_to(ROOT))] = 0
        status,output = call('proof-'+source.stem,[dafny,'verify',target,*flags])
        receipt['proofs'][str(source.relative_to(ROOT))] = proof_result(status,output)
    for name,stem,symbol,old,new in CONTROLS:
        folder = out/name
        witness = mutations(folder,frozen_sources,name,stem,old,new,frozen)
        target = folder/'formal/crypto'/('native_shake_domain.dfy' if name.startswith('domain-') else stem+'.dfy')
        mutant_hashes = tree(folder,'*.dfy')
        extra = []
        if name == 'round-count':
            lines = target.read_text().splitlines()
            positions = [i+1 for i,line in enumerate(lines) if line.strip() == 'assert completed == 24;']
            if len(positions) != 1:
                raise RuntimeError('Round-count control needs an erased completed-round assertion')
            extra = ['--isolate-assertions','--filter-position',f'{target.name}:{positions[0]}']
        status,output = call('control-'+name,[dafny,'verify',target,'--filter-symbol',symbol,*extra,*flags])
        receipt['controls'][name] = proof_result(status,output,negative=True)
        if tree(folder,'*.dfy') != mutant_hashes:
            raise RuntimeError('Mutant source drift: '+name)
        receipt['controls'][name]['inputs'] = mutant_hashes
        if witness:
            receipt['controls'][name]['negative_control_witness'] = witness
    vector_file = out/'hashlib-vectors.tsv'
    inventory = oracle.vectors(vector_file)
    tests = expected_inventory(inventory)
    vector_hash = sha(vector_file)
    status,output = call('generate-java',[dafny,'translate','java',frozen/'formal/crypto/NativeShake.dfy',
                                        '--output',out/'NativeShake',*flags])
    receipt['generation'] = proof_result(status,output)
    generated = out/'NativeShake-java'
    generated_hashes = tree(generated,'*.java')
    if not generated_hashes:
        raise RuntimeError('No generated Java files')
    classes = out/'classes'
    classes.mkdir()
    status,output = call('javac',[homes[0]/'bin/javac','--release','21','-cp',runtime,'-d',classes,
                                *sorted(generated.rglob('*.java')),frozen/harness.relative_to(ROOT),frozen/reference.relative_to(ROOT)])
    if status or 'warning:' in output.lower():
        raise RuntimeError('Generated Java compilation failed or warned')
    class_hashes = tree(classes,'*.class')
    for major,home in zip((21,25),homes):
        status,version = call(f'java-{major}-version',[home/'bin/java','-version'])
        if status or not re.search(r'version "'+str(major)+r'[.\"]',version):
            raise RuntimeError('Expected JDK '+str(major))
        status,output = call(f'java-{major}',[home/'bin/java','-Xmx1024m','-ea','-cp',
                                            str(classes)+os.pathsep+str(runtime),
                                            'io.github.mahmoudimus.quic.tls.NativeShakeTest',vector_file])
        matches = re.findall(r'^PASS NativeShakeTest (\{.*\})$',output,re.M)
        if status or len(matches) != 1 or json.loads(matches[0]) != tests:
            raise RuntimeError('Native Java replay or exact assertion inventory failed')
        receipt['java'].append({'version':version,'tests':json.loads(matches[0])})
    status,bytecode = call('native-bytecode',[homes[0]/'bin/javap','-c','-p','-cp',classes,
                                             'NativeKeccak.__default','NativeShake.__default','NativeShake.Sponge'])
    if status:
        raise RuntimeError('Native bytecode inspection failed')
    receipt['native_runtime_audit'] = native_audit(generated,bytecode)
    for label,cp,classname in [('types',classes,'NativeTypes.I'),('euclidean',runtime,'dafny.DafnyEuclidean'),
                               ('helpers',runtime,'dafny.Helpers'),('descriptor',runtime,'dafny.TypeDescriptor')]:
        status,_ = call('runtime-'+label+'-bytecode',[homes[0]/'bin/javap','-c','-p','-cp',cp,classname])
        if status:
            raise RuntimeError('Runtime inspection failed: '+classname)
    after = snapshot(inputs,ROOT)
    if after != before or closure(HERE/'native_shake_domain.dfy') != sources:
        raise RuntimeError('Source, include graph, harness, reference, or tool manifest drift')
    if snapshot(frozen_inputs,frozen) != before:
        raise RuntimeError('Frozen replay inputs changed during replay')
    tool_after = tool_snapshot()
    if tool_after != tool_before:
        raise RuntimeError('Compiler, solver, runtime, JDK, or Python oracle drift')
    if tree(generated,'*.java') != generated_hashes or tree(classes,'*.class') != class_hashes:
        raise RuntimeError('Generated or compiled artifact drift')
    if sha(vector_file) != vector_hash:
        raise RuntimeError('Independent vectors changed during replay')
    receipt.update({'inputs_before':before,'inputs_after':after,'tools_before':tool_before,
                    'tools_after':tool_after,'toolchain_asset':asset,'python':sys.version,
                    'openssl':ssl.OPENSSL_VERSION,'platform':platform.platform(),
                    'generated_java':generated_hashes,'compiled_classes':class_hashes,
                    'snapshot_root':str(frozen),'frozen_inputs':snapshot(frozen_inputs,frozen),
                    'vectors':{'sha256':vector_hash,'count':len(inventory),'inventory':inventory},
                    'runtime_sha256':sha(runtime)})
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'output':str(out),'proofs':receipt['proofs'],
                      'controls':{k:{f:v for f,v in r.items() if f != 'inputs'} for k,r in receipt['controls'].items()},
                      'java':receipt['java']},indent=2))


if __name__ == '__main__':
    main()

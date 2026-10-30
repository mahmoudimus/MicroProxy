#!/usr/bin/env python3
"""Replay native ML-KEM refinement, cleanup controls and finite Java compatibility."""
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
DEFAULT_DAFNY = Path.home()/'.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
MAVEN_RUNTIME_SHA256 = 'dc62d34579572da104eda5ab812cf1aae8b1eae7bb952ce260a12b3c7c458ce6'
DEFAULT_RUNTIME = Path.home()/'.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'
REFERENCE_PROVENANCE_SHA256 = '5ecd37f14f0390f01c21c566eb10ecf1923c84f9966a1d0e861b4c6353777b3f'
EXPECTED_TESTS = {'assertions':7813, 'rounds':100, 'malformed':30, 'selections':3265, 'destroyed':101}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def graph(path, seen=None):
    seen = set() if seen is None else seen
    path = path.resolve()
    if path in seen:
        return seen
    seen.add(path)
    for include in re.findall(r'^include "([^"]+)"',path.read_text(),re.M):
        graph(path.parent/include,seen)
    return seen


def jvm_method(bytecode, signature):
    marker = '  '+signature+';'
    start = bytecode.index(marker)
    following = re.search(r'\n  (?:public|private|protected|static)\b',bytecode[start+len(marker):])
    end = start+len(marker)+following.start() if following else len(bytecode)
    return bytecode[start:end]


def native_runtime_guards(bytecode, helpers, byte_helpers):
    """Source discipline checks, not a JVM timing theorem.

    Index, length, width, table-offset and rejection-sampling metadata are
    public. Datatype toString/hashCode and newtype IntegerRange metadata are
    outside the ordinary KEM entry-point call graph. Payload scalars must not
    enter boxed arithmetic or a sign-sensitive runtime shift helper.
    """
    helper_calls = sorted(set(re.findall(r'// Method dafny/Helpers\.([^:]+):([^\s]+)',bytecode)))
    allowed = {'bv64ShiftLeft','bv64ShiftRight','toInt','toIntChecked','toString'}
    if any(name not in allowed for name,descriptor in helper_calls):
        raise RuntimeError('Unreviewed or payload-sensitive runtime helper')
    if re.search(r'NativeTypes/(?:I|L)\.IntegerRange|DafnySequence',bytecode):
        raise RuntimeError('Unexpected executable sequence/newtype enumeration')
    boxes = []
    lines = bytecode.splitlines()
    for index,line in enumerate(lines):
        found = re.search(r'java/lang/(Byte|Short|Integer|Long)\.valueOf:',line)
        if not found:
            continue
        prior = lines[index-1] if index else ''
        kind = found[1]
        permitted = (kind == 'Integer' and 'NativeTypes/I.Witness:I' in prior) or (
            kind == 'Byte' and re.search(r'\biconst_0\b',prior)) or (
            kind == 'Long' and re.search(r'\blconst_0\b',prior))
        if not permitted:
            raise RuntimeError('Payload scalar boxing: '+line.strip())
        boxes.append({'instruction':line.strip(),'source':'fixed public zero/Witness0'})
    shift_checks = {}
    for direction,operation in (('Right','lushr'),('Left','lshl')):
        section = jvm_method(helpers,'public static long bv64Shift'+direction+'(long, byte)')
        ops = re.findall(r'^\s*\d+:\s+(\w+)',section,re.M)
        expected = ['iload_2','bipush','if_icmpne','lconst_0','lreturn','lload_0','iload_2',operation,'lreturn']
        if ops != expected or not re.search(r'1: bipush\s+64',section):
            raise RuntimeError('Runtime wide shift changed; re-review payload dependence')
        shift_checks['bv64Shift'+direction] = 'Only shift-distance==64 branch; first operand never tested'
    for signature in ('public static int toUnsignedInt(byte)','public static long toUnsignedLong(byte)'):
        section = jvm_method(byte_helpers,signature)
        if re.search(r'^\s*\d+:\s+(?:if\w*|invoke\w*|[il](?:div|rem)|[al]newarray|tableswitch|lookupswitch)\b',section,re.M):
            raise RuntimeError('Unsigned byte conversion changed; re-review payload dependence')
    selector = jvm_method(bytecode,'public static byte[] Select(byte[], byte[], byte[], byte[])')
    branches = re.findall(r'^\s*\d+:\s+(if\w*)\b',selector,re.M)
    if branches != ['if_icmpge','if_icmpge'] or re.search(r'\b(?:tableswitch|lookupswitch)\b',selector):
        raise RuntimeError('Selector payload branch or changed loop control')
    if not re.search(r'sipush\s+1088',selector) or not re.search(r'bipush\s+32',selector):
        raise RuntimeError('Selector fixed comparison/selection bounds changed')
    shifts = re.findall(r'bipush\s+(\d+)\n\s*\d+: invokestatic[^\n]*dafny/Helpers\.bv64ShiftRight:',selector)
    if shifts != ['56']:
        raise RuntimeError('Selector shift must use public literal distance56')
    if re.search(r'BigInteger|DafnySequence|DafnyEuclidean|\b[il](?:div|rem)\b',selector):
        raise RuntimeError('Selector contains non-native or division arithmetic')
    return {'selector_bounds':[1088,32],'selector_conditional_opcodes':branches,
            'runtime_helper_calls':helper_calls,'wide_shift_helpers':shift_checks,
            'unsigned_byte_conversions':'branchless primitive operations',
            'constant_zero_boxings':boxes,'payload_scalar_boxings':0,
            'metadata_boundary':'toInt/toIntChecked and Euclidean calls carry public lengths, indices, widths, loop counts and table offsets; BigInteger carries only fixed-size initialization indices or array lengths.',
            'scope':'Native executable classes and pinned runtime helper bodies; source/bytecode discipline, not a JVM timing theorem'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dafny',type=Path,default=DEFAULT_DAFNY)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--runtime',type=Path,default=DEFAULT_RUNTIME)
    p.add_argument('--java-home',type=Path,action='append',required=True)
    p.add_argument('--scope',choices=('full','owned'),default='full',
                   help='owned is explicitly partial evidence; full rechecks every dependency')
    args = p.parse_args()
    if not args.runtime.is_file() or sha(args.runtime) != MAVEN_RUNTIME_SHA256:
        raise RuntimeError('Expected pinned Maven org.dafny:DafnyRuntime:4.9.1 artifact')
    args.output.mkdir(parents=True,exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='native-kem-',dir=args.output)).resolve()
    print(out,flush=True)
    deps = sorted(graph(HERE/'native_kem_domain.dfy'))
    provenance = HERE/'reference/provenance.json'
    if not provenance.is_file() or sha(provenance) != REFERENCE_PROVENANCE_SHA256:
        raise RuntimeError('Expected pinned pre-adoption reference provenance')
    reference_entries = json.loads(provenance.read_text())['files']
    refs = [ROOT/entry['reference'] for entry in reference_entries]
    if set(refs) != {HERE/'reference'/n for n in ('Shake.java','MlKem768.java')} or any(
        not path.is_file() or sha(path) != entry['sha256'] for path,entry in zip(refs,reference_entries)):
        raise RuntimeError('Pre-adoption comparison source differs from pinned provenance')
    inputs = deps+[HERE/n for n in ('native_kem_checks.py','native_kem_test.java','native_kem_hash.java')]+[provenance]+refs
    before = {str(f.relative_to(ROOT)):sha(f) for f in inputs}
    (out/'input-digests-start.json').write_text(json.dumps(before,indent=2)+'\n')
    solver = args.dafny.parent/'z3/bin/z3-4.12.1'
    flags = ['--cores','2','--verification-time-limit','30','--resource-limit','50000000','--solver-path',str(solver)]
    receipt = {'scope':args.scope,'commands':[],'proofs':{},'controls':{},'java':[],
               'limitations':['Proposed 280-iteration sampling cap requires production policy review; owned source writes are proved, physical erasure is a compiler/JIT/provider assumption.',
                              'JVM timing, compiler/runtime/provider correctness, entropy and cryptographic security are not proved.',
                              'Finite Java comparisons do not prove universal source/compiler refinement.',
                              'The Java facade must hide generated mutable key constructors/fields, prevent external aliases and enforce Valid/destroyed-state lifetimes.']}

    def call(label,command):
        command = list(map(str,command))
        print(label,flush=True)
        r = subprocess.run(command,cwd=ROOT,text=True,capture_output=True,timeout=1800)
        output = r.stdout+r.stderr
        (out/(label+'.log')).write_text(output)
        receipt['commands'].append({'label':label,'command':command,'exit':r.returncode})
        return r.returncode,output

    def prove(label,command):
        status,output = call(label,command)
        match = re.search(r'verifier finished with (\d+) verified, 0 errors\s*$',output)
        if status or not match or int(match[1]) == 0 or 'Warning:' in output:
            raise RuntimeError(f'{label} failed: {out/(label+".log")}')
        receipt['proofs'][label] = int(match[1])

    status,version = call('dafny-version',[args.dafny,'--version'])
    if status or version.strip() != '4.9.1+452c307284e1511e5c2d10b9615f4c9c15f010e2':
        raise RuntimeError('Unexpected Dafny version')
    status,solver_version = call('solver-version',[solver,'--version'])
    if status or 'Z3 version 4.12.1' not in solver_version:
        raise RuntimeError('Unexpected solver version')
    status,audit = call('audit',[args.dafny,'audit',*deps])
    warnings = [line for line in audit.splitlines() if 'Warning:' in line]
    expected_names = {('JdkHash.dfy','H'),('JdkHash.dfy','G'),('NativeJdkHash.dfy','Hash'),('NativeJdkHash.dfy','Expand')}
    found_names = {(Path(line.split('(')[0]).name,re.search(r'Warning: (\w+):',line).group(1)) for line in warnings}
    if status or 'Dafny auditor completed with 4 findings' not in audit or len(warnings) != 4 or found_names != expected_names or not all(
        'JdkHash.dfy' in line and 'explicit `{:axiom}`' in line for line in warnings):
        raise RuntimeError('Expected exactly four declarations binding two provider primitives')
    receipt['provider_assumptions'] = {'primitive_count':2,'declaration_count':4,'declarations':warnings}
    native_flags = [*flags,'--boogie','/proverOpt:O:smt.case_split=0']
    owned = [HERE/n for n in ('NativeMlKem.dfy','NativeJdkHash.dfy','native_kem_domain.dfy')]
    if args.scope == 'full':
        native = [f for f in deps if f.name.startswith('Native') or f.name == 'native_kem_domain.dfy']
        original = [f for f in deps if f not in native]
        prove('proof-native-composition',[args.dafny,'verify',*owned,*flags])
        prove('proof-reference-graph',[args.dafny,'verify',*original,*flags])
        kernels = [f for f in native if f not in owned]
        prove('proof-native-kernels',[args.dafny,'verify',*kernels,*native_flags])
    else:
        prove('proof-owned',[args.dafny,'verify',*owned,*flags])

    source = re.sub(r'^include "([^"]+)"',lambda m:'include "'+str(HERE/m[1])+'"',(HERE/'NativeMlKem.dfy').read_text(),flags=re.M)
    controls = [
        ('wrong-coins','Encaps.','var coins := Slice(g,32,32);','var coins := Slice(g,0,32);','assert coins[..] == g[32..64];'),
        ('matrix-axis','Sample.','var first := Tag(rho,j as bv8);','var first := Tag(rho,i as bv8);',None),
        ('matrix-transpose','Row.','a[if transposed then 3*j+i else 3*i+j]','a[3*i+j]',None),
        ('reused-nonce','Noise.','Tag(seed,nonce as bv8)','Tag(seed,0 as bv8)',None),
        ('wrong-fallback-seed','Decaps.','var z := Slice(dk.seed,32,32);','var z := Slice(dk.seed,0,32);','assert z[..] == dk.seed[32..64];'),
        ('constant-selection','Select.','var mask := (((diff as bv64)-1) >> 56) as bv8;','var mask: bv8 := 255;',None),
        ('short-comparison','Select.','for i: T.I := 0 to 1088','for i: T.I := 0 to 1087',None),
        ('modulus-error-kind','Parse.','if words.Failure? { return S.Failure(S.ModulusError); }','if words.Failure? { return S.Failure(S.InvalidKeyLength); }',None),
        ('short-sampler','SamplePrefix.','var sample := NS.Feed(empty,bytes);','var shortened := Slice(bytes,0,837);\n    var sample := NS.Feed(empty,shortened);',None),
        ('missing-failure-wipe','SamplePrefix.','WipeInts(sample.coeffs);','// omitted wipe',None),
        ('missing-byte-wipe','WipeBytes.','{ a[i] := 0; }','{ if i+1 < n { a[i] := 0; } }',None)]
    for name,symbol,old,new,focus in controls:
        method_name = symbol.rstrip('.')
        declaration = re.search(r'^  method\b[^\n]*\b'+re.escape(method_name)+r'\(',source,re.M)
        if not declaration:
            raise RuntimeError('Mutant method missing: '+name)
        following = re.search(r'^  (?:method|lemma|ghost (?:function|predicate))\b',source[declaration.end():],re.M)
        end_offset = declaration.end()+following.start() if following else len(source)
        section = source[declaration.start():end_offset]
        if section.count(old) != 1:
            raise RuntimeError('Mutant anchor changed: '+name)
        target = out/(name+'.dfy')
        target.write_text(source[:declaration.start()]+section.replace(old,new,1)+source[end_offset:])
        extra = []
        if focus:
            lines = target.read_text().splitlines()
            method_name = symbol.rstrip('.')
            begin = next(i for i,line in enumerate(lines) if re.search(r'\bmethod\b.*\b'+re.escape(method_name)+r'\(',line))
            end = next((i for i in range(begin+1,len(lines)) if re.match(r'^  (?:method|lemma|ghost (?:function|predicate))\b',lines[i])),len(lines))
            matches = [i+1 for i in range(begin,end) if lines[i].strip() == focus]
            if len(matches) != 1:
                raise RuntimeError('Mutant focus changed: '+name)
            extra = ['--isolate-assertions','--filter-position',f'{target.name}:{matches[0]}']
        status,output = call('control-'+name,[args.dafny,'verify',target,'--filter-symbol','NativeMlKem.'+symbol,*extra,*flags])
        match = re.search(r'verifier finished with (\d+) (?:assertions )?verified, ([1-9]\d*) errors?\s*$',output)
        if status != 4 or not match or any(x in output for x in ('timed out','out of resource','parse errors','resolution/type errors','Warning:')) or not any(x in output for x in ('could not be proved','assertion might not hold')):
            raise RuntimeError('No genuine semantic failure for '+name)
        receipt['controls'][name] = {'verified':int(match[1]),'errors':int(match[2])}

    prefix = out/'NativeMlKem'
    prove('generate-java',[args.dafny,'translate','java',*owned,'--output',prefix,*flags])
    generated = out/'NativeMlKem-java'
    classes = out/'classes';classes.mkdir()
    runtime = args.runtime
    sources = sorted(generated.rglob('*.java'))+[HERE/'native_kem_test.java',HERE/'native_kem_hash.java',*refs]
    status,output = call('javac',[args.java_home[0]/'bin/javac','--release','21','-cp',runtime,'-d',classes,*sources])
    if status:
        raise RuntimeError('Generated Java compilation failed')
    native_packages = {'NativeMlKem','NativeCodec','NativeSampling','NativePolynomial','NativeField','NativeKeccak','NativeShake'}
    witness_source = (generated/'NativeTypes/I.java').read_text()
    if 'public static int Witness = ((java.lang.Number) (java.math.BigInteger.ZERO)).intValue();' not in witness_source:
        raise RuntimeError('Native integer allocation witness is no longer fixed zero')
    native_classes = sorted('.'.join(f.relative_to(classes).with_suffix('').parts) for f in classes.rglob('*.class')
                            if f.relative_to(classes).parts[0] in native_packages)
    status,bytecode = call('native-runtime-bytecode',[args.java_home[0]/'bin/javap','-c','-p','-s','-cp',classes,*native_classes])
    if status:
        raise RuntimeError('Cannot inspect native KEM runtime callees')
    status,helpers = call('runtime-helpers-bytecode',[args.java_home[0]/'bin/javap','-c','-p','-s','-cp',runtime,'dafny.Helpers'])
    if status:
        raise RuntimeError('Cannot inspect pinned runtime helpers')
    status,byte_helpers = call('jdk-byte-conversions',[args.java_home[0]/'bin/javap','-c','-p','-s','java.lang.Byte'])
    if status:
        raise RuntimeError('Cannot inspect primitive byte conversions')
    receipt['native_runtime_guard'] = native_runtime_guards(bytecode,helpers,byte_helpers)
    # Preserve an exact inventory for the explicit caller-side metadata review.
    # The component scalar data-flow checks and reviewed caller loop bounds
    # establish this classification; this inventory is not a general taint proof.
    metadata_sites = []
    for path in sorted(generated.rglob('*.java')):
        if path.parent.name not in native_packages:
            continue
        method = None
        for number,line in enumerate(path.read_text().splitlines(),1):
            declaration = re.search(r'public (?:static )?[^\n]+? (\w+)\([^\n]*\)',line)
            if declaration:
                method = declaration[1]
            if re.search(r'dafny\.(?:Helpers|DafnyEuclidean)\.|Public(?:Div|Mod)\(|BigInteger|Integer\.signum',line):
                metadata_sites.append({'file':str(path.relative_to(generated)),'method':method,'line':number,'source':line.strip()})
    receipt['native_runtime_guard']['caller_inventory'] = metadata_sites
    receipt['native_runtime_guard']['caller_review'] = {
        'NativeMlKem':'ExpandMatrix divides/mods only its public k=0..8 counter. BigInteger carries fixed3/9 reference-array initialization indices or public array lengths. Select uses only literal56 for its wide shift.',
        'NativePolynomial':'Stage, block, coefficient and twiddle-table indices control all division, table selection and allocation; coefficients enter only the verified native field operations.',
        'NativeKeccak/NativeShake':'Rate, phase, position, input/output lengths, fixed25/5 arrays and public rotation-offset tables control metadata helpers. Payload lanes enter only bv64 shifts with public distances.',
        'NativeCodec/NativeSampling':'Widths, grouping indices and lengths are public; component operand-stack data-flow guards check PublicDiv/PublicMod/Extract/Shift boundaries. Decode(m,1) validates secret message bits, but decoded d1/d4/d10 values are bounded by1/15/1023, so IsCanonical outcomes are constant. Only d12 validation can vary; its KEM caller parses public encoded keys. Feed validates the empty/public prefix and rejects public rho-derived matrix candidates; CBD payloads avoid those branches.',
        'allocation/tuple/result':'TypeDescriptor allocation/fill dispatch uses public dimensions/type descriptors and fixed zero values. Tuple2 and Result constructors/getters retain references. No owned KEM call reaches IntegerRange, payload toString/hashCode or mutable metadata writes.',
        'boundary':'Generated constructors, mutable arrays and metadata are internal; the production facade must keep them inaccessible to callers. This review is source/runtime discipline, not a JVM timing theorem.'}
    # These regressions preserve selector semantics but violate source/runtime
    # discipline, so rejection cannot be delegated to functional proofs.
    default_source = generated/'NativeMlKem/__default.java'
    text = default_source.read_text()
    declaration = re.search(r'public static byte\[\] Select\([^\n]+\)\s*\{',text)
    start = declaration.end()-1; end = start+1; depth = 1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}'); end += 1
    selector = text[start:end]
    diff = re.search(r'byte (\w+diff);',selector)[1]
    mask_line = next(line for line in selector.splitlines() if 'bv64ShiftRight' in line)
    lhs = mask_line.split('=',1)[0]
    controls = [
        ('selector-narrow-helper',lhs+'= (byte) dafny.Helpers.bv16ShiftRight((short)(Byte.toUnsignedInt('+diff+')-1),(byte)8);','payload-sensitive runtime helper'),
        ('selector-payload-branch',lhs+'= '+diff+' == 0 ? (byte)255 : (byte)0;','Selector payload branch'),
        ('selector-payload-boxing',lhs+'= (byte) dafny.Helpers.bv64ShiftRight(Byte.toUnsignedLong(Byte.valueOf('+diff+').byteValue())-1,(byte)56);','Payload scalar boxing')]
    receipt['bytecode_controls'] = {}
    for name,replacement,expected_error in controls:
        folder = out/name; source_dir = folder/'NativeMlKem'; source_dir.mkdir(parents=True)
        mutant = source_dir/'__default.java'
        mutant.write_text(text[:start]+selector.replace(mask_line,replacement,1)+text[end:])
        status,output = call('compile-'+name,[args.java_home[0]/'bin/javac','--release','21','-cp',str(classes)+os.pathsep+str(runtime),'-d',folder,mutant])
        if status:
            raise RuntimeError('Bytecode-control compilation failed: '+name)
        status,mutant_code = call('inspect-'+name,[args.java_home[0]/'bin/javap','-c','-p','-s','-cp',str(folder)+os.pathsep+str(classes),'NativeMlKem.__default'])
        if status:
            raise RuntimeError('Bytecode-control inspection failed: '+name)
        try:
            native_runtime_guards(mutant_code,helpers,byte_helpers)
        except RuntimeError as failure:
            if expected_error not in str(failure):
                raise RuntimeError('Wrong bytecode-control rejection: '+name+' '+str(failure))
            receipt['bytecode_controls'][name] = {'rejected':str(failure)}
        else:
            raise RuntimeError('Bytecode-control regression accepted: '+name)
    for i,home in enumerate(args.java_home):
        status,java_version = call(f'java-{i}-version',[home/'bin/java','-version'])
        if status:
            raise RuntimeError('JVM version check failed')
        status,jdk_bytes = call(f'java-{i}-byte-conversions',[home/'bin/javap','-c','-p','-s','java.lang.Byte'])
        if status:
            raise RuntimeError('Cannot inspect this JDK unsigned byte conversion')
        native_runtime_guards(bytecode,helpers,jdk_bytes)
        status,output = call(f'java-{i}',[home/'bin/java','-Xmx1024m','-ea','-cp',str(classes)+os.pathsep+str(runtime),'io.github.mahmoudimus.quic.tls.native_kem_test'])
        matches = re.findall(r'^PASS native_kem_test (\{.*\})$',output,re.M)
        if status or len(matches) != 1 or json.loads(matches[0]) != EXPECTED_TESTS:
            raise RuntimeError('Generated Java test inventory failed or changed')
        receipt['java'].append({'version':java_version,'tests':json.loads(matches[0])})
    receipt['inputs'] = {str(f.relative_to(ROOT)):sha(f) for f in inputs}
    if receipt['inputs'] != before:
        changed = [name for name in before if receipt['inputs'][name] != before[name]]
        (out/'input-digests-end.json').write_text(json.dumps(receipt['inputs'],indent=2)+'\n')
        raise RuntimeError('Proof or reference input changed during replay: '+', '.join(changed))
    native_sources = [f for f in generated.rglob('*.java') if f.parent.name.startswith('Native')]
    if any('DafnySequence' in f.read_text() for f in native_sources):
        raise RuntimeError('Unexpected executable sequence use in a native class')
    receipt['native_big_integer_sites'] = {str(f.relative_to(generated)):[{'line':i+1,'source':line.strip()} for i,line in enumerate(f.read_text().splitlines()) if 'BigInteger' in line] for f in native_sources}
    receipt['generated_java'] = {str(f.relative_to(generated)):sha(f) for f in sorted(generated.rglob('*.java'))}
    receipt['compiled_classes'] = {str(f.relative_to(classes)):sha(f) for f in sorted(classes.rglob('*.class'))}
    receipt['dafny_sha256'] = sha(args.dafny)
    receipt['solver_sha256'] = sha(solver)
    receipt['runtime_sha256'] = sha(runtime)
    receipt['runtime_coordinate'] = 'org.dafny:DafnyRuntime:4.9.1'
    if receipt['runtime_sha256'] != MAVEN_RUNTIME_SHA256:
        raise RuntimeError('Maven runtime changed during replay')
    receipt['footprint'] = {'generated_java_bytes':sum(f.stat().st_size for f in generated.rglob('*.java')),
                            'compiled_class_bytes':sum(f.stat().st_size for f in classes.rglob('*.class')),
                            'runtime_bytes':runtime.stat().st_size}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('PASS '+args.scope+' native KEM replay '+str(out),flush=True)


if __name__ == '__main__':
    main()

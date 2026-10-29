#!/usr/bin/env python3
"""Replay native polynomial proofs, semantic controls, bytecode and exact Java.

The dependency proof, native refinement proof, finite compatibility checks and
JVM assumptions are reported separately. No handwritten Java replaces generated
arithmetic. Physical erasure, JIT behavior and timing remain separate trust limits.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, log, env=None):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=1200)
    log.write_text(result.stdout)
    return result.returncode, result.stdout


def positive(command, log, env=None):
    status, text = run(command, log, env)
    if status:
        raise RuntimeError(f'{log.name}: exit {status}')
    return text


def verified(command, log):
    text = positive(command, log)
    found = re.search(r'finished with (\d+) verified, 0 errors\s*$', text)
    if not found or int(found.group(1)) == 0:
        raise RuntimeError(f'{log.name}: no positive proof count')
    return int(found.group(1))


def absolute_includes(text):
    return re.sub(r'include "([^"]+)"', lambda m: f'include "{(HERE / m.group(1)).resolve()}"', text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dafny', type=Path, default=DAFNY)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/native-polynomial-checks')
    parser.add_argument('--java-home', type=Path, default=Path('/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
    parser.add_argument('--runtime-home', type=Path, action='append', default=[])
    parser.add_argument('--runtime-jar', type=Path, help='Exact delivered Dafny runtime JAR; defaults to compiler bundle')
    parser.add_argument('--runtime-sha256', help='Required SHA256 for the selected runtime JAR')
    parser.add_argument('--phase', choices=['all','proof','controls','java'], default='all')
    args = parser.parse_args()
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'native_polynomial_report.json'
    dafny = args.dafny.resolve(); solver = dafny.parent / 'z3/bin/z3-4.12.1'
    common = ['--cores','2','--verification-time-limit','30','--resource-limit','50000000','--solver-path',solver]
    native = [*common,'--solver-option','O:smt.case_split=0']
    source = HERE / 'NativePolynomial.dfy'
    field = HERE / 'NativeField.dfy'
    domain = HERE / 'native_polynomial_domain.dfy'
    inputs = [source,field,domain,HERE / 'NativeTypes.dfy',HERE / 'Polynomial.dfy',
              ROOT / 'formal/primitives/Field.dfy',Path(__file__).resolve(),HERE / 'native_polynomial_test.java',
              ROOT / 'formal/crypto/reference/MlKem768.java',
              ROOT / 'formal/crypto/reference/Shake.java', HERE/'reference/provenance.json']
    pins = {str(p.relative_to(ROOT)): digest(p) for p in inputs}
    report = {'status':'incomplete','phase':args.phase,'inputs':pins,
              'domain':'Every array of exactly 256 coefficients in [0,3329); input aliasing permitted',
              'not_proved':['Dafny compiler/runtime and JVM correctness','physical memory erasure',
                            'CPU/JIT timing behavior','production integration and performance acceptance']}
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['dafny_version'] = positive([dafny,'--version'],output/'dafny-version.log').strip()
        report['solver_version'] = positive([solver,'--version'],output/'solver-version.log').strip()
        if args.phase in ['all','proof']:
            report['dependency_verified'] = verified([dafny,'verify',HERE/'Polynomial.dfy','--verify-included-files',*common],output/'dependency-proof.log')
            report['native_verified'] = verified([dafny,'verify',source,'--verify-included-files','--filter-symbol','Native',*native],output/'native-proof.log')
            report['domain_verified'] = verified([dafny,'verify',domain,*native],output/'domain-proof.log')
            audit = positive([dafny,'audit',domain,'--report-format','txt','--report-file',output/'audit.txt'],output/'audit.log')
            if 'completed with 0 findings' not in audit or (output/'audit.txt').read_text().strip():
                raise RuntimeError('Nonempty Dafny assumption audit')
            report['audit_findings'] = 0
        if args.phase in ['all','controls']:
            poly = absolute_includes(source.read_text()); scalar = absolute_includes(field.read_text())
            def mutation(text, old, new):
                if text.count(old) != 1: raise RuntimeError(f'Mutation target not unique: {old}')
                return text.replace(old,new,1)
            controls = [
                ('reduce',mutation(scalar,'    r := ReduceOnce(remainder);','    r := 0;'),'NativeField.Reduce.'),
                ('correction-shift',mutation(scalar,'>> (15 as T.I)','>> (14 as T.I)'),'NativeField.ReduceOnce.'),
                ('barrett-shift',mutation(scalar,'>> (24 as T.I)','>> (23 as T.I)'),'NativeField.Reduce.'),
                ('mask',mutation(scalar,'>> (15 as T.I)) & 1','>> (15 as T.I)) & 0'),'NativeField.ReduceOnce.'),
                ('reciprocal',f'''include "{field}"
module NativeReciprocalControl {{
  import T = NativeTypes
  import F = NativeField
  method {{:isolate_assertions}} Wrong(a: T.I) returns (r: T.I)
    requires 0 <= a <= 22154496
    ensures 0 <= r < 3329
  {{
    var product: T.L := (a as T.L)*5038;
    F.NativeShift24(product);
    var shifted: bv64 := (product as bv64) >> (24 as T.I);
    var quotient: T.I := shifted as T.I;
    r := F.ReduceOnce(a-quotient*3329);
  }}
}}
''','NativeReciprocalControl.Wrong.'),
                ('sign',mutation(poly,'r[i+l] := F.Sub(f[i],t);','r[i+l] := F.Add(f[i],t);'),'NativePolynomial.ForwardStage.'),
                ('index',mutation(poly,'var t := F.Mul(z,f[i+l]);','var t := F.Mul(z,f[i]);'),'NativePolynomial.ForwardStage.'),
                ('inverse',mutation(poly,'F.MulSub(z,f[i+l],f[i])','F.MulSub(z,f[i],f[i+l])'),'NativePolynomial.InverseStage.'),
                ('product',f'''include "{field}"
module NativeProductControl {{
  import T = NativeTypes
  import F = NativeField
  method Wrong(a0: T.I, a1: T.I, b0: T.I, b1: T.I) returns (r: T.I)
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329 && 0 <= b0 < 3329 && 0 <= b1 < 3329
    ensures r as int == ((a0 as int)*(b1 as int)+(a1 as int)*(b0 as int))%3329
  {{ r := F.Mul(a0,b1); }}
}}
''','NativeProductControl.Wrong.'),
                ('root',mutation(poly,'else if i == 1 then 1729','else if i == 1 then 1730'),'NativePolynomial.ZetasChunk0.'),
                ('wipe',mutation(poly,'{ a[i] := 0; }','{ if i > 0 { a[i] := 0; } }'),'NativePolynomial.Wipe.'),
                ('positive-dividend',mutation(scalar,'var adjusted := b+Q-c;','var adjusted := b-c;'),'NativeField.MulSub.'),
                ('scale',f'''include "{source}"
module NativeScaleControl {{
  import T = NativeTypes
  import S = PolySpec
  import P = NativePolynomial
  method Wrong(f: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f)
    ensures T.Canonical(r) && T.Ints(r) == S.Scale(T.Ints(f),3303)
  {{ r := P.Copy(f); P.Scale(r,3302); }}
}}
''','NativeScaleControl.Wrong.'),
                ('freshness',f'''include "{source}"
module NativeFreshControl {{
  import T = NativeTypes
  method Wrong(f: array<T.I>) returns (r: array<T.I>)
    requires T.Canonical(f)
    ensures fresh(r) && T.Ints(r) == T.Ints(f)
  {{ r := f; }}
}}
''','NativeFreshControl.Wrong.')]
            # These legal inputs make two scalar counterexamples deterministic
            # under host load. Only temporary negative copies gain the witness
            # precondition; positive sources and unrestricted proofs are intact.
            witnesses = {
                'reduce': {'a':1, 'requires':'a == 1', 'expected_modulo':1, 'mutant_return':0},
                'barrett-shift': {'a':16777216, 'requires':'a == 16777216', 'expected_modulo':2385,
                                  'product':84540391424, 'shift24':5039, 'mutant_shift23':10078,
                                  'mutant_remainder':-16772446},
            }
            for witness in witnesses.values():
                assert 0 <= witness['a'] <= 22154496
                assert witness['expected_modulo'] == witness['a'] % 3329
            barrett = witnesses['barrett-shift']
            assert barrett['product'] == barrett['a'] * 5039
            assert barrett['shift24'] == barrett['product'] >> 24
            assert barrett['mutant_shift23'] == barrett['product'] >> 23
            assert barrett['mutant_remainder'] == barrett['a'] - barrett['mutant_shift23'] * 3329 < 0
            report['controls'] = {}
            with tempfile.TemporaryDirectory(prefix='native-polynomial-') as temporary:
                for name,text,symbol in controls:
                    witness = witnesses.get(name)
                    if witness:
                        text = mutation(text,'    requires 0 <= a <= MaxReduce\n',
                                        f"    requires 0 <= a <= MaxReduce\n    requires {witness['requires']}\n")
                    path = Path(temporary)/f'native_polynomial_{name}.dfy'; path.write_text(text)
                    log = output/f'control-{name}.log'
                    status,result = run([dafny,'verify',path,'--filter-symbol',symbol,*native],log)
                    if status != 4 or not re.search(r'Error: (a postcondition|this invariant|a loop invariant|a precondition|a postcondition might|assertion might not hold|value does not satisfy)',result):
                        raise RuntimeError(f'{name}: did not fail a genuine proof obligation')
                    if re.search(r'out of resource|timed out|parse errors|resolution/type errors',result,re.I):
                        raise RuntimeError(f'{name}: inconclusive')
                    report['controls'][name] = {'result':'semantic proof failure','sha256':digest(path),'symbol':symbol,'log':log.name}
                    if witness:
                        report['controls'][name]['witness'] = {**witness,'scope':'temporary negative copy only'}
        if args.phase in ['all','java']:
            jdk = args.java_home.resolve()
            env = dict(os.environ,JAVA_HOME=str(jdk),PATH=str(jdk/'bin')+os.pathsep+os.environ['PATH'])
            prefix = output/'NativePolynomial'
            translated = positive([dafny,'translate','java',source,'--output',prefix,*native],output/'translate.log',env)
            match = re.search(r'finished with (\d+) verified, 0 errors',translated)
            if not match or int(match.group(1)) == 0: raise RuntimeError('No translation proof count')
            report['translation_verified'] = int(match.group(1))
            generated = output/'NativePolynomial-java'
            generated_sources = sorted(generated.rglob('*.java'))
            generated_pins = {str(p.relative_to(generated)):digest(p) for p in generated_sources}
            classes = output/'classes'; classes.mkdir(exist_ok=True)
            runtime = (args.runtime_jar or dafny.parent/'DafnyRuntime.jar').resolve()
            runtime_pin = digest(runtime)
            if args.runtime_sha256 and runtime_pin != args.runtime_sha256:
                raise RuntimeError('Selected runtime JAR checksum mismatch')
            report['runtime_path'] = str(runtime)
            positive([jdk/'bin/javac','--release','21','-cp',runtime,'-d',classes,*generated_sources,HERE/'native_polynomial_test.java',*inputs[-2:]],output/'javac.log',env)
            bytecode = positive([jdk/'bin/javap','-c','-p','-s','-cp',f'{classes}{os.pathsep}{runtime}',
                                 'NativePolynomial.__default','NativeField.__default'],output/'native-bytecode.log',env)
            forbidden = r'java/math/BigInteger|dafny/DafnySequence|dafny/Tuple|java/lang/Long.valueOf'
            if re.search(forbidden,bytecode): raise RuntimeError('Non-native arithmetic, sequence or tuple in native bytecode')
            # Dafny TypeDescriptor initializes arrays with the fixed zero witness.
            # The only permitted Integer boxing is this public allocation value.
            for line_no,line in enumerate(bytecode.splitlines()):
                if 'java/lang/Integer.valueOf' in line:
                    prior = bytecode.splitlines()[line_no-1]
                    if 'NativeTypes/I.Witness:I' not in prior: raise RuntimeError('Value boxing beyond fixed zero witness')
            field_bytecode = positive([jdk/'bin/javap','-c','-p','-s','-cp',f'{classes}{os.pathsep}{runtime}',
                                       'NativeField.__default'],output/'field-bytecode.log',env)
            forbidden_field = r'\b(?:idiv|irem|ldiv|lrem)\b|dafny/DafnyEuclidean|java/math/BigInteger|java/lang/(?:Integer|Long).valueOf|\bif(?:eq|ne|lt|le|gt|ge|_icmp\w+|_acmp\w+|null|nonnull)\b'
            if re.search(forbidden_field,field_bytecode) or re.search(r'\b(?:tableswitch|lookupswitch)\b',field_bytecode):
                raise RuntimeError('NativeField bytecode contains division, remainder, Euclidean helper, value boxing, BigInteger or conditional branch')
            field_calls = re.findall(r'invokestatic[^\n]*// Method ([^:]+):',field_bytecode)
            if any('/' in call and call != 'dafny/Helpers.bv64ShiftRight' and not call.startswith('NativeField/__default.') for call in field_calls):
                raise RuntimeError('Unexpected external NativeField arithmetic callee')
            helper_bytecode = positive([jdk/'bin/javap','-c','-p','-s','-cp',runtime,'dafny.Helpers'],
                                       output/'shift-helper-bytecode.log',env)
            helper = helper_bytecode.split('public static long bv64ShiftRight(long, byte);',1)[1].split('\n  public ',1)[0]
            ops = re.findall(r'^\s*\d+:\s+(\w+)',helper,re.M)
            if ops != ['iload_2','bipush','if_icmpne','lconst_0','lreturn','lload_0','iload_2','lushr','lreturn']:
                raise RuntimeError('Selected runtime shift helper changed; inspect complete control flow')
            if not re.search(r'1: bipush\s+64',helper) or not re.search(r'3: if_icmpne\s+8',helper):
                raise RuntimeError('Unexpected shift-helper branch operands')
            # The only helper branch is on its public shift distance; actual
            # field calls use the literal distances 15 and 24. No value-sign test.
            shift_calls = re.findall(r'bipush\s+(\d+)\n\s*\d+: invokestatic[^\n]*dafny/Helpers\.bv64ShiftRight:',field_bytecode)
            if shift_calls != ['15','24'] or 'bv32ShiftRight' in field_bytecode:
                raise RuntimeError('NativeField shift distances or helper callees changed')
            report['native_bytecode'] = {'forbidden_value_representations':0,'array_fill_boxing':'fixed public zero witness only',
                                         'field_division_remainder_branches':0,
                                         'shift_helper':'Only public constant-distance guard; no value-sign branch',
                                         'shift_helper_bytecode_sha256':digest(output/'shift-helper-bytecode.log'),
                                         'bytecode_sha256':digest(output/'native-bytecode.log'),
                                         'field_bytecode_sha256':digest(output/'field-bytecode.log')}
            report['java_runs'] = []
            for index,home in enumerate([jdk,*args.runtime_home]):
                home=home.resolve()
                result = positive([home/'bin/java','-ea','-cp',f'{classes}{os.pathsep}{runtime}',
                                   'io.github.mahmoudimus.quic.tls.native_polynomial_test'],output/f'java-{index}.log',env)
                if not re.fullmatch(r'NATIVE_POLYNOMIAL_CHECKS cases=288 product_cases=32 assertions=\d+\n?',result):
                    raise RuntimeError('Unexpected finite compatibility check summary')
                version = positive([home/'bin/java','-version'],output/f'java-version-{index}.log',env).strip()
                report['java_runs'].append({'version':version,'result':result.strip(),'java_sha256':digest(home/'bin/java')})
            if generated_pins != {str(p.relative_to(generated)):digest(p) for p in generated_sources}:
                raise RuntimeError('Generated source changed during Java replay')
            report['generated_java'] = generated_pins
            report['classes'] = {str(p.relative_to(classes)):digest(p) for p in sorted(classes.rglob('*.class'))}
            if digest(runtime) != runtime_pin: raise RuntimeError('Runtime JAR changed during replay')
            report['runtime_sha256'] = runtime_pin
            report['footprint'] = {'native_source_bytes':sum((generated/n/'__default.java').stat().st_size for n in ['NativePolynomial','NativeField']),
                                   'native_class_bytes':sum((classes/n/'__default.class').stat().st_size for n in ['NativePolynomial','NativeField'])}
        if pins != {str(p.relative_to(ROOT)):digest(p) for p in inputs}: raise RuntimeError('Input changed during replay')
        report['status']='passed'
    except Exception as error:
        report['status']='failed'; report['error']=str(error)
        raise
    finally:
        report_path.write_text(json.dumps(report,indent=2)+'\n')
    print(report_path)


if __name__ == '__main__':
    main()

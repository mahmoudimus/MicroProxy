#!/usr/bin/env python3
"""Replay the polynomial proof checkpoint, semantic controls and exact generated Java.

This is deliberately separate from the shared inventory/production adoption runner.
Runtime comparisons are finite artifact evidence, not proofs of production Java
refinement or physical timing.
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
SOURCE = HERE / 'Polynomial.dfy'
FIELD = ROOT / 'formal/primitives/Field.dfy'
DEFAULT_DAFNY = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, log, env=None, timeout=900):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=timeout)
    log.write_text(result.stdout)
    return result.returncode, result.stdout


def positive(command, log, env=None):
    status, text = run(command, log, env)
    if status:
        raise RuntimeError(f'{log.name} failed (exit {status}); see {log}')
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dafny', type=Path, default=DEFAULT_DAFNY)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/polynomial-checks')
    parser.add_argument('--java-home', type=Path, default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--runtime-home', type=Path, action='append', default=[],
                        help='Additional JDK for running the same compiled classes')
    parser.add_argument('--phase', choices=['all', 'proof', 'controls', 'java'], default='all')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'polynomial_report.json'
    report = {'status': 'incomplete', 'phase': args.phase,
              'scope': 'Canonical polynomial operations, mathematical NTT representation, two-sided inverse and negacyclic multiplication',
              'not_proved': ['Dafny compiler/runtime and JVM correctness',
                             'production Java refinement/integration', 'JVM/CPU side-channel behavior']}
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    dafny = args.dafny.resolve()
    solver = dafny.parent / 'z3/bin/z3-4.12.1'
    flags = ['--cores', '2', '--verification-time-limit', '30', '--resource-limit', '50000000',
             '--solver-path', solver]
    references = [HERE/'reference'/name for name in ('MlKem768.java','Shake.java')]
    inputs = [SOURCE, FIELD, Path(__file__).resolve(), HERE / 'polynomial_java.java',
              *references, HERE/'reference/provenance.json']
    pins = {str(p.relative_to(ROOT)): digest(p) for p in inputs}
    report['inputs'] = pins
    source_text = SOURCE.read_text()
    try:
        report['dafny_version'] = positive([dafny, '--version'], output / 'polynomial_dafny_version.log').strip()
        report['solver_version'] = positive([solver, '--version'], output / 'polynomial_solver_version.log').strip()
        if args.phase in ['all', 'proof']:
            proof = positive([dafny, 'verify', SOURCE, '--verify-included-files', *flags], output / 'polynomial_proof.log')
            match = re.search(r'finished with (\d+) verified, 0 errors\s*$', proof)
            if not match or int(match.group(1)) == 0:
                raise RuntimeError('Missing successful complete proof summary')
            report['verified'] = int(match.group(1))
        with tempfile.TemporaryDirectory(prefix='polynomial-checks-') as scratch:
            scratch = Path(scratch)
            if args.phase in ['all', 'controls']:
                absolute_source = source_text.replace('include "../primitives/Field.dfy"',
                                                       f'include "{FIELD}"')
                controls = [
                    ('root', absolute_source.replace('[1, 1729,', '[1, 1730,', 1), 'RootEntry1.'),
                    ('sign', absolute_source.replace('a[i] := F.Sub(f[i-l],t);',
                                                      'a[i] := F.Add(f[i-l],t);', 1),
                     'VerifiedPolynomial.ForwardStage.'),
                    ('index', absolute_source.replace('var t := F.Mul(z,f[i+l]);',
                                                       'var t := F.Mul(z,f[i]);', 1),
                     'VerifiedPolynomial.ForwardStage.'),
                    ('product', f'''include "{FIELD}"
module PolynomialProductControl {{
  import F = VerifiedField
  method WrongProduct(a0: int, a1: int, b0: int, b1: int) returns (c1: int)
    requires 0 <= a0 < 3329 && 0 <= a1 < 3329 && 0 <= b0 < 3329 && 0 <= b1 < 3329
    ensures c1 == (a0*b1+a1*b0)%3329
  {{ c1 := F.Mul(a0,b1); }}
}}
''', 'WrongProduct.'),
                    ('wrap', '''module PolynomialWrapControl {
  method WrongWrap(f: seq<int>) returns (r: seq<int>)
    requires |f| == 256 && forall i :: 0 <= i < 256 ==> 0 <= f[i] < 3329
    ensures |r| == 256
    ensures r[0] == (-f[255])%3329
    ensures forall i :: 1 <= i < 256 ==> r[i] == f[i-1]
  { r := [f[255]] + f[..255]; }
}
''', 'WrongWrap.'),
                    ('scale', f'''include "{SOURCE}"
module PolynomialScaleControl {{
  import P = VerifiedPolynomial
  import S = PolySpec
  method WrongScale(f: seq<int>) returns (r: seq<int>)
    requires S.Canonical(f)
    ensures r == S.Scale(f,3303)
  {{ r := P.Scale(f,3302); }}
}}
''', 'WrongScale.')]
                outcomes = {}
                for name, mutant, symbol in controls:
                    if name != 'scale' and mutant == absolute_source:
                        raise RuntimeError(f'{name} mutation did not change the source')
                    focus = []
                    witness = None
                    if name in ('sign', 'index'):
                        # Negative copies only: a legal first-stage basis vector.
                        # Focus the first affected lane before any false mutant
                        # invariant could make the local check inconsistent.
                        start = mutant.index('  method ForwardStage(')
                        end = mutant.index('  method Ntt(', start)
                        body = mutant[start:end]
                        body = body.replace('    requires S.Canonical(f) && s < 7',
                            '    requires S.Canonical(f) && s < 7\n    requires s == 0 && f == seq(256,i => if i == 128 then 1 else 0)',1)
                        lane = 128 if name == 'sign' else 0
                        anchor = '        a[i] := F.Add(f[i-l],t);' if name == 'sign' else '        a[i] := F.Add(f[i],t);'
                        assertion = f'        if i == {lane} {{ assert a[i] == S.ForwardLane(f,s,i); }}'
                        if body.count(anchor) != 1:
                            raise RuntimeError('Control witness anchor changed: '+name)
                        body = body.replace(anchor,anchor+'\n'+assertion,1)
                        mutant = mutant[:start]+body+mutant[end:]
                        witness = {'stage':0,'nonzero_coefficient':128,'value':1,'other_coefficients':0,'checked_lane':lane}
                    path = scratch / f'polynomial_{name}.dfy'
                    path.write_text(mutant)
                    if witness:
                        position = next(i+1 for i,line in enumerate(mutant.splitlines()) if line.strip() == assertion.strip())
                        focus = ['--isolate-assertions','--filter-position',f'{path.name}:{position}']
                        # The same legal witness must verify with the original
                        # operation. This also checks that the focused assertion
                        # still names the intended executable expression.
                        if name == 'sign':
                            correct = mutant.replace('a[i] := F.Add(f[i-l],t);', 'a[i] := F.Sub(f[i-l],t);', 1)
                        else:
                            correct = mutant.replace('var t := F.Mul(z,f[i]);', 'var t := F.Mul(z,f[i+l]);', 1)
                        positive_path = scratch / f'polynomial_{name}_witness.dfy'
                        positive_path.write_text(correct)
                        positive_text = positive([dafny, 'verify', positive_path, '--filter-symbol', symbol,
                            '--isolate-assertions','--filter-position',f'{positive_path.name}:{position}',*flags],
                            output / f'polynomial_witness_{name}.log')
                        if not re.search(r'finished with [1-9]\d* assertions verified, 0 errors\s*$',positive_text):
                            raise RuntimeError('Missing positive witness verification: '+name)
                    log = output / f'polynomial_control_{name}.log'
                    status, text = run([dafny, 'verify', path, '--filter-symbol', symbol, *focus, *flags], log)
                    if status != 4 or not re.search(r'Error: (a postcondition|this invariant|a loop invariant|assertion might not hold)', text):
                        raise RuntimeError(f'{name} did not produce the intended proof failure: {log}')
                    if re.search(r'out of resource|timed out|parse errors|resolution/type errors', text, re.I):
                        raise RuntimeError(f'{name} was inconclusive: {log}')
                    outcomes[name] = {'result': 'semantic proof failure', 'source_sha256': digest(path),
                                      'symbol': symbol, 'log': log.name}
                    if witness:
                        outcomes[name]['negative_control_witness'] = witness
                        outcomes[name]['correct_witness_sha256'] = digest(positive_path)
                    saved = output/'controls'/path.name
                    saved.parent.mkdir(exist_ok=True)
                    saved.write_text(mutant)
                report['controls'] = outcomes
                harness = scratch / 'polynomial_domain.dfy'
                harness.write_text(f'''include "{SOURCE}"
module PolynomialDomain {{
  import P = VerifiedPolynomial
  import S = PolySpec
  import R = PolynomialRing
  method ArbitraryCanonical(f: seq<int>, g: seq<int>)
    requires S.Canonical(f) && S.Canonical(g)
  {{
    var sum := P.Add(f,g);
    var difference := P.Sub(f,g);
    var nf := P.Ntt(f);
    var ng := P.Ntt(g);
    var product := P.NttMul(nf,ng);
    var ringProduct := P.InverseNtt(product);
    var restored := P.InverseNtt(nf);
    var inverted := P.InverseNtt(f);
    R.NegacyclicViaNtt(f,g);
    R.NttInverseRoundTrip(f);
    assert ringProduct == R.NegacyclicProduct(f,g);
    assert S.Representation(inverted) == f;
    S.NttRoundTrip(f);
    assert restored == f;
    assert nf == S.Representation(f);
    assert S.Canonical(sum) && S.Canonical(difference) && S.Canonical(product);
  }}
}}
''')
                report['domain_harness'] = positive([dafny, 'verify', harness, *flags],
                                                      output / 'polynomial_domain.log').strip()
            if args.phase in ['all', 'java']:
                if args.java_home is None:
                    raise RuntimeError('Set JAVA_HOME or pass --java-home for JDK21+')
                jdk = args.java_home.resolve()
                env = dict(os.environ, JAVA_HOME=str(jdk), PATH=str(jdk / 'bin') + os.pathsep + os.environ['PATH'])
                prefix = output / 'Polynomial'
                positive([dafny, 'translate', 'java', SOURCE, '--verify-included-files', '--output', prefix, *flags],
                         output / 'polynomial_translate.log', env)
                generated = output / 'Polynomial-java'
                classes = output / 'classes'
                classes.mkdir(exist_ok=True)
                runtime = dafny.parent / 'DafnyRuntime.jar'
                generated_sources = sorted(generated.rglob('*.java'))
                if not generated_sources:
                    raise RuntimeError('No generated Java source')
                source_pins = {str(p.relative_to(generated)): digest(p) for p in generated_sources}
                positive([jdk / 'bin/javac', '--release', '21', '-cp', runtime, '-d', classes,
                          *generated_sources, HERE / 'polynomial_java.java', *references],
                         output / 'polynomial_javac.log', env)
                java_runs = []
                for index, home in enumerate([jdk, *args.runtime_home]):
                    home = home.resolve()
                    suffix = '' if index == 0 else f'_{index}'
                    java_result = positive([home / 'bin/java', '-ea', '-cp', f'{classes}{os.pathsep}{runtime}',
                                            'io.github.mahmoudimus.quic.tls.polynomial_java'],
                                           output / f'polynomial_java{suffix}.log', env)
                    version = positive([home / 'bin/java', '-version'],
                                       output / f'polynomial_java_version{suffix}.log', env).strip()
                    java_runs.append({'version': version, 'result': java_result.strip(),
                                      'java_sha256': digest(home / 'bin/java')})
                report['java_runs'] = java_runs
                report['classes'] = {str(p.relative_to(classes)): digest(p) for p in sorted(classes.rglob('*.class'))}
                report['generated_java'] = source_pins
                report['runtime_sha256'] = digest(runtime)
                report['footprint'] = {'generated_source_bytes': sum(p.stat().st_size for p in generated_sources),
                                       'class_bytes': sum(p.stat().st_size for p in classes.rglob('*.class')),
                                       'runtime_bytes': runtime.stat().st_size}
                if source_pins != {str(p.relative_to(generated)): digest(p) for p in generated_sources}:
                    raise RuntimeError('Generated sources changed during the run')
        if pins != {str(p.relative_to(ROOT)): digest(p) for p in inputs}:
            raise RuntimeError('Input source changed during the run')
        report['status'] = 'passed'
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(report_path)


if __name__ == '__main__':
    main()

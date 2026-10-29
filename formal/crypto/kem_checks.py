#!/usr/bin/env python3
"""Replay ML-KEM composition evidence; finite Java checks are not refinement proofs."""
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
EXPECTED_TESTS = {'assertions':5091, 'rounds':100, 'malformed':30, 'selections':3265}


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


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dafny',type=Path,default=DEFAULT_DAFNY)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,action='append',required=True)
    p.add_argument('--scope',choices=('full','owned'),default='full',
                   help='owned is explicitly partial evidence; full rechecks every dependency')
    args = p.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='kem-',dir=args.output)).resolve()
    print(out,flush=True)
    deps = sorted(graph(HERE/'kem_domain.dfy'))
    refs = [ROOT/'formal/crypto/reference'/n for n in ('Shake.java','MlKem768.java')]
    inputs = deps+[HERE/n for n in ('kem_checks.py','kem_test.java','kem_hash.java')]+refs+[HERE/'reference/provenance.json']
    before = {str(f.relative_to(ROOT)):sha(f) for f in inputs}
    (out/'input-digests-start.json').write_text(json.dumps(before,indent=2)+'\n')
    solver = args.dafny.parent/'z3/bin/z3-4.12.1'
    flags = ['--cores','2','--verification-time-limit','30','--resource-limit','50000000','--solver-path',str(solver)]
    receipt = {'scope':args.scope,'commands':[],'proofs':{},'controls':{},'java':[],
               'limitations':['Proposed 280-iteration sampling cap requires production policy review and intermediate wiping.',
                              'JVM timing, compiler/runtime/provider correctness, entropy and cryptographic security are not proved.',
                              'Finite Java comparisons do not prove universal source/compiler refinement.']}

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
        if status or not match or 'Warning:' in output:
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
    if status or 'Dafny auditor completed with 2 findings' not in audit or len(warnings) != 2 or not all(
        'JdkHash.dfy' in line and ('Warning: H:' in line or 'Warning: G:' in line) and 'explicit `{:axiom}`' in line for line in warnings):
        raise RuntimeError('Assumption inventory differs from the two named provider contracts')
    receipt['provider_assumptions'] = warnings
    proof_command = [args.dafny,'verify',HERE/'MlKem.dfy',HERE/'KemSpec.dfy',HERE/'kem_domain.dfy',*flags]
    if args.scope == 'full':
        proof_command.append('--verify-included-files')
    prove('proof-'+args.scope,proof_command)

    source = (HERE/'MlKem.dfy').read_text().replace('include "KemSpec.dfy"','include "'+str(HERE/'KemSpec.dfy')+'"')
    controls = [
        ('wrong-coins','Encaps.','Encrypt(parsed.value,m,g[32..])','Encrypt(parsed.value,m,g[..32])',None),
        ('matrix-axis','Sample.','rho+[j as bv8,i as bv8]','rho+[i as bv8,j as bv8]',None),
        ('matrix-transpose','Row.','a[if transposed then 3*j+i else 3*i+j]','a[3*i+j]',None),
        ('reused-nonce','Noise.','seed+[nonce as bv8]','seed+[0 as bv8]',None),
        ('wrong-fallback-seed','Decaps.','dk.seed[32..]+c','dk.seed[..32]+c',None),
        ('constant-selection','Select.','var mask := (((diff as bv16)-1) >> 8) as bv8;','var mask: bv8 := 255;',None),
        ('short-comparison','Select.','for i := 0 to 1088','for i := 0 to 1087',None),
        ('modulus-error-kind','Parse.','return S.Failure(S.ModulusError);','return S.Failure(S.InvalidKeyLength);',None),
        ('short-sampler','SamplePrefix.','var sampled := VS.Feed([],b);','var sampled := VS.Feed([],b[..837]);',None)]
    for name,symbol,old,new,focus in controls:
        if source.count(old) != 1:
            raise RuntimeError('Mutant anchor changed: '+name)
        target = out/(name+'.dfy')
        target.write_text(source.replace(old,new))
        extra = []
        if focus:
            matches = [i+1 for i,line in enumerate(target.read_text().splitlines()) if line.strip() == focus]
            if len(matches) != 1:
                raise RuntimeError('Mutant focus changed: '+name)
            extra = ['--isolate-assertions','--filter-position',f'{target.name}:{matches[0]}']
        status,output = call('control-'+name,[args.dafny,'verify',target,'--filter-symbol','VerifiedMlKem.'+symbol,*extra,*flags])
        match = re.search(r'verifier finished with (\d+) (?:assertions )?verified, ([1-9]\d*) errors?\s*$',output)
        if not status or not match or any(x in output for x in ('timed out','out of resource','parse errors','resolution/type errors','Warning:')) or not any(x in output for x in ('could not be proved','assertion might not hold')):
            raise RuntimeError('No genuine semantic failure for '+name)
        receipt['controls'][name] = {'verified':int(match[1]),'errors':int(match[2])}

    prefix = out/'MlKem'
    prove('generate-java',[args.dafny,'translate','java',HERE/'MlKem.dfy',HERE/'KemSpec.dfy',HERE/'kem_domain.dfy','--output',prefix,*flags])
    generated = out/'MlKem-java'
    classes = out/'classes';classes.mkdir()
    runtime = args.dafny.parent/'DafnyRuntime.jar'
    sources = sorted(generated.rglob('*.java'))+[HERE/'kem_test.java',HERE/'kem_hash.java',*refs]
    status,output = call('javac',[args.java_home[0]/'bin/javac','--release','21','-cp',runtime,'-d',classes,*sources])
    if status:
        raise RuntimeError('Generated Java compilation failed')
    for i,home in enumerate(args.java_home):
        status,java_version = call(f'java-{i}-version',[home/'bin/java','-version'])
        if status:
            raise RuntimeError('JVM version check failed')
        status,output = call(f'java-{i}',[home/'bin/java','-Xmx1024m','-ea','-cp',str(classes)+os.pathsep+str(runtime),'io.github.mahmoudimus.quic.tls.kem_test'])
        matches = re.findall(r'^PASS kem_test (\{.*\})$',output,re.M)
        if status or len(matches) != 1 or json.loads(matches[0]) != EXPECTED_TESTS:
            raise RuntimeError('Generated Java test inventory failed or changed')
        receipt['java'].append({'version':java_version,'tests':json.loads(matches[0])})
    receipt['inputs'] = {str(f.relative_to(ROOT)):sha(f) for f in inputs}
    if receipt['inputs'] != before:
        changed = [name for name in before if receipt['inputs'][name] != before[name]]
        (out/'input-digests-end.json').write_text(json.dumps(receipt['inputs'],indent=2)+'\n')
        raise RuntimeError('Proof or reference input changed during replay: '+', '.join(changed))
    receipt['generated_java'] = {str(f.relative_to(generated)):sha(f) for f in sorted(generated.rglob('*.java'))}
    receipt['compiled_classes'] = {str(f.relative_to(classes)):sha(f) for f in sorted(classes.rglob('*.class'))}
    receipt['dafny_sha256'] = sha(args.dafny)
    receipt['solver_sha256'] = sha(solver)
    receipt['runtime_sha256'] = sha(runtime)
    receipt['footprint'] = {'generated_java_bytes':sum(f.stat().st_size for f in generated.rglob('*.java')),
                            'compiled_class_bytes':sum(f.stat().st_size for f in classes.rglob('*.class')),
                            'runtime_bytes':runtime.stat().st_size}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('PASS '+args.scope+' KEM replay '+str(out),flush=True)


if __name__ == '__main__':
    main()

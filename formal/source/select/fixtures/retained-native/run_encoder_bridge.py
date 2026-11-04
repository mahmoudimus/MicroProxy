#!/usr/bin/env python3
"""Isolated combined-checker canonical encoder and real semantic bridge replay."""
from pathlib import Path
import hashlib,importlib.util,json,os,re,shutil,subprocess,time
R=Path(__file__).resolve().parent; P=R.parent
D=Path('/Users/mahmoud/.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny')
A=Path('/Users/mahmoud/.codex/worktrees/crypto-release-artifact/microproxy')
DLL=R/'work/checker-build/bin/Debug/net6.0/SourceCoverage.dll'
OUT=R/'encoder-bridge-v2';OUT.mkdir(exist_ok=False)
FLAGS=['--verification-time-limit','30','--resource-limit','50000000','--cores','2','--solver-option','O:smt.case_split=0','--progress','Symbol']
ROOTS='NativeKeccak.SetLane,NativeKeccak.Iota,NativeKeccak.Wipe,NativeKeccak.Chi,NativeKeccak.Theta,NativeKeccak.RhoPi'
BAD=re.compile(r'Warning:|out of resource|timed? out|out of memory|pars(?:e|er) error|CLI: Error|unhandled exception|internal error',re.I)
SUMMARY=re.compile(r'^Dafny program verifier finished with (\d+) verified, (\d+) errors?\s*$',re.M)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def inv(p):return {str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*.dfy'))}
code={str(f.relative_to(R)):sha(f) for f in (R/'formal/source/checker').glob('*') if f.is_file()}
report={'status':'incomplete','scope':'Isolated combined C# checker and actual canonical bridge; no production adoption/NI/JVM claim','source_before':inv(R/'formal'),'checker_inputs':code,'assembly_before':sha(DLL),'checks':[]}
def call(name,cmd,check,env=None):
 log=OUT/(name+'.log');t=time.time()
 with log.open('w') as s:q=subprocess.run(list(map(str,cmd)),stdout=s,stderr=subprocess.STDOUT,cwd=R,env=env,timeout=300)
 text=log.read_text();ok=not BAD.search(text) and check(q.returncode,text)
 report['checks'].append({'name':name,'command':list(map(str,cmd)),'exit':q.returncode,'ok':bool(ok),'seconds':time.time()-t,'log_sha256':sha(log)})
 (OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(name,q.returncode,bool(ok),flush=True)
 if not ok:raise RuntimeError(name+': unexpected semantic/checker outcome; inspect log')
def proof(expected,rc=0):
 def check(status,text):
  m=SUMMARY.findall(text)
  return status==rc and len(m)==1 and tuple(map(int,m[0]))==expected
 return check
spec=importlib.util.spec_from_file_location('combined_official_discovery',A/'formal/crypto/delivery.py');discovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(discovery)
fixtures=R/'encoder-fixtures-v2';fixtures.mkdir(exist_ok=False)
cases=[]
review=P/'source-coverage-independent-review/findings-root-repair'
for n in ['encoder-body-tag4','encoder-body-constant4','encoder-body-empty']:
 cases.append((n,review/n,'formal/crypto/NativeKeccak.dfy',False))
for n in ['boolean-flip','address-loss','ops-reordered','branch-tag','alpha-case-formals']:
 folder=P/'native-canonical-encoder-policy/metadata-controls'/n
 entries=list(folder.rglob('NativeKeccak.dfy'))
 if len(entries)!=1:raise RuntimeError('ambiguous fixture '+n)
 entry=entries[0]; root=entry.parents[2]
 cases.append((n,root,str(entry.relative_to(root)),n=='alpha-case-formals'))
report['fixture_inputs']={}
for name,root,entry,accept in cases:
 graph=discovery.source_closure(root,root/entry,D)
 folder=fixtures/name
 for rel,h in graph.items():
  source=root/rel;target=folder/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
  if sha(target)!=h:raise RuntimeError('fixture source drift '+name+'/'+rel)
 report['fixture_inputs'][name]=graph
 env=os.environ.copy();env['SOURCE_TRACE_ROOTS']=ROOTS
 check=(lambda rc,t:rc==0 and 'SOURCE-COVERAGE OK' in t) if accept else (lambda rc,t:rc==2 and 'canonical Encode does not implement the exact typed wire layout' in t)
 call('encoder-'+name,[D,'resolve',folder/entry,'--plugin',DLL],check,env)
for filename,count in [('ObservationVocabulary.dfy',29),('SourceTrace.dfy',17)]:
 call('proof-'+filename,[D,'verify',R/'formal/source'/filename,*FLAGS],proof((count,0)))
call('proof-real-bridge-included',[D,'verify',R/'formal/source/SourceTraceBridge.dfy','--verify-included-files',*FLAGS],proof((54,0)))
for filename in ['ObservationVocabulary.dfy','SourceTrace.dfy','SourceTraceBridge.dfy']:
 call('audit-'+filename,[D,'audit',R/'formal/source'/filename],lambda rc,t:rc==0 and 'Dafny auditor completed with 0 findings' in t)
mutant=OUT/'constant-branch';mutant.mkdir()
for f in (R/'formal/source').glob('*.dfy'):shutil.copyfile(f,mutant/f.name)
f=mutant/'SourceTrace.dfy';s=f.read_text();a='{ O.Encode(O.Branch(site, taken)) }'
if s.count(a)!=1:raise RuntimeError('branch helper control anchor changed')
f.write_text(s.replace(a,'{ O.Encode(O.Branch(site, false)) }'))
def negative(rc,text):
 return proof((52,2),4)(rc,text) and 'BranchIsEncode' in text and 'postcondition could not be proved' in text
call('actual-constant-branch-bridge-failure',[D,'verify',mutant/'SourceTraceBridge.dfy','--verify-included-files',*FLAGS],negative)
report['source_after']=inv(R/'formal');report['assembly_after']=sha(DLL)
if report['source_before']!=report['source_after'] or report['assembly_before']!=report['assembly_after']:raise RuntimeError('source/checker mutated during replay')
for name,graph in report['fixture_inputs'].items():
 for rel,h in graph.items():
  if sha(fixtures/name/rel)!=h:raise RuntimeError('fixture mutated during replay')
report['status']='complete';(OUT/'report.json').write_text(json.dumps(report,indent=2)+'\n')

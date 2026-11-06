"""Small private adaptation of the reviewed XorByte PS-member supervisor."""
import hashlib,json,os,signal,subprocess,time,types
from pathlib import Path
_passive_path=Path(__file__).with_name('passive_drain.py')
_passive_raw=_passive_path.read_bytes()
if hashlib.sha256(_passive_raw).hexdigest()!='07b75c69acd6d1fd999b2eab733db745f84a882e1e6d2eb753e8541550a19dcd':
 raise RuntimeError('reviewed passive helper hash mismatch')
_passive=types.ModuleType('destroy_reviewed_passive_drain')
exec(compile(_passive_raw,str(_passive_path),'exec'),_passive.__dict__)

def durable_json(path,payload):
 path=Path(path);temporary=path.with_name(path.name+'.tmp')
 with temporary.open('w') as stream:
  json.dump(payload,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
 os.replace(temporary,path)
 # Atomic publication follows a durable file flush; no CSV/classification has run.

def roster(pgid,env):
 raw=subprocess.check_output(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,comm='],text=True,env=env);rows=[]
 for line in raw.splitlines():
  fields=line.split(None,4)
  if len(fields)!=5:continue
  pid,ppid,group,uid=map(int,fields[:4])
  if group==pgid:rows.append({'pid':pid,'ppid':ppid,'pgid':group,'uid':uid,'comm':fields[4]})
 return rows

def may_signal(rows,pgid,observed):
 return bool(rows) and all(x['pgid']==pgid and x['uid']==os.getuid() and x['pid'] in observed for x in rows)

def signal_observed_group(rows,pgid,observed,sig,env):
 if not may_signal(rows,pgid,observed):raise RuntimeError('refusing signal: untracked/foreign group member')
 try:
  os.killpg(pgid,sig)
  return 'signal sent to confirmed observed owned group'
 except ProcessLookupError:
  # A PS-to-signal natural-exit race authorizes NO different signal or PID.
  for _ in range(20):
   if not roster(pgid,env):return 'no signal delivered: group naturally exited before signal (ESRCH), PS recensus empty'
   time.sleep(.1)
  raise RuntimeError('ESRCH but PS still lists group members; no further signal authorized')

def run(command,log,cwd,env,timeout=240):
 command=list(map(str,command));log=Path(log);start=time.monotonic();observed=set();samples=[];cleanup=None;failure=None
 with log.open('w') as stream:
  process=subprocess.Popen(command,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
  pgid=os.getpgid(process.pid)
  if pgid!=process.pid:raise RuntimeError('launched process does not own its expected process group')
  observed.add(process.pid)
  launch_path=log.with_suffix('.launch.json');exit_path=log.with_suffix('.raw-execution.json')
  launch={'argv':command,'cwd':str(cwd),'environment':env,'pid':process.pid,'process_group':pgid,'uid':os.getuid(),'log':str(log)}
  try:
   durable_json(launch_path,launch)
   while process.poll() is None:
    sample=roster(pgid,env);observed.update(x['pid'] for x in sample);samples.append(sample)
    try:process.wait(timeout=.2)
    except subprocess.TimeoutExpired:pass
    if time.monotonic()-start>=timeout:raise TimeoutError('owned command deadline exceeded')
  except BaseException as error:
   stream.flush();os.fsync(stream.fileno()) # stdout is saved BEFORE any cleanup
   remaining=roster(pgid,env)
   failure={'type':type(error).__name__,'message':str(error),'pid':process.pid,'pgid':pgid,'members':remaining,'observed':sorted(observed)}
   log.with_suffix('.failure.json').write_text(json.dumps(failure,indent=2)+'\n')
   if remaining:
    if not may_signal(remaining,pgid,observed):raise RuntimeError('refusing signal: untracked/foreign process-group member')
    cleanup=signal_observed_group(remaining,pgid,observed,signal.SIGKILL,env);process.wait(timeout=5)
   raise
  finally:
   stream.flush();os.fsync(stream.fileno())
   actual_returncode=process.poll()
   durable_json(exit_path,{**launch,'returncode':actual_returncode,'actual_exit_observed':actual_returncode is not None,'log_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),'supervisor_failure':failure,'scope':'raw owned execution BEFORE cleanup/CSV/classification'})
 # The complete stdout is durable before optional post-exit group cleanup.
 remaining,passive_samples=_passive.passive_drain(pgid,lambda group:roster(group,env))
 if remaining:
  if not may_signal(remaining,pgid,observed):raise RuntimeError('refusing signal: untracked/foreign residual member')
  cleanup=signal_observed_group(remaining,pgid,observed,signal.SIGTERM,env)
  for _ in range(20):
   remaining=roster(pgid,env)
   if not remaining:break
   time.sleep(.1)
  if remaining:raise RuntimeError('owned residual group persisted')
 record={'pid':process.pid,'process_group':pgid,'uid':os.getuid(),'ownership_samples':samples,
  'residual_cleanup':cleanup,'passive_drain_samples':passive_samples,'passive_drain_helper_sha256':hashlib.sha256(_passive_raw).hexdigest(),'process_group_empty_after_exit':not remaining,'seconds':time.monotonic()-start,
  'membership_authority':'launch PGID plus explicit PS group/UID/observed-member census; no killpg0 authority','launch_record':str(launch_path),'raw_execution_record':str(exit_path),'raw_execution_sha256':hashlib.sha256(exit_path.read_bytes()).hexdigest()}
 return process.returncode,log.read_text(),record

#!/usr/bin/env python3
"""Real-file archive admission controls; no solver/toolchain execution."""
import gzip,hashlib,io,json,os
from pathlib import Path
import subprocess,sys,tarfile,tempfile,types,unittest
HERE=Path(__file__).resolve().parent

def digest(raw):return hashlib.sha256(raw).hexdigest()

def capsule(payload):
 return (json.dumps({'schema':'microproxy.keccak004-retained-capsule/1','qualification':False,
  'scope':'retained-Darwin-arm64-cold-evidence-only','policy_map_sha256':'0'*64,
  'root_map':{},'files':{n:digest(b) for n,b in payload.items()}},sort_keys=True)+'\n').encode()

def archive(entries):
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w',format=tarfile.USTAR_FORMAT) as output:
  for name,raw,kind in entries:
   info=tarfile.TarInfo(name);info.type=kind;info.size=len(raw);info.mode=0o644
   if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):info.linkname='outside'
   output.addfile(info,io.BytesIO(raw))
 return gzip.compress(data.getvalue(),mtime=0)

class ExtractionTests(unittest.TestCase):
 def setUp(self):
  self.assertTrue((HERE/'safeextract.py').is_file(),'safe extractor implementation is missing')
  self.api=types.ModuleType('tested_capsule_extractor');self.api.__file__=str(HERE/'safeextract.py')
  exec(compile((HERE/'safeextract.py').read_bytes(),self.api.__file__,'exec'),self.api.__dict__)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve();self.source=self.root/'source';self.source.mkdir()
  self.path=self.source/'capsule.tar.gz';self.out=self.root/'extracted'
  self.payload={'data/one.txt':b'one\n','data/two.txt':b'two\n'};self.manifest=capsule(self.payload)
  self.entries=[('capsule.json',self.manifest,tarfile.REGTYPE),*[(n,b,tarfile.REGTYPE) for n,b in self.payload.items()]]
  self.put(self.entries)
 def put(self,entries):self.path.write_bytes(archive(entries))
 def extract(self,archive_sha=None,capsule_sha=None,output=None,path=None):
  return self.api.extract_capsule(path or self.path,archive_sha or digest(self.path.read_bytes()),
    capsule_sha or digest(self.manifest),output or self.out)
 def reject(self,pattern=None,**kwargs):
  before=self.path.read_bytes();out=kwargs.get('output',self.out)
  with self.assertRaisesRegex((self.api.CapsuleError,OSError),pattern or '.'):
   self.extract(**kwargs)
  self.assertFalse(out.exists());self.assertEqual(self.path.read_bytes(),before)
 def test_exact_files_only(self):
  before=self.path.read_bytes();r=self.extract()
  self.assertEqual({p.relative_to(self.out).as_posix():p.read_bytes() for p in self.out.rglob('*') if p.is_file()}, {'capsule.json':self.manifest,**self.payload})
  self.assertEqual(self.path.read_bytes(),before);self.assertFalse(r['qualification']);self.assertEqual(r['regular_members'],3)
 def test_read_access_time_is_not_input_drift(self):
  pin=digest(self.path.read_bytes());before=self.path.stat()
  os.utime(self.path,ns=(0,before.st_mtime_ns))
  self.assertEqual(self.extract(archive_sha=pin)['regular_members'],3)
 def test_wrong_archive_hash_before_tar_parsing_or_output(self):
  self.path.write_bytes(b'not gzip');self.reject('archive digest',archive_sha='0'*64)
 def test_wrong_capsule_hash(self):self.reject('capsule digest',capsule_sha='0'*64)
 def test_missing_payload(self):self.put(self.entries[:-1]);self.reject('inventory')
 def test_extra_payload(self):self.put([*self.entries,('extra.txt',b'x',tarfile.REGTYPE)]);self.reject('inventory')
 def test_changed_payload(self):self.put([self.entries[0],('data/one.txt',b'changed',tarfile.REGTYPE),self.entries[2]]);self.reject('payload digest')
 def test_missing_capsule(self):self.put(self.entries[1:]);self.reject('capsule.json')
 def test_capsule_cannot_index_itself(self):
  d=json.loads(self.manifest);d['files']['capsule.json']='0'*64;self.manifest=json.dumps(d).encode();self.entries[0]=('capsule.json',self.manifest,tarfile.REGTYPE);self.put(self.entries);self.reject('index itself')
 def test_duplicate_json_key(self):
  self.manifest=self.manifest.replace(b'"files":',b'"files":{},"files":',1);self.entries[0]=('capsule.json',self.manifest,tarfile.REGTYPE);self.put(self.entries);self.reject('duplicate JSON')
 def test_bad_index_digest(self):
  d=json.loads(self.manifest);d['files']['data/one.txt']='invalid';self.manifest=json.dumps(d).encode();self.entries[0]=('capsule.json',self.manifest,tarfile.REGTYPE);self.put(self.entries);self.reject('digest')
 def test_duplicate_member(self):self.put([*self.entries,self.entries[1]]);self.reject('duplicate')
 def test_unsafe_names(self):
  for name in ['/absolute','../escape','a/../../escape','a//b','a/./b','a\\b','C:/escape','a/','']:
   with self.subTest(name=name):self.put([*self.entries,(name,b'x',tarfile.REGTYPE)]);self.reject('member path')
 def test_case_alias_file(self):self.put([*self.entries,('DATA/ONE.TXT',b'x',tarfile.REGTYPE)]);self.reject('case alias')
 def test_case_alias_parent(self):self.put([*self.entries,('DATA/other',b'x',tarfile.REGTYPE)]);self.reject('case alias')
 def test_unicode_alias(self):self.put([*self.entries,('K/a',b'x',tarfile.REGTYPE),('\u212a/b',b'x',tarfile.REGTYPE)]);self.reject('alias|canonical')
 def test_file_directory_conflict(self):self.put([*self.entries,('data',b'x',tarfile.REGTYPE)]);self.reject('file/directory')
 def test_nonregular_members(self):
  for kind in [tarfile.DIRTYPE,tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE,tarfile.CONTTYPE,tarfile.XHDTYPE,tarfile.GNUTYPE_LONGNAME]:
   with self.subTest(kind=kind):self.put([*self.entries,('special',b'',kind)]);self.reject('regular')
 def test_truncated_tar(self):self.path.write_bytes(gzip.compress(b'x'*513,mtime=0));self.reject('tar')
 def test_invalid_gzip(self):self.path.write_bytes(b'not gzip');self.reject('gzip')
 def test_bad_header_checksum(self):
  raw=bytearray(gzip.decompress(self.path.read_bytes()));raw[0]=ord('z');self.path.write_bytes(gzip.compress(raw,mtime=0));self.reject('tar')
 def test_nonzero_trailing_archive_data(self):
  raw=gzip.decompress(self.path.read_bytes())+b'x'*512;self.path.write_bytes(gzip.compress(raw,mtime=0));self.reject('trailing')
 def test_existing_output_preserved(self):
  self.out.mkdir();sentinel=self.out/'sentinel';sentinel.write_bytes(b'keep');before=self.path.read_bytes()
  with self.assertRaises(self.api.CapsuleError):self.extract()
  self.assertEqual(sentinel.read_bytes(),b'keep');self.assertEqual(self.path.read_bytes(),before)
 def test_output_nested_in_archive_source_rejected_before_write(self):self.reject('overlap',output=self.source/'must-not-create')
 def test_output_nested_in_extractor_source_rejected_before_write(self):self.reject('overlap',output=HERE/'must-not-create-capsule-test')
 def test_output_cannot_be_archive(self):
  before=self.path.read_bytes()
  with self.assertRaises(self.api.CapsuleError):self.extract(output=self.path)
  self.assertEqual(self.path.read_bytes(),before)
 def test_archive_symlink(self):
  alias=self.root/'linked.tar.gz';alias.symlink_to(self.path);self.reject('symlink',path=alias)
 def test_archive_hardlink(self):
  alias=self.root/'hard.tar.gz';os.link(self.path,alias);self.reject('alias|hardlink')
 def test_output_symlink(self):
  self.out.symlink_to(self.root/'not-created')
  with self.assertRaises(self.api.CapsuleError):self.extract()
  self.assertFalse((self.root/'not-created').exists())
 def test_output_parent_symlink(self):
  target=self.root/'target';target.mkdir();alias=self.root/'linked';alias.symlink_to(target,target_is_directory=True)
  self.reject('symlink',output=alias/'not-created');self.assertFalse((target/'not-created').exists())
 def test_actual_case_alias_source(self):
  alias=self.source.with_name('SOURCE')
  if alias.exists() and alias.samefile(self.source):self.reject('overlap',output=alias/'not-created')
  else:
   alias.mkdir();r=self.extract(output=alias/'allowed');self.assertEqual(r['regular_members'],3)
 def test_relative_archive_rejected(self):self.reject('absolute',path=Path('relative.tar.gz'))
 def test_relative_output_rejected(self):
  with self.assertRaisesRegex(self.api.CapsuleError,'absolute'):self.extract(output=Path('relative-out'))
 def test_cli_requires_external_hashes(self):
  r=subprocess.run([sys.executable,'-I','-B',str(HERE/'safeextract.py'),'--archive',str(self.path),'--output',str(self.out)],capture_output=True,text=True)
  self.assertEqual(r.returncode,2);self.assertFalse(self.out.exists())

if __name__=='__main__':unittest.main(verbosity=2)

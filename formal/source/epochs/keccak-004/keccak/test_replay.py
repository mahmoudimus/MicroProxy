#!/usr/bin/env python3
"""Bounded admission/loading/classification regressions; no solver required."""
import hashlib
import importlib.util
import json
import marshal
import struct
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent

def load():
    path = HERE / 'replay.py'
    spec = importlib.util.spec_from_file_location('keccak_public_under_test', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module

class Boundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = load()

    def test_duplicate_and_wrong_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder).resolve() / 'input.json'
            p.write_bytes(b'{"a":1,"a":2}')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                self.r.authenticated_json(p, self.r.sha(p))
            with self.assertRaisesRegex(ValueError, 'external'):
                self.r.authenticated_json(p, '0' * 64)

    def test_aliases_and_output(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve(); protected = base / 'input'; protected.mkdir()
            p = protected / 'a'; p.write_text('one')
            os.link(p, protected / 'alias')
            with self.assertRaisesRegex(ValueError, 'unaliased'):
                self.r.file_bytes(p)
            (protected / 'alias').unlink()
            (base / 'link').symlink_to(protected)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                self.r.file_bytes(base / 'link' / 'a')
            with self.assertRaisesRegex(ValueError, 'overlap'):
                self.r.output_admission(protected / 'new', [protected])
            with self.assertRaisesRegex(ValueError, 'overlap'):
                self.r.output_admission(base, [protected])

    def test_captured_load_ignores_pyc_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder).resolve() / 'helper.py'; p.write_text('VALUE = 17\n')
            (Path(folder).resolve() / '__pycache__').mkdir()
            cache = Path(folder).resolve() / '__pycache__' / ('helper.' + sys.implementation.cache_tag + '.pyc')
            header = importlib.util.MAGIC_NUMBER + struct.pack('<III',0,int(p.stat().st_mtime),p.stat().st_size)
            cache.write_bytes(header + marshal.dumps(compile('VALUE = 99\n',str(p),'exec')))
            self.assertEqual(self.r.load('safe_public_probe', p, self.r.sha(p)).VALUE, 17)
            original = self.r.sha(p); p.write_text('raise RuntimeError("POISON_EXECUTED")\n')
            with self.assertRaisesRegex(ValueError, 'executable bytes'):
                self.r.load('poison_public_probe', p, original)
            self.assertEqual(len(list((Path(folder).resolve() / '__pycache__').iterdir())), 1)

    def test_closed_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder).resolve(); (p / 'home').mkdir(); (p / 'temp').mkdir()
            poison = {k: 'POISON' for k in ('PYTHONPATH','PYTHONSTARTUP','DOTNET_ROOT','DOTNET_STARTUP_HOOKS','DYLD_INSERT_LIBRARIES','LD_PRELOAD','MSBuildSDKsPath','DAFNY_OPTIONS','PATH')}
            poison['LANG'] = 'C'
            env = self.r.child_environment(poison,p/'home',p/'temp')
            self.assertEqual(env['PATH'],'/usr/bin:/bin:/usr/sbin:/sbin')
            self.assertEqual(set(env) & set(poison), {'PATH','LANG'})
            (p / 'home' / 'ambient').write_text('x')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                self.r.child_environment({},p/'home',p/'temp')

    def test_proof_classifier_rejects_substitutes(self):
        good = 'Dafny program verifier finished with 3 verified, 0 errors\n'
        self.assertEqual(self.r.classify({'kind':'proof','counts':[3,0]},0,good)['counts'],[3,0])
        for code,text in [(0,good.replace('3 verified','0 verified')),('timeout',good),(4,good),(0,good+'out of resource'),(0,good+good),(0,good+'formal/a.dfy(1,1): Error: parser error\n')]:
            with self.assertRaises(ValueError): self.r.classify({'kind':'proof','counts':[3,0]},code,text)

    def test_actual_position_filter_summary_units(self):
        positive=(HERE/'stale-positive.stdout.in').read_text()
        mutant=(HERE/'stale-mutant.stdout.in').read_text()
        # Retained private control used inputs/mutant/ as its working-directory prefix.
        # Public replay works inside each variant, retaining the same source/line/assertion.
        mutant=mutant.replace('inputs/mutant/formal/','formal/')
        rule={'kind':'proof','counts':[11,0],'summary_unit':'assertions'}
        self.r.classify(rule,0,positive)
        negative={'kind':'proof','counts':[10,1],'summary_unit':'assertions','errors':[{'file':'formal/crypto/NativeKeccak.dfy','line':926,'column':13,'message':'assertion might not hold'}]}
        self.r.classify(negative,4,mutant)
        with self.assertRaises(ValueError):self.r.classify({'kind':'proof','counts':[11,0]},0,positive)
        for changed in [positive.replace('11 assertions','11'),positive+positive,positive+positive.replace('assertions ',''),positive.replace('11 assertions','0 assertions'),positive+'out of resource',positive+'formal/a.dfy(1,1): Error: parser error']:
            with self.assertRaises(ValueError):self.r.classify(rule,0,changed)
        with self.assertRaises(ValueError):self.r.classify({**rule,'summary_unit':'unknown'},0,positive)

    def test_exact_error_and_audit_classifiers(self):
        error = {'file':'formal/probe.dfy','line':7,'column':11,'message':'assertion might not hold'}
        text = 'formal/probe.dfy(7,11): Error: assertion might not hold\nDafny program verifier finished with 1 verified, 1 error\n'
        rule = {'kind':'proof','counts':[1,1],'errors':[error]}
        self.r.classify(rule,4,text)
        for changed in [text.replace('(7,11)','(8,11)'),text.replace('assertion might not hold','a precondition could not be proved'),text+'timed out\n']:
            with self.assertRaises(ValueError):self.r.classify(rule,4,changed)
        self.r.classify({'kind':'audit','findings':0},0,'Dafny auditor completed with 0 findings\n')
        for changed in ['Dafny auditor completed with 1 findings\n','Dafny auditor completed with 0 findings\nError: parser']:
            with self.assertRaises(ValueError):self.r.classify({'kind':'audit','findings':0},0,changed)

    def test_plugin_roots_and_exact_rejection(self):
        text = '\n'.join('KECCAK-METHOD-COVERAGE ROOT OK: '+n for n in self.r.METHOD_ROOTS)+'\nKECCAK-METHOD-COVERAGE OK: exact methods x\n'
        self.r.classify({'kind':'method'},0,text)
        function = 'KECCAK-FUNCTION-OBSERVATIONS OK: exact functions [' + ','.join(self.r.FUNCTION_ROOTS) + ']; FUNCTION-ONLY DEVELOPMENT SCOPE\n'
        self.r.classify({'kind':'function'},0,function)
        with self.assertRaises(ValueError):self.r.classify({'kind':'function'},0,function.replace(self.r.FUNCTION_ROOTS[0],self.r.FUNCTION_ROOTS[1]))
        with self.assertRaises(ValueError):self.r.classify({'kind':'method'},0,text.replace(self.r.METHOD_ROOTS[0],self.r.METHOD_ROOTS[1]))
        rule={'kind':'reject','diagnostic':'KMC004: missing Read observation in ordinary assignment'}
        self.r.classify(rule,2,'formal/a.dfy(1,1): Error: '+rule['diagnostic']+'\n1 resolution/type errors detected in a.dfy\n')
        for code,changed in [('timeout',rule['diagnostic']),(2,rule['diagnostic']),(2,'formal/a.dfy(1,1): Error: '+rule['diagnostic']+'\nformal/a.dfy(2,1): Error: another\n')]:
            with self.assertRaises(ValueError):self.r.classify(rule,code,changed)

    def test_raw_log_bindings_are_real_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); records=[]
            for i in range(177):
                row={'argv':['/pinned/dafny','resolve'],'cwd':str(root),'exit':0}
                for stream in ('stdout','stderr'):
                    p=root/(str(i)+'.'+stream);p.write_text('original')
                    row[stream]=str(p);row[stream+'_sha256']=self.r.sha(p)
                records.append(row)
            self.assertEqual(len(self.r.bound_logs(records,root)),354)
            Path(records[0]['stdout']).write_text('tampered')
            with self.assertRaisesRegex(ValueError,'binding changed'):self.r.bound_logs(records,root)

    def test_frozen_copy_has_new_identity_and_survives_source_change(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); source=root/'source';source.mkdir()
            p=source/'input';p.write_text('approved');pins={'input':self.r.sha(p)}
            frozen=root/'frozen';self.r.freeze_files(source,pins,frozen)
            self.assertNotEqual(p.stat().st_ino,(frozen/'input').stat().st_ino)
            self.assertEqual((frozen/'input').stat().st_mode & 0o777,0o444)
            p.write_text('changed')
            with self.assertRaisesRegex(ValueError,'changed during capture'):
                self.r.capture_file(p,root/'must-not-exist',pins['input'])
            self.assertFalse((root/'must-not-exist').exists())
            self.assertEqual((frozen/'input').read_text(),'approved')
            with self.assertRaisesRegex(ValueError,'inventory'):self.r.exact_map(source,pins)

    def test_timeout_is_collected_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            row,text=self.r.command('owned-timeout',[sys.executable,'-I','-B','-c',
                'import time;print("started",flush=True);time.sleep(30)'],root,root,0.2)
            self.assertEqual(row['exit'],'timeout')
            self.assertIn('started',text)
            self.assertTrue(Path(row['stdout']).exists())
            with self.assertRaises(ValueError):self.r.classify({'kind':'resolve'},row['exit'],text)

    def test_timeout_kills_stubborn_owned_grandchild(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve()
            child='import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("STUBBORN_PID="+str(os.getpid()),flush=True);time.sleep(30)'
            parent='import subprocess,sys,time;subprocess.Popen([sys.executable,"-I","-B","-c",'+repr(child)+']);time.sleep(30)'
            row,text=self.r.command('owned-grandchild',[sys.executable,'-I','-B','-c',parent],root,root,0.5)
            self.assertEqual(row['exit'],'timeout')
            pid=int(text.split('STUBBORN_PID=')[1].splitlines()[0])
            # The direct child is waited by command(). Launchd may briefly retain an orphan zombie;
            # such a process cannot execute, and must not be mistaken for a live TERM survivor.
            for _ in range(30):
                status=subprocess.run(['/bin/ps','-p',str(pid),'-o','stat='],capture_output=True,text=True,timeout=2)
                if status.returncode==1 or status.stdout.strip().startswith('Z'):break
                time.sleep(0.02)
            self.assertTrue(status.returncode==1 or status.stdout.strip().startswith('Z'),status.stdout)
            print('OWNED_GROUP_CLEANUP '+json.dumps({'grandchild_pid':pid,'ps_exit':status.returncode,'ps_status':status.stdout.strip(),'parent_collected':True}),flush=True)
            with self.assertRaises(ValueError):self.r.classify({'kind':'resolve'},row['exit'],text)

    def test_include_escape_and_extra_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); (root/'a.dfy').write_text('include "../outside.dfy"\n')
            pins={'a.dfy':self.r.sha(root/'a.dfy')}
            with self.assertRaisesRegex(ValueError,'outside|unmapped'):
                self.r.include_closure(root,pins,'a.dfy')
            (root/'a.dfy').write_text('module A {}\n'); pins['a.dfy']=self.r.sha(root/'a.dfy')
            self.assertEqual(self.r.include_closure(root,pins,'a.dfy'),['a.dfy'])
            (root/'extra').write_text('x')
            with self.assertRaisesRegex(ValueError,'inventory'):
                self.r.exact_map(root,pins)

if __name__ == '__main__':unittest.main()

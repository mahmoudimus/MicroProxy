"""Legacy utility/data regressions; current replay admission is tested in formal/source/hkdf."""
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
from zipfile import ZipFile, ZipInfo

import check_adapter_discipline
import deliver_hkdf
import run
import toolchain


class TrustGates(unittest.TestCase):
    def test_permission_error_is_ignored_only_for_quiescent_owned_group(self):
        for living in (False, True):
            process = Mock(pid=812345)
            with (self.subTest(living=living),
                  patch.object(run.os, 'killpg', side_effect=PermissionError('denied')),
                  patch.object(run, 'live_group', return_value=living)):
                if living:
                    with self.assertRaises(PermissionError):
                        run.stop_group(process)
                else:
                    run.stop_group(process)
            process.wait.assert_called_once_with(timeout=1)

    def test_marker_write_failure_removes_old_success(self):
        with tempfile.TemporaryDirectory() as folder:
            report = Path(folder) / 'report.json'
            report.write_text('{"status":"complete"}')
            with patch.object(run, 'atomic_report', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    run.historical_main(['--output', folder])
            self.assertFalse(report.exists(), 'old success survived failed marker creation')

    def test_success_requires_positive_verified_count(self):
        for output in ("", "Dafny program verifier did not attempt verification",
                       "Dafny program verifier finished with 0 verified, 0 errors"):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                run.check_verified(0, output, 1)
        self.assertEqual(21, run.check_verified(0, "Dafny program verifier finished with 21 verified, 0 errors", 21))

    def test_timeout_cannot_be_a_negative_proof(self):
        for status, output in ((124, "a postcondition could not be proved"),
                               (-9, "assertion might not hold"),
                               (4, "1 verified, 1 error\nVerification timed out"),
                               (2, "unresolved identifier"), (4, "out of resource")):
            with self.subTest(status=status, output=output), self.assertRaises(RuntimeError):
                run.check_rejected(status, output)
        run.check_rejected(4, "a postcondition could not be proved\nDafny program verifier finished with 2 verified, 1 error")

    def test_audit_allows_only_named_mac_axiom(self):
        good = ('Hkdf.dfy(19,4): Warning: Mac: Declaration has explicit `{:axiom}` attribute. '
                'Possible mitigation: Provide a proof or test.\nDafny auditor completed with 1 findings\n'
                'Dafny program verifier did not attempt verification\n')
        run.check_audit(0, good)
        for output in (good.replace('Mac:', 'Other:'), good.replace('1 findings', '2 findings'),
                       good + 'Warning: unchecked assumption\n', ''):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                run.check_audit(0, output)

    def test_changed_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'input').write_text('original')
            pins = {'input': toolchain.digest(root / 'input')}
            run.check_inputs(root, pins)
            (root / 'input').write_text('changed')
            with self.assertRaisesRegex(RuntimeError, 'Input changed'):
                run.check_inputs(root, pins)

    def test_changed_generated_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'A.java').write_text('A')
            original = run.snapshot(root, '*.java')
            (root / 'A.java').write_text('B')
            with self.assertRaisesRegex(RuntimeError, 'Generated Java changed'):
                run.check_generated(root, original)

    def test_delivered_generated_sources_must_match_fresh_translation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fresh = root / 'fresh/Pkg/Module'
            committed = root / 'committed'
            fresh.mkdir(parents=True)
            committed.mkdir()
            (fresh / 'A.java').write_text('generated A\n')
            (committed / 'A.java').write_text('generated A\n')
            with patch.object(run, 'GENERATED_PACKAGE', Path('Pkg/Module')), \
                    patch.object(run, 'GENERATED_SOURCE', committed):
                self.assertEqual({'A.java': run.digest(fresh / 'A.java')},
                                 run.check_delivered_generated(root / 'fresh'))
                (committed / 'A.java').write_text('hand edited\n')
                with self.assertRaisesRegex(RuntimeError, 'changed=.*A.java'):
                    run.check_delivered_generated(root / 'fresh')
                (committed / 'A.java').write_text('generated A\n')
                (committed / 'Extra.java').write_text('extra\n')
                with self.assertRaisesRegex(RuntimeError, 'extra=.*Extra.java'):
                    run.check_delivered_generated(root / 'fresh')
                (committed / 'Extra.java').unlink()
                (fresh / 'B.java').write_text('new\n')
                with self.assertRaisesRegex(RuntimeError, 'missing=.*B.java'):
                    run.check_delivered_generated(root / 'fresh')

    BULK_BYTES = (
        '  public static byte[] bytes(dafny.DafnySequence<? extends java.lang.Byte>);\n'
        '    Code:\n'
        '       0: aload_0\n'
        '       1: invokevirtual #101 // Method dafny/DafnySequence.toRawArray:()Ljava/lang/Object;\n'
        '       4: astore_1\n'
        '       5: aload_1\n'
        '       6: instanceof #109 // class "[B"\n'
        '       9: ifeq 19\n'
        '      12: aload_1\n'
        '      13: checkcast #109 // class "[B"\n'
        '      16: areturn\n'
        '      17: new #77 // class java/lang/IllegalStateException\n'
        '      20: athrow\n')
    BARE_CAST = (
        '  public static byte[] bytes(dafny.DafnySequence<? extends java.lang.Byte>);\n'
        '    Code:\n'
        '       0: aload_0\n'
        '       1: invokevirtual #101 // Method dafny/DafnySequence.toRawArray:()Ljava/lang/Object;\n'
        '       4: checkcast #109 // class "[B"\n'
        '       7: areturn\n')
    BRIDGE_BYTES = (
        '  private static byte[] bytes(dafny.DafnySequence<? extends java.lang.Byte>);\n'
        '    Code:\n'
        '       0: aload_0\n'
        '       1: invokestatic #122 // Method io/github/mahmoudimus/verifiedcrypto/'
        'JdkHmac.bytes:(Ldafny/DafnySequence;)[B\n'
        '       4: areturn\n')
    NO_BRANCH = (
        '  public static byte[] bytes(dafny.DafnySequence<? extends java.lang.Byte>);\n'
        '    Code:\n'
        '       0: aload_0\n'
        '       1: invokevirtual #101 // Method dafny/DafnySequence.toRawArray:()Ljava/lang/Object;\n'
        '       4: astore_1\n'
        '       5: aload_1\n'
        '       6: instanceof #109 // class "[B"\n'
        '       9: istore_2\n'
        '      10: aload_1\n'
        '      11: checkcast #109 // class "[B"\n'
        '      14: areturn\n')
    DECOY_METHOD = (
        '  private static byte[] decoy(dafny.DafnySequence<? extends java.lang.Byte>);\n'
        '    Code:\n'
        '       0: aload_0\n'
        '       1: invokevirtual #101 // Method dafny/DafnySequence.toRawArray:()Ljava/lang/Object;\n'
        '       4: astore_1\n'
        '       5: aload_1\n'
        '       6: instanceof #109 // class "[B"\n'
        '       9: ifeq 19\n'
        '      12: aload_1\n'
        '      13: checkcast #109 // class "[B"\n'
        '      16: areturn\n'
        '      17: new #77 // class java/lang/IllegalStateException\n'
        '      20: athrow\n')

    def test_adapter_discipline_rejects_payload_select_and_byte_value(self):
        select = ('  public static dafny.DafnySequence compute(dafny.DafnySequence value);\n'
                  '    Code:\n'
                  '       1: invokevirtual #1 // Method dafny/DafnySequence.select:(I)Ljava/lang/Object;\n'
                  '       4: areturn\n')
        value = ('  public static dafny.DafnySequence compute(dafny.DafnySequence value);\n'
                 '    Code:\n'
                 '       1: invokestatic #2 // Method java/lang/Byte.valueOf:(B)Ljava/lang/Byte;\n'
                 '       4: areturn\n')
        for extra in (select, value):
            found = check_adapter_discipline.violations(
                self.BULK_BYTES + extra, 'io.github.mahmoudimus.verifiedcrypto.JdkHmac')
            self.assertTrue(found, extra)

    def test_adapter_discipline_requires_guarded_bulk_shape_and_delegation(self):
        self.assertEqual([], check_adapter_discipline.violations(
            self.BULK_BYTES, 'io.github.mahmoudimus.verifiedcrypto.JdkHmac'))
        self.assertEqual([], check_adapter_discipline.violations(
            self.BRIDGE_BYTES, 'io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge'))
        self.assertTrue(check_adapter_discipline.violations(
            self.BARE_CAST, 'io.github.mahmoudimus.verifiedcrypto.JdkHmac'))
        self.assertTrue(check_adapter_discipline.violations(
            self.NO_BRANCH, 'io.github.mahmoudimus.verifiedcrypto.JdkHmac'))
        self.assertTrue(check_adapter_discipline.violations(
            self.BARE_CAST + self.DECOY_METHOD, 'io.github.mahmoudimus.verifiedcrypto.JdkHmac'))
        self.assertTrue(check_adapter_discipline.violations(
            self.BRIDGE_BYTES.replace('JdkHmac.bytes', 'Other.bytes'),
            'io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge'))

    def test_delivery_change_list_and_exact_jar_hook(self):
        self.assertEqual({'added': ['b'], 'removed': ['c'], 'changed': ['a']},
                         deliver_hkdf.changes({'a': '1', 'c': '3'}, {'a': '2', 'b': '4'}))
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            jar = root / 'sample.jar'
            with ZipFile(jar, 'w') as bundle:
                bundle.writestr('a/B.class', b'pinned')
            class_map = {'a/B.class': deliver_hkdf.sha256_bytes(b'pinned')}
            deliver_hkdf.check_jar(jar, class_map)
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                deliver_hkdf.check_jar(jar, dict(class_map, **{'a/C.class': '0' * 64}))
            with self.assertRaisesRegex(RuntimeError, 'bytes differ'):
                deliver_hkdf.check_jar(jar, {'a/B.class': '0' * 64})

    def test_top_level_aggregator_must_define_no_executable_content(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'HkdfCrypto.java'
            path.write_text('// Dafny program Hkdf.dfy compiled into Java\n\nimport a.b.*;\n')
            run.check_aggregator(path)
            path.write_text('package a;\nclass X {}\n')
            with self.assertRaisesRegex(RuntimeError, 'executable top-level'):
                run.check_aggregator(path)

    def test_report_is_invalidated_even_when_setup_fails(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            report = output / 'report.json'
            report.write_text('{"status":"complete"}')
            with patch.object(run, 'pipeline', side_effect=RuntimeError('bad pin')):
                self.assertEqual(1, run.historical_main(['--output', str(output)]))
            result = json.loads(report.read_text())
            self.assertEqual('failed', result['status'])
            self.assertIn('bad pin', result['error'])
            self.assertNotIn('claims', result)

    def test_report_stays_incomplete_when_interrupted(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            with patch.object(run, 'pipeline', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run.historical_main(['--output', str(output)])
            self.assertEqual('incomplete', json.loads((output / 'report.json').read_text())['status'])

    def test_public_domain_harness_has_no_caller_preconditions(self):
        harness = run.domain_harness(Path('/tmp/Hkdf.dfy'))
        self.assertNotIn('requires', harness)
        for method in ('Extract', 'Expand', 'LabelInfo', 'ExpandLabel'):
            self.assertIn(f'VerifiedHkdf.{method}(', harness)
            self.assertIn(f'VerifiedHkdf.{method}Spec(', harness)

    def test_mutations_do_not_change_ghost_specs(self):
        source = (run.HERE / 'hkdf/Hkdf.dfy').read_text()
        split = source.index('  method Extract(')
        for name, mutated in run.mutations(source).items():
            with self.subTest(name=name):
                self.assertEqual(source[:split], mutated[:split])
                self.assertNotEqual(source, mutated)
        with self.assertRaises(RuntimeError):
            run.mutations('missing mutation anchors')

    def test_archive_path_traversal_and_symlinks_are_rejected(self):
        for name in ('../outside', '/absolute', 'dafny/../../outside', 'dafny\\evil', 'other/file'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                toolchain.validate_member(ZipInfo(name))
        link = ZipInfo('dafny/link')
        link.external_attr = 0o120777 << 16
        with self.assertRaises(RuntimeError):
            toolchain.validate_member(link)

    def test_pinned_distribution_rejects_archive_compiler_and_runtime_drift(self):
        for change in ('archive', 'compiler', 'extra-file', 'runtime-pin'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                archive = root / 'bundle.zip'
                with ZipFile(archive, 'w') as bundle:
                    bundle.writestr('dafny/dafny', 'compiler')
                    bundle.writestr('dafny/DafnyRuntime.jar', 'runtime')
                import hashlib
                asset = {'archive': archive.name, 'directory': 'extracted',
                         'sha256': toolchain.digest(archive),
                         'runtime_sha256': hashlib.sha256(b'runtime').hexdigest()}
                manifest = {'version': 'test', 'runtime': 'dafny/DafnyRuntime.jar',
                            'assets': {f'{platform.system()}-{platform.machine()}': asset}}
                (root / 'tools.json').write_text(json.dumps(manifest))
                with patch.object(toolchain, 'HERE', root):
                    compiler, _, _, _ = toolchain.install(root)
                    if change == 'archive':
                        archive.write_bytes(b'changed archive')
                    elif change == 'compiler':
                        compiler.write_bytes(b'changed compiler')
                    elif change == 'extra-file':
                        (root / 'extracted/dafny/unknown.dll').write_text('unexpected loader input')
                    else:
                        asset['runtime_sha256'] = '0' * 64
                        (root / 'tools.json').write_text(json.dumps(manifest))
                    with self.assertRaisesRegex(RuntimeError, 'checksum mismatch|distribution changed'):
                        toolchain.install(root)

    @unittest.skipUnless(os.name == 'posix', 'process-group cleanup is POSIX')
    def test_sigterm_cleans_up_active_tool(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            pidfile = root / 'pid'
            code = ('import os,time; '
                    f'open({str(pidfile)!r},"w").write(str(os.getpid())); time.sleep(120)')
            script = (f'import sys; sys.path.insert(0,{str(run.HERE)!r}); import run; from pathlib import Path; '
                      f'run.pipeline=lambda args,output: run.execute([sys.executable,"-c",{code!r}],output/"log"); '
                      f'run.historical_main(["--output",{str(root)!r}])')
            process = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    ready = pidfile.read_text().strip() if pidfile.exists() else ''
                    if ready.isdecimal():
                        break
                    time.sleep(.02)
                self.assertTrue(ready.isdecimal(), 'tool did not start')
                child = int(ready)
                process.terminate()
                process.wait(timeout=5)
                state = subprocess.run(['ps', '-o', 'stat=', '-p', str(child)], capture_output=True, text=True).stdout.strip()
                self.assertTrue(not state or state.startswith('Z'), 'active tool survived runner SIGTERM')
                self.assertEqual('incomplete', json.loads((root / 'report.json').read_text())['status'])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if pidfile.exists() and pidfile.read_text().strip().isdecimal():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name == 'posix', 'process-group cleanup is POSIX')
    def test_cleanup_kills_when_process_inspection_fails(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            pidfile = root / 'pid'
            code = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                    f'open({str(pidfile)!r},"w").write(str(os.getpid())); time.sleep(120)')
            try:
                with patch.object(run, 'live_group', side_effect=subprocess.TimeoutExpired('ps', 1)):
                    status, _ = run.execute([sys.executable, '-c', code], root / 'log', .5)
                self.assertEqual(124, status)
                state = subprocess.run(['ps', '-o', 'stat=', '-p', pidfile.read_text()], capture_output=True, text=True).stdout.strip()
                self.assertTrue(not state or state.startswith('Z'), 'tool survived failed cleanup inspection')
            finally:
                if pidfile.exists():
                    try:
                        os.kill(int(pidfile.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(os.name == 'posix', 'process-group cleanup is POSIX')
    def test_timeout_kills_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            pidfile = root / 'pid'
            child = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                     f'open({str(pidfile)!r},"w").write(str(os.getpid())); time.sleep(120)')
            parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",sys.argv[1]]); time.sleep(120)'
            started = time.monotonic()
            status, output = run.execute([sys.executable, '-c', parent, child], root / 'log', 0.5)
            self.assertEqual(124, status)
            self.assertIn('timeout', output.lower())
            self.assertLess(time.monotonic() - started, 5)
            pid = int(pidfile.read_text())
            # Reaped descendants may briefly be zombies on Linux; they cannot run.
            for _ in range(50):
                result = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True)
                if not result.stdout.strip() or result.stdout.strip().startswith('Z'):
                    break
                time.sleep(.02)
            else:
                os.kill(pid, signal.SIGKILL)
                self.fail('descendant survived cleanup')


if __name__ == '__main__':
    unittest.main()

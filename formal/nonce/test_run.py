#!/usr/bin/env python3
"""Fast unit controls for the portable nonce replay runner.

These tests use tiny fixtures and fake JDK executables. They do not run Dafny,
compile generated Java, execute the differential suite or claim any proof
result. They specifically exercise the fail-closed operator/tool selection that
must happen before a replay can reach the proof steps.
"""
import json
from pathlib import Path
import tempfile
import unittest

import run


class PortableConfigTests(unittest.TestCase):
    def test_checked_in_tools_are_host_neutral_and_pinned(self):
        tools = run.validate_portable_tools(json.loads(run.TOOLS.read_text()))
        text = json.dumps(tools, sort_keys=True)
        self.assertEqual(tools['schema'], run.TOOLS_SCHEMA)
        self.assertEqual(tools['dafny']['version'], run.EXPECTED_DAFNY_VERSION)
        self.assertEqual(tools['runtime']['sha256'], run.EXPECTED_RUNTIME_SHA256)
        self.assertNotIn('/Users/', text)
        self.assertNotIn('/home/', text)
        self.assertNotIn(run.EXPECTED_DAFNY_VERSION.split('+')[0] + '-' + 'macos', text)
        self.assertNotIn('9ae7c1d3dc24d82d2bd0058b3c29a1071eacfcebb5782f05d5ed53f8e41662c6',
                         text)

    def test_host_specific_tool_configuration_is_rejected(self):
        tools = json.loads(run.TOOLS.read_text())
        tools['runtime']['path'] = '/Users/example/.m2/DafnyRuntime-4.9.1.jar'
        with self.assertRaisesRegex(run.InputError, 'forbidden'):
            run.validate_portable_tools(tools)

    def test_unreviewed_dafny_build_is_rejected(self):
        tools = json.loads(run.TOOLS.read_text())
        tools['dafny']['version'] = '4.9.1+0000000000000000000000000000000000000000'
        with self.assertRaisesRegex(run.InputError, 'reviewed Dafny build'):
            run.validate_portable_tools(tools)

    def test_wrong_runtime_is_rejected_before_proof(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            runtime = root / 'DafnyRuntime-4.9.1.jar'
            runtime.write_bytes(b'not the pinned jar')
            tools = json.loads(run.TOOLS.read_text())
            with self.assertRaisesRegex(run.InputError, 'checksum mismatch'):
                run.resolve_runtime(runtime, tools)

    def test_core_input_inventory_is_explicit(self):
        inventory = run.input_inventory()
        self.assertIn('formal/nonce/test_run.py', inventory)
        self.assertIn('formal/nonce/bench/NonceBenchmark.java', inventory)
        self.assertNotIn('formal/nonce/packet_bench.py', inventory)
        self.assertNotIn('formal/nonce/bench/PacketKeyBenchmark.java', inventory)


class ToolAssetBindingTests(unittest.TestCase):
    def fixture(self, root):
        cache = root / 'cache'
        distribution = cache / 'dafny-4.9.1-test'
        solver_dir = distribution / 'dafny/z3/bin'
        solver_dir.mkdir(parents=True)
        (distribution / 'dafny/dafny').write_text('fake dafny executable\n')
        runtime = distribution / 'dafny/DafnyRuntime.jar'
        runtime.write_text('fake distribution runtime\n')
        (solver_dir / 'z3-4.12.1').write_text('fake solver\n')
        archive = cache / 'dafny-test.zip'
        archive.write_text('fake archive bytes\n')
        asset = {
            'archive': archive.name,
            'sha256': run.digest(archive),
            'runtime_sha256': run.digest(runtime),
        }
        manifest = {'version': '4.9.1', 'runtime': 'dafny/DafnyRuntime.jar'}
        return cache, distribution, runtime, asset, manifest

    def test_selected_identity_records_archive_executable_solver_and_runtime(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            cache, distribution, runtime, asset, manifest = self.fixture(root)
            identity = run.distribution_identity(
                cache, asset, distribution / 'dafny/dafny', runtime, manifest)
            self.assertEqual(identity['archive']['sha256'], asset['sha256'])
            self.assertEqual(identity['executable']['sha256'],
                             run.digest(distribution / 'dafny/dafny'))
            self.assertIn('z3-4.12.1', identity['solvers'])
            self.assertEqual(identity['distribution_runtime']['sha256'],
                             asset['runtime_sha256'])
            self.assertEqual(identity['distribution_file_count'], 3)

    def test_mismatched_archive_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            cache, distribution, runtime, asset, manifest = self.fixture(root)
            wrong = dict(asset)
            wrong['sha256'] = '0' * 64
            with self.assertRaisesRegex(run.InputError, 'Dafny archive checksum mismatch'):
                run.distribution_identity(
                    cache, wrong, distribution / 'dafny/dafny', runtime, manifest)

    def test_mismatched_distribution_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            cache, distribution, runtime, asset, manifest = self.fixture(root)
            wrong = dict(asset)
            wrong['runtime_sha256'] = '0' * 64
            with self.assertRaisesRegex(run.InputError,
                                        'Dafny distribution runtime checksum mismatch'):
                run.distribution_identity(
                    cache, wrong, distribution / 'dafny/dafny', runtime, manifest)


class JdkSelectionTests(unittest.TestCase):
    def make_jdk(self, root, name, version):
        home = root / name
        binaries = home / 'bin'
        binaries.mkdir(parents=True)
        for executable, text in (
                ('java', f'openjdk version "{version}" 2026-01-01'),
                ('javac', f'javac {version}')):
            path = binaries / executable
            path.write_text(f'#!/bin/sh\necho \'{text}\'\n')
            path.chmod(0o755)
        return home

    def test_one_21_compiler_and_one_25_runtime_are_selected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            workspace = root / 'workspace'
            workspace.mkdir()
            jdk21 = self.make_jdk(root, 'jdk21', '21.0.1')
            jdk25 = self.make_jdk(root, 'jdk25', '25.0.2')
            compiler, runtime, identities = run.select_jdks([jdk25, jdk21], workspace)
            self.assertEqual(compiler['major'], 21)
            self.assertEqual(runtime['major'], 25)
            self.assertEqual(len(identities), 2)

    def test_missing_jdk_home_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            workspace = root / 'workspace'
            workspace.mkdir()
            jdk25 = self.make_jdk(root, 'jdk25', '25.0.2')
            with self.assertRaisesRegex(run.InputError, 'Missing JDK home'):
                run.select_jdks([root / 'absent', jdk25], workspace)

    def test_duplicate_jdk_major_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            workspace = root / 'workspace'
            workspace.mkdir()
            first21 = self.make_jdk(root, 'jdk21-a', '21.0.1')
            second21 = self.make_jdk(root, 'jdk21-b', '21.0.2')
            jdk25 = self.make_jdk(root, 'jdk25', '25.0.2')
            with self.assertRaisesRegex(run.InputError, 'exactly one JDK 21'):
                run.select_jdks([first21, second21, jdk25], workspace)

    def test_duplicate_home_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            workspace = root / 'workspace'
            workspace.mkdir()
            jdk21 = self.make_jdk(root, 'jdk21', '21.0.1')
            jdk25 = self.make_jdk(root, 'jdk25', '25.0.2')
            with self.assertRaisesRegex(run.InputError, 'Duplicate JDK home'):
                run.select_jdks([jdk21, jdk21, jdk25], workspace)


class ControlLocationTests(unittest.TestCase):
    """Dafny prints paths relative to its process cwd when the file is inside it.

    The exact bytes below are the Linux CI control log for PR 128 head 25dee38.
    Dafny was given an absolute path under ROOT, but reported it relative to the
    executor cwd (ROOT), so the old resolver joined it to the mutant folder and
    lost the real source line.
    """

    LINUX_WRONG_ENDIAN_LOG = (
        'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd/controls/wrong-endian/Nonce.dfy'
        '(173,11): Error: assertion might not hold\n'
        '    |\n'
        '173 |     assert nonce[4] == NonceBytes(old(iv[..]), pn)[4];\n'
        '    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n'
        '\n'
        'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd/controls/wrong-endian/Nonce.dfy'
        '(174,11): Error: assertion might not hold\n'
        '    |\n'
        '174 |     assert nonce[5] == NonceBytes(old(iv[..]), pn)[5];\n'
        '    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n'
        '\n'
        'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd/controls/wrong-endian/Nonce.dfy'
        '(175,11): Error: assertion might not hold\n'
        '    |\n'
        '175 |     assert nonce[6] == NonceBytes(old(iv[..]), pn)[6];\n'
        '    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n'
        '\n'
        'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd/controls/wrong-endian/Nonce.dfy'
        '(176,11): Error: assertion might not hold\n'
        '    |\n'
        '176 |     assert nonce[7] == NonceBytes(old(iv[..]), pn)[7];\n'
        '    |            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n'
        '\n'
        '\n'
        'Dafny program verifier finished with 333 verified, 4 errors\n')

    def wrong_endian(self, folder):
        mutant = next(item for item in run.mutations(run.SOURCE.read_text())
                      if item['name'] == 'wrong-endian')
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / 'Nonce.dfy'
        path.write_text(mutant['text'])
        return mutant, path

    def test_repo_relative_paths_resolve_against_the_executor_cwd(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = (checkout / 'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd'
                      / 'controls/wrong-endian')
            mutant, path = self.wrong_endian(folder)
            lines = path.read_text().splitlines()
            self.assertEqual(lines[172].strip(), mutant['anchor'])
            result = run.check_rejected(4, self.LINUX_WRONG_ENDIAN_LOG, mutant, path,
                                        diagnostic_cwd=checkout)
            self.assertEqual(result['status'], 'proof-obligation-rejected')
            self.assertEqual([item['line'] for item in result['observations']], [173])
            self.assertTrue(all(Path(item['path']) == path.resolve()
                                for item in result['observations']))
            self.assertTrue(all(item['owned'] for item in result['observations']))

    def test_absolute_output_outside_the_checkout_still_resolves(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            checkout = root / 'checkout'
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            external = root / 'external-output' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            external.mkdir(parents=True)
            absolute = external / 'Nonce.dfy'
            absolute.write_bytes(path.read_bytes())
            log = self.LINUX_WRONG_ENDIAN_LOG.replace(
                'target/dafny-nonce/run-6EkIG7/replay-ir3z1pyd/controls/wrong-endian/Nonce.dfy',
                str(absolute))
            result = run.check_rejected(4, log, mutant, absolute, diagnostic_cwd=checkout)
            self.assertEqual([item['line'] for item in result['observations']], [173])

    def test_related_location_anchor_must_match_its_own_kind(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'alias-freshness'
            folder.mkdir(parents=True)
            path = folder / 'Nonce.dfy'
            lines = [''] * 205
            lines[204] = '    ensures nonce != iv'
            path.write_text('\n'.join(lines) + '\n')
            relative = 'target/controls/alias-freshness/Nonce.dfy'
            log = (f'{relative}(100,9): Error: a freshness obligation depends on this\n'
                   f'{relative}(205,5): Related location: this is the postcondition\n'
                   'Dafny program verifier finished with 341 verified, 2 errors\n')
            mutant = {'name': 'alias-freshness', 'kind': 'Related location',
                      'anchor': 'ensures nonce != iv',
                      'expected': 'returning the IV aliases the output'}
            result = run.check_rejected(4, log, mutant, path, diagnostic_cwd=checkout)
            self.assertEqual([(item['kind'], item['line']) for item in result['observations']],
                             [('Related location', 205)])

    def test_wrong_file_inside_the_workspace_does_not_satisfy_the_anchor(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            other = folder / 'Other.dfy'
            other.write_bytes(path.read_bytes())
            log = self.LINUX_WRONG_ENDIAN_LOG.replace('wrong-endian/Nonce.dfy',
                                                      'wrong-endian/Other.dfy')
            with self.assertRaisesRegex(RuntimeError, 'did not fail at the intended'):
                run.check_rejected(4, log, mutant, path, diagnostic_cwd=checkout)

    def test_path_escape_missing_file_and_wrong_line_cannot_count(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            escape = checkout / 'outside' / 'Nonce.dfy'
            escape.parent.mkdir(parents=True)
            escape.write_bytes(path.read_bytes())
            probes = (
                '../outside/Nonce.dfy',
                'target/controls/wrong-endian/Missing.dfy',
                'target/controls/wrong-endian/Nonce.dfy',
            )
            for index, relative in enumerate(probes):
                line = 173 if index != 2 else 172
                log = (f'{relative}({line},11): Error: assertion might not hold\n'
                       'Dafny program verifier finished with 333 verified, 4 errors\n')
                with self.subTest(relative=relative, line=line):
                    with self.assertRaisesRegex(RuntimeError,
                                                'did not fail at the intended'):
                        run.check_rejected(4, log, mutant, path, diagnostic_cwd=checkout)

    def test_invalid_line_and_missing_diagnostics_cannot_count(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            relative = 'target/controls/wrong-endian/Nonce.dfy'
            for line in (0, 99999):
                log = (f'{relative}({line},11): Error: assertion might not hold\n'
                       'Dafny program verifier finished with 333 verified, 4 errors\n')
                with self.subTest(line=line):
                    with self.assertRaisesRegex(RuntimeError,
                                                'did not fail at the intended'):
                        run.check_rejected(4, log, mutant, path, diagnostic_cwd=checkout)
            with self.assertRaisesRegex(RuntimeError, 'did not fail at the intended'):
                run.check_rejected(
                    4, 'Dafny program verifier finished with 333 verified, 4 errors\n',
                    mutant, path, diagnostic_cwd=checkout)

    def test_timeout_resource_and_non_error_status_remain_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            inconclusive = self.LINUX_WRONG_ENDIAN_LOG + 'Error: out of resource\n'
            for status, log in ((4, inconclusive), (0, self.LINUX_WRONG_ENDIAN_LOG),
                                (4, self.LINUX_WRONG_ENDIAN_LOG.replace(
                                    '4 errors', '0 errors'))):
                with self.subTest(status=status, tail=log[-40:]):
                    with self.assertRaisesRegex(RuntimeError,
                                                'did not fail a proof obligation'):
                        run.check_rejected(status, log, mutant, path,
                                           diagnostic_cwd=checkout)

    def test_empty_anchor_cannot_match_a_valid_location(self):
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name).resolve()
            folder = checkout / 'target' / 'controls' / 'wrong-endian'
            mutant, path = self.wrong_endian(folder)
            relative = 'target/controls/wrong-endian/Nonce.dfy'
            log = (f'{relative}(173,11): Error: assertion might not hold\n'
                   'Dafny program verifier finished with 333 verified, 4 errors\n')
            empty = dict(mutant, anchor='')
            with self.assertRaisesRegex(RuntimeError, 'did not fail at the intended'):
                run.check_rejected(4, log, empty, path, diagnostic_cwd=checkout)

    def test_parse_locations_reads_only_inside_the_owned_workspace(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            cwd = root / 'cwd'
            workspace = cwd / 'workspace'
            outside = root / 'outside'
            workspace.mkdir(parents=True)
            outside.mkdir(parents=True)
            owned = workspace / 'Nonce.dfy'
            owned.write_text('first\nanchor line\n')
            (outside / 'Nonce.dfy').write_text('first\nanchor line\n')

            def parse(relative):
                output = f'{relative}(2,3): Error: boom\n'
                return run.parse_locations(output, workspace, diagnostic_cwd=cwd)[0]

            inside = parse('workspace/Nonce.dfy')
            self.assertTrue(inside['owned'])
            self.assertEqual(inside['path'], str(owned.resolve()))
            self.assertEqual(inside['source'], 'anchor line')

            escaped = parse('../outside/Nonce.dfy')
            self.assertFalse(escaped['owned'])
            self.assertEqual(escaped['source'], '')

            absolute = run.parse_locations(
                f'{outside / "Nonce.dfy"}(2,3): Error: boom\n', workspace,
                diagnostic_cwd=cwd)[0]
            self.assertFalse(absolute['owned'])
            self.assertEqual(absolute['source'], '')

            uri = parse('file:///etc/Nonce.dfy')
            self.assertFalse(uri['owned'])
            self.assertEqual(uri['source'], '')


if __name__ == '__main__':
    unittest.main()

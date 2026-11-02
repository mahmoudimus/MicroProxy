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


if __name__ == '__main__':
    unittest.main()

"""Admission and failure-classification regressions for the current consumer epoch."""
import copy
import importlib._bootstrap_external
import os
import sys
import types
from unittest import mock
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def module():
    name = 'epoch004_ownership_api'
    value = types.ModuleType(name)
    value.__file__ = str(HERE / 'replay.py')
    sys.modules[name] = value
    exec(compile((HERE / 'replay.py').read_bytes(), value.__file__, 'exec',
                 dont_inherit=True, optimize=0), value.__dict__)
    return value


class AuthorityTests(unittest.TestCase):
    def test_omitted_semantic_or_parser_control_is_rejected(self):
        replay = module()
        expected = copy.deepcopy(replay.REQUIRED_CONTROLS)
        replay.check_controls(expected)
        for kind, names in expected.items():
            for name in names:
                altered = copy.deepcopy(expected)
                altered[kind].remove(name)
                with self.subTest(kind=kind, name=name), self.assertRaises(ValueError):
                    replay.check_controls(altered)
        with self.assertRaises(ValueError):
            replay.check_controls({**expected, 'unchecked': ['optional']})

    def test_manifest_authority_precedes_json_parsing(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'manifest.json'
            path.write_bytes(b'not JSON')
            with self.assertRaisesRegex(ValueError, 'external expected digest'):
                replay.authenticated_json(path, '0' * 64)

    def test_duplicate_keys_and_source_substitution_are_rejected(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            manifest = root / 'manifest.json'
            manifest.write_text('{"schema":"first","schema":"second"}')
            with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
                replay.authenticated_json(manifest, replay.sha(manifest))
            source = root / 'Source.dfy'
            source.write_text('module Original {}')
            pins = {'Source.dfy': replay.sha(source)}
            replay.read_map(root, pins)
            source.write_text('module Substitute {}')
            with self.assertRaisesRegex(ValueError, 'hash changed'):
                replay.read_map(root, pins)

    def test_symlink_hardlink_and_case_alias_input_domains_are_rejected(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'Source.dfy'
            source.write_text('module Original {}')
            pin = replay.sha(source)
            (root / 'Link.dfy').symlink_to(source)
            with self.assertRaises(ValueError):
                replay.read_map(root, {'Link.dfy': pin})
            (root / 'Hard.dfy').hardlink_to(source)
            with self.assertRaises(ValueError):
                replay.read_map(root, {'Source.dfy': pin})
            with self.assertRaises(ValueError):
                replay.validate_pin_map({'Source.dfy': pin, 'source.dfy': pin})

    def test_output_alias_admission_precedes_any_creation(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            protected = root / 'protected'
            protected.mkdir()
            for target in [protected, protected / 'output', root]:
                with self.subTest(target=target), self.assertRaises(ValueError):
                    replay.output_admission(target, [protected])
            redirected = root / 'redirected'
            redirected.symlink_to(protected, target_is_directory=True)
            with self.assertRaises(ValueError):
                replay.output_admission(redirected / 'output', [protected])
            fresh = root / 'fresh'
            self.assertEqual(replay.output_admission(fresh, [protected]), fresh)
            self.assertFalse(fresh.exists())

    def test_epoch_manifest_rejects_source_substitution_and_old_counts_authority(self):
        replay = module()
        path = HERE / 'observation-inputs.json'
        authority = json.loads(path.read_text())
        replay.validate_manifest(authority)
        altered = copy.deepcopy(authority)
        altered['current_sources']['formal/crypto/NativeKeccak.dfy'] = '0' * 64
        with self.assertRaises(ValueError):
            replay.validate_manifest(altered)
        altered = copy.deepcopy(authority)
        altered['consumers']['ownership']['proof_counts']['complete_source'] = 1552
        with self.assertRaises(ValueError):
            replay.validate_manifest(altered)
        altered = copy.deepcopy(authority)
        altered['qualification'] = True
        with self.assertRaises(ValueError):
            replay.validate_manifest(altered)

    def test_control_failure_requires_exact_location_anchor_and_classification(self):
        replay = module()
        entry = 'formal/source/Control-factory-alias.dfy'
        anchor = 'assert s.lanes == s.scratch;'
        text = (entry + '(42,5): Error: assertion might not hold\n'
                '42 | ' + anchor + '\n'
                'Dafny program verifier finished with 1 verified, 1 error\n')
        replay.negative_result(4, text, 1, entry, 42, anchor)
        invalid = [
            (0, text), (2, text), (124, text),
            (4, text.replace('(42,', '(41,')),
            (4, text.replace(entry, 'Other.dfy')),
            (4, text.replace(anchor, 'assert other;')),
            (4, text.replace('assertion might not hold', 'a precondition for this call could not be proved')),
            (4, text.replace('1 verified, 1 error', '0 verified, 1 error')),
            (4, text + 'Verification out of resources\n'),
            (4, text + 'CASE-TIMEOUT\n'), (4, text + 'System.InvalidOperationException\n'),
            (4, text + 'Warning: skipped declaration\n'),
            (4, text + entry + '(42,5): Error: assertion might not hold\n'),
        ]
        for status, altered in invalid:
            with self.subTest(status=status, text=altered), self.assertRaises(ValueError):
                replay.negative_result(status, altered, 1, entry, 42, anchor)


class ExecutionClosureTests(unittest.TestCase):
    def test_real_valid_poisoned_cache_cannot_replace_authenticated_source(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'toolchain.py'
            source.write_bytes((HERE.parents[3] / 'dafny/toolchain.py').read_bytes())
            expected = replay.sha(source)
            payload = compile('BYTECODE_POISON = True\n', str(source), 'exec')
            pyc = Path(importlib.util.cache_from_source(str(source)))
            pyc.parent.mkdir()
            pyc.write_bytes(importlib._bootstrap_external._code_to_timestamp_pyc(
                payload, int(source.stat().st_mtime), source.stat().st_size))
            # This is a real importable timestamp cache for the authentic source.
            loaded = replay.load_module(source, 'poisoned_helper_probe', expected)
            self.assertFalse(hasattr(loaded, 'BYTECODE_POISON'))
            self.assertTrue(callable(loaded.validate_member))
            self.assertEqual(replay.sha(source), expected)

    def test_real_child_drops_python_hooks_and_all_inherited_selectors(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            poison = root / 'poison'; poison.mkdir()
            inherited_home = root / 'inherited-home'; inherited_home.mkdir()
            (inherited_home / 'private-config').write_text('untrusted parent configuration')
            marker = root / 'sitecustomize-executed'
            (poison / 'sitecustomize.py').write_text(
                'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
            selectors = {
                'PYTHONPATH': str(poison), 'PYTHONPYCACHEPREFIX': str(root / 'foreign-bytecode'),
                'DOTNET_STARTUP_HOOKS': 'untrusted-hook.dll', 'DOTNET_ADDITIONAL_DEPS': 'untrusted.deps.json',
                'DOTNET_SHARED_STORE': str(poison), 'CORECLR_ENABLE_PROFILING': '1', 'CORECLR_PROFILER': 'untrusted',
                'LD_LIBRARY_PATH': str(poison), 'DYLD_LIBRARY_PATH': str(poison),
                'LD_PRELOAD': str(poison / 'absent.so'), 'DYLD_INSERT_LIBRARIES': str(poison / 'absent.dylib'),
                'PYTHONHOME': str(poison), 'PYTHONSTARTUP': str(poison / 'sitecustomize.py'),
                'PYTHONUSERBASE': str(poison), 'PYTHONINSPECT': '1',
                'DOTNET_ROOT': str(poison), 'DOTNET_ROLL_FORWARD': 'LatestMajor',
                'COR_ENABLE_PROFILING': '1', 'COR_PROFILER': 'untrusted',
                'DAFNY_OPTIONS': '--no-verify', 'MICROPROXY_UNREVIEWED_ENV': 'untrusted',
                'HOME': str(inherited_home), 'XDG_CONFIG_HOME': str(inherited_home),
            }
            probe = ('import json,os,sys;from pathlib import Path;'
                     'print(json.dumps({"environment":dict(os.environ),"isolated":sys.flags.isolated,'
                     '"no_bytecode":sys.dont_write_bytecode,"home_entries":[p.name for p in Path.home().iterdir()]}))')
            command = [sys.executable, '-B', '-c', probe]
            with mock.patch.dict(os.environ, selectors):
                status, text = replay.execute(command, root / 'child.log', root,
                                              child_root=root / 'child-state', timeout=20)
            self.assertEqual(status, 0, text)
            self.assertFalse(marker.exists(), 'inherited PYTHONPATH executed sitecustomize')
            record = json.loads(text)
            self.assertFalse(set(selectors) - {'HOME', 'XDG_CONFIG_HOME'} & set(record['environment']))
            self.assertNotEqual(record['environment']['HOME'], str(inherited_home))
            self.assertEqual(record['isolated'], 1)
            self.assertTrue(record['no_bytecode'])
            self.assertEqual(record['home_entries'], [])

    def test_module_context_pin_gate_and_failure_registry_restoration(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'context.py'
            source.write_text('import sys\nfrom dataclasses import dataclass\n'
                              'assert sys.modules[__name__].__file__ == __file__\n'
                              '@dataclass\nclass Record:\n    value: int\n')
            value = replay.load_module(source, 'owned.context_probe', replay.sha(source))
            self.assertIs(sys.modules['owned.context_probe'], value)
            self.assertEqual(value.__package__, 'owned')
            self.assertEqual(value.__spec__.origin, str(source))
            self.assertIsNone(value.__cached__)
            self.assertEqual(value.Record(3).value, 3)
            source.write_text('raise RuntimeError("module body failed")\n')
            with self.assertRaisesRegex(RuntimeError, 'module body failed'):
                replay.load_module(source, 'owned.context_probe', replay.sha(source))
            self.assertIs(sys.modules['owned.context_probe'], value)
            with self.assertRaises(RuntimeError):
                replay.load_module(source, 'absent_context_probe', replay.sha(source))
            self.assertNotIn('absent_context_probe', sys.modules)
            with self.assertRaisesRegex(ValueError, 'module hash changed'):
                replay.load_module(source, 'owned.context_probe', '0' * 64)
            self.assertIs(sys.modules['owned.context_probe'], value)

    def test_module_executes_same_captured_bytes_after_pin_check(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'captured.py'
            source.write_text('VALUE = "captured"\n')
            expected = replay.sha(source)
            original = replay.regular
            def capture_then_replace(path, *arguments):
                raw = original(path, *arguments)
                Path(path).write_text('VALUE = "substitute"\n')
                return raw
            with mock.patch.object(replay, 'regular', capture_then_replace):
                value = replay.load_module(source, 'captured_probe', expected)
            self.assertEqual(value.VALUE, 'captured')
            self.assertNotEqual(replay.sha(source), expected)

    def test_executor_preserves_merged_output_status_and_timeout_rejection(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            status, text = replay.execute([sys.executable, '-c',
                'import sys;print("stdout",flush=True);print("stderr",file=sys.stderr,flush=True);sys.exit(7)'],
                root / 'merged.log', root, timeout=20, child_root=root / 'merged-state')
            self.assertEqual(status, 7)
            self.assertEqual(text, 'stdout\nstderr\n')
            status, text = replay.execute([sys.executable, '-c', 'import time;time.sleep(30)'],
                root / 'timeout.log', root, timeout=0.2, child_root=root / 'timeout-state')
            self.assertEqual(status, 124)
            self.assertIn('CASE-TIMEOUT', text)
            with self.assertRaises(ValueError):
                replay.negative_result(status, text, 1, 'Control.dfy', 1, 'assert false;')

    def test_child_configuration_is_new_private_and_never_reused(self):
        replay = module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / 'state'
            environment = replay.child_environment(root)
            self.assertEqual(set(environment), {'PATH', 'LANG', 'LC_ALL', 'TZ', 'HOME',
                'TMPDIR', 'TMP', 'TEMP', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME',
                'XDG_DATA_HOME', 'DOTNET_CLI_HOME'})
            for key in ['HOME', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'DOTNET_CLI_HOME']:
                path = Path(environment[key])
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                self.assertEqual(list(path.iterdir()), [])
            (root / 'home' / 'untrusted').write_text('preserve')
            with self.assertRaises(FileExistsError):
                replay.child_environment(root)
            self.assertEqual((root / 'home' / 'untrusted').read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()

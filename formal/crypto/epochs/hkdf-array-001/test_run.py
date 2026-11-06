"""Data-only admission controls. Unit fixtures confer no proof qualification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest
import warnings
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run as E
A = E.A


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(root, name, raw):
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw)
    return {'path': name, 'sha256': sha(raw)}


class DeltaAdmission(unittest.TestCase):
    def setUp(self):
        self.before = {'A.class': sha(b'a'), 'B.class': sha(b'b'), 'C.class': sha(b'c')}
        self.after = {**self.before, 'A.class': sha(b'new-a'), 'B.class': sha(b'new-b')}
        self.allowed = {'changed': {'A.class': {'before': self.before['A.class'], 'after': self.after['A.class']},
                                    'B.class': {'before': self.before['B.class'], 'after': self.after['B.class']}},
                        'added': {}, 'removed': {}}

    def test_exact_two_changed_entries_are_returned(self):
        self.assertEqual(self.allowed, A.check_delta(self.before, self.after, self.allowed))

    def test_unauthorized_third_class_is_rejected(self):
        self.after['C.class'] = sha(b'changed-c')
        with self.assertRaisesRegex(A.EpochError, 'delta'):
            A.check_delta(self.before, self.after, self.allowed)

    def test_missing_extra_and_unchanged_permitted_entries_are_rejected(self):
        for change in ('missing', 'extra', 'unchanged'):
            after = dict(self.after)
            if change == 'missing':
                del after['C.class']
            elif change == 'extra':
                after['D.class'] = sha(b'd')
            else:
                after['B.class'] = self.before['B.class']
            with self.subTest(change=change), self.assertRaisesRegex(A.EpochError, 'delta'):
                A.check_delta(self.before, after, self.allowed)

    def test_added_and_removed_entries_require_their_exact_hashes(self):
        allowed = {'changed': {}, 'added': {'new.java': sha(b'n')}, 'removed': {'old.java': sha(b'o')}}
        self.assertEqual(allowed, A.check_delta({'old.java': sha(b'o')}, {'new.java': sha(b'n')}, allowed))
        allowed['removed']['old.java'] = sha(b'other')
        with self.assertRaises(A.EpochError):
            A.check_delta({'old.java': sha(b'o')}, {'new.java': sha(b'n')}, allowed)

    def test_noncanonical_paths_hashes_and_case_aliases_reject(self):
        for name in ('../outside', '/absolute', 'x//y', './x', 'x/../y', 'x\\y', 'x:y', 'x\ny'):
            with self.subTest(name=name), self.assertRaises(A.EpochError):
                A.check_delta({}, {name: sha(b'x')}, {'changed': {}, 'added': {name: sha(b'x')}, 'removed': {}})
        with self.assertRaises(A.EpochError):
            A.check_delta({'A': sha(b'a'), 'a': sha(b'b')}, {}, {'changed': {}, 'added': {}, 'removed': {}})
        with self.assertRaises(A.EpochError):
            A.check_delta({'A': '0' * 63}, {}, {'changed': {}, 'added': {}, 'removed': {}})


class PolicyAdmission(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        refs = {name: put(self.root, name + '.json', json.dumps({'fixture': name}).encode())
                for name in ('ci', 'selection', 'manifest', 'receipt', 'projector', 'old-config', 'config', 'native', 'api')}
        self.data = {
            'schema': 'microproxy.hkdf-array-epoch-inputs/1', 'epoch': 'hkdf-array-001', 'qualification': False,
            'predecessor': {'inputs': {r['path']: r['sha256'] for r in refs.values()}, 'classes': {'A.class': sha(b'old')}},
            'candidate': {'inputs': {r['path']: r['sha256'] for r in refs.values()}, 'classes': {'A.class': sha(b'new')}},
            'allowed': {'inputs': {'changed': {}, 'added': {}, 'removed': {}},
                        'classes': {'changed': {'A.class': {'before': sha(b'old'), 'after': sha(b'new')}}, 'added': {}, 'removed': {}}},
            'retained': {'ci': refs['ci'], 'selection': refs['selection'], 'prepared_receipt_sha256': sha(b'prepared')},
            'hkdf': {'manifest': refs['manifest'], 'receipt': refs['receipt'], 'projector': refs['projector'],
                     'raw_files': {'report.json': sha(b'raw')}, 'producers': {'projector.json': refs['projector']['sha256']},
                     'tool_map_sha256': sha(b'tools')},
            'delivery': {'predecessor': refs['old-config'], 'config': refs['config'], 'native_evidence': refs['native'],
                         'api': refs['api'], 'timeout': 1800, 'build_outputs': {'directories': {}, 'files': {}}},
            'tools': {k: sha(k.encode()) for k in ('runtime_sha256', 'jdk21_tree_sha256', 'jdk25_tree_sha256',
                                                  'maven_tree_sha256', 'maven_repository_tree_sha256', 'python_sha256')},
        }
        self.path = self.root / 'inputs.json'

    def save(self):
        self.path.write_text(json.dumps(self.data))
        return sha(self.path.read_bytes())

    def test_selected_policy_and_all_candidate_input_bytes_are_bound(self):
        selected = self.save()
        result = A.load_policy(self.root, self.path, selected)
        self.assertEqual(self.data, result)
        (self.root / 'api.json').write_bytes(b'changed')
        with self.assertRaisesRegex(A.EpochError, 'input'):
            A.load_policy(self.root, self.path, selected)

    def test_selected_config_is_installed_at_canonical_path_only_in_new_view(self):
        old = put(self.root, 'formal/crypto/delivery.json', b'old canonical config')
        self.data['predecessor']['inputs'][old['path']] = old['sha256']
        selected = self.data['delivery']['config']['sha256']
        self.data['candidate']['inputs'][old['path']] = selected
        self.data['allowed']['inputs']['changed'][old['path']] = {'before': old['sha256'], 'after': selected}
        policy = A.load_policy(self.root, self.path, self.save())
        self.assertEqual(selected, policy['candidate']['inputs'][old['path']])
        self.assertEqual(b'old canonical config', (self.root / old['path']).read_bytes())

    def test_missing_wrong_and_placeholder_selection_reject_before_execution(self):
        self.save()
        for expected in ('', None, '0' * 64, 'a' * 64):
            with self.subTest(expected=expected), self.assertRaises(A.EpochError):
                A.load_policy(self.root, self.path, expected)

    def test_unknown_fields_old_epoch_and_global_qualification_reject(self):
        for field, value in (('unknown', True), ('schema', 'microproxy.hkdf-source-traces/v1'),
                             ('epoch', 'keccak-004'), ('qualification', True)):
            data = copy.deepcopy(self.data)
            data[field] = value
            self.path.write_text(json.dumps(data))
            with self.subTest(field=field), self.assertRaises(A.EpochError):
                A.load_policy(self.root, self.path, sha(self.path.read_bytes()))

    def test_unauthorized_third_input_cannot_hide_in_coherent_policy_maps(self):
        self.data['candidate']['inputs']['extra.java'] = sha(b'extra')
        put(self.root, 'extra.java', b'extra')
        with self.assertRaisesRegex(A.EpochError, 'delta'):
            A.load_policy(self.root, self.path, self.save())

    def test_symlink_and_hardlink_inputs_reject_even_with_matching_hash(self):
        selected = self.save()
        victim = self.root / 'api.json'
        other = self.root / 'actual.json'
        victim.rename(other)
        victim.symlink_to(other.name)
        with self.assertRaisesRegex(A.EpochError, 'symlink'):
            A.load_policy(self.root, self.path, selected)
        victim.unlink()
        os.link(other, victim)
        with self.assertRaisesRegex(A.EpochError, 'alias'):
            A.load_policy(self.root, self.path, selected)

    def test_duplicate_json_keys_and_absolute_policy_paths_reject(self):
        self.path.write_text('{"schema":"a","schema":"b"}')
        with self.assertRaisesRegex(A.EpochError, 'duplicate'):
            A.load_policy(self.root, self.path, sha(self.path.read_bytes()))
        self.data['hkdf']['raw_root'] = '/Users/private/cache'
        with self.assertRaisesRegex(A.EpochError, 'inventory'):
            A.load_policy(self.root, self.path, self.save())

    def test_mutating_loaded_policy_cannot_select_new_authority(self):
        policy = A.load_policy(self.root, self.path, self.save())
        policy['candidate']['classes']['C.class'] = sha(b'new')
        with self.assertRaisesRegex(A.EpochError, 'policy.*changed'):
            A.reauthenticate(policy)

    def test_missing_runtime_authority_cannot_create_qualified_output(self):
        policy = A.load_policy(self.root, self.path, self.save())
        output = self.root.parent / (self.root.name + '-not-created')
        with self.assertRaises(A.EpochError):
            E.qualify(self.root, policy, output, self.root / 'library.jar', self.root / 'bundle.jar',
                      self.root / 'runtime.jar', self.root / 'jdk21', self.root / 'jdk25')
        self.assertFalse(output.exists())

    def test_source_only_authority_has_no_candidate_class_map_or_qualification_right(self):
        self.data['schema'] = 'microproxy.hkdf-array-source-inputs/1'
        del self.data['candidate']['classes']
        del self.data['allowed']['classes']
        del self.data['tools']['maven_repository_tree_sha256']
        selected = self.save()
        with self.assertRaises(A.EpochError):
            A.load_policy(self.root, self.path, selected)
        policy = A.load_source_policy(self.root, self.path, selected)
        self.assertNotIn('classes', policy['candidate'])
        with self.assertRaisesRegex(A.EpochError, 'source-only'):
            E.qualify(self.root, policy, self.root / 'out', self.root / 'library.jar', self.root / 'bundle.jar',
                      self.root / 'runtime.jar', self.root / 'jdk21', self.root / 'jdk25')
        self.assertFalse((self.root / 'out').exists())


class RawSourceAndOutputAdmission(unittest.TestCase):
    def test_nonisolated_epoch_rejects_before_ambient_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / 'run.py'
            path.write_bytes((HERE / 'run.py').read_bytes())
            (root / 'argparse.py').write_text(
                'print("UNAUTHORIZED_ARGPARSE_SENTINEL")\nraise SystemExit(77)\n')
            env = {**os.environ, 'PYTHONPATH': str(root)}
            for flags in (['-B'], ['-B', '-O'], ['-B', '-OO']):
                with self.subTest(flags=flags):
                    result = subprocess.run(
                        [sys.executable, *flags, str(path), '--help'], env=env,
                        capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(77, result.returncode)
                    self.assertNotIn('UNAUTHORIZED_ARGPARSE_SENTINEL', result.stdout + result.stderr)
                    message = ('requires unoptimized Python' if len(flags) > 1
                               else 'requires Python -I -B')
                    self.assertIn(message, result.stderr)

    def test_epoch_rejects_missing_B_before_bootstrap_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'run.py'
            path.write_bytes((HERE / 'run.py').read_bytes())
            result = subprocess.run(
                [sys.executable, '-I', str(path), '--help'],
                capture_output=True, text=True, timeout=10)
            self.assertIn('requires Python -I -B', result.stderr)
            self.assertNotIn('FileNotFoundError', result.stderr)

    def test_optimized_epoch_entry_rejects_before_cli(self):
        for flag in ('-O', '-OO'):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, '-I', '-B', flag, str(HERE / 'run.py'), '--help'],
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('requires unoptimized Python', result.stderr)
                self.assertEqual('', result.stdout)

    def test_optimized_epoch_entry_rejects_before_bootstrap_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / 'run.py'
            path.write_bytes((HERE / 'run.py').read_bytes())
            # No bootstrap exists. Optimization must be rejected before its read.
            for flag in ('-O', '-OO'):
                with self.subTest(flag=flag):
                    result = subprocess.run(
                        [sys.executable, '-I', '-B', flag, str(path), '--help'],
                        capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn('requires unoptimized Python', result.stderr)
                    self.assertNotIn('FileNotFoundError', result.stderr)
                    self.assertEqual(['run.py'], sorted(p.name for p in path.parent.iterdir()))

    def test_epoch_runner_never_imports_poisoned_admission_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'run.py').write_bytes((HERE / 'run.py').read_bytes())
            path = root / 'admission.py'
            actual = (HERE / 'admission.py').read_bytes()
            evil = b'raise SystemExit(77)\n'
            path.write_bytes(evil + b'#' * (len(actual) - len(evil)))
            stamp = path.stat()
            py_compile.compile(str(path), doraise=True)
            path.write_bytes(actual)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            result = subprocess.run([sys.executable, '-I', '-B', str(root / 'run.py'), '--help'], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('qualify', result.stdout)

    def test_poisoned_bytecode_does_not_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            p = root / 'tool.py'
            p.write_bytes(b'value = "EVIL"\n')
            stamp = p.stat()
            py_compile.compile(str(p), doraise=True)
            p.write_bytes(b'value = "GOOD"\n')
            os.utime(p, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            spec = importlib.util.spec_from_file_location('poisoned_control', p)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertEqual('EVIL', module.value)
            self.assertEqual('GOOD', A.load_module('raw_control', p, sha(p.read_bytes())).value)

    def test_wrong_source_pin_rejects_before_any_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            p = root / 'tool.py'
            p.write_text('raise RuntimeError("executed unselected source")')
            with self.assertRaisesRegex(A.EpochError, 'source pin'):
                A.load_module('unselected', p, sha(b'other'))

    def test_output_checks_both_overlap_directions_before_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in ('project', 'tools', 'jdk21', 'jdk25', 'runtime', 'raw'):
                protected = root / name
                protected.mkdir()
                for output in (protected / 'new', root):
                    with self.subTest(name=name, output=output), self.assertRaisesRegex(A.EpochError, 'overlap'):
                        A.output_admission(output, {name: protected})
                self.assertFalse((protected / 'new').exists())
            self.assertEqual(root / 'new', A.output_admission(root / 'new', {'project': root / 'project'}))


class DeliveryBoundaryControls(unittest.TestCase):
    def test_only_exact_selected_hkdf_generated_config_pins_may_change(self):
        before = {'native_evidence': {'required_source_pins': {'NativeKeccak.dfy': sha(b'k')}},
                  'javac': {'release': '21'}, 'existing_generated_sources': {'Hkdf.java': sha(b'old'), 'Native.java': sha(b'n')}}
        after = copy.deepcopy(before)
        after['existing_generated_sources']['Hkdf.java'] = sha(b'new')
        delta = {'Hkdf.java': {'before': sha(b'old'), 'after': sha(b'new')}}
        self.assertEqual(delta, E.check_delivery_config(before, after, delta))
        for section, value in (('javac', {'release': '25'}), ('native_evidence', {})):
            changed = copy.deepcopy(after)
            changed[section] = value
            with self.subTest(section=section), self.assertRaisesRegex(A.EpochError, 'delivery.*policy'):
                E.check_delivery_config(before, changed, delta)

    def test_old_configuration_stage_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            put(root, 'receipt.json', json.dumps({'status': 'complete', 'component': None,
                'manifest_sha256': sha(b'old-config'), 'jdk_home': str(root / 'jdk21')}).encode())
            with self.assertRaisesRegex(A.EpochError, 'stage.*configuration'):
                E.check_stage(root, sha(b'new-config'), root / 'jdk21')

    def test_jar_hook_rejects_duplicate_and_multirelease_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            jar = root / 'actual.jar'
            classes = {'hkdf/A.class': sha(b'a')}
            with ZipFile(jar, 'w') as z:
                z.writestr('hkdf/A.class', b'a')
            self.assertEqual(classes, E.check_jar_subset(jar, classes))
            for name in ('hkdf/A.class', 'META-INF/versions/21/hkdf/A.class'):
                with ZipFile(jar, 'w') as z:
                    z.writestr('hkdf/A.class', b'a')
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        z.writestr(name, b'a')
                with self.subTest(name=name), self.assertRaises(A.EpochError):
                    E.check_jar_subset(jar, classes)

    def test_jar_hook_preserves_existing_api_module_descriptor_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp).resolve() / 'descriptor.jar'
            with ZipFile(jar, 'w') as z:
                z.writestr('hkdf/A.class', b'a')
                z.writestr('META-INF/versions/9/module-info.class', b'declarative module descriptor')
            self.assertEqual({'hkdf/A.class': sha(b'a')}, E.check_jar_subset(jar, {'hkdf/A.class': sha(b'a')}))

    def test_old_whole_class_map_cannot_be_promoted_to_new_subject(self):
        before, after = {'A.class': sha(b'old')}, {'A.class': sha(b'new')}
        allowed = {'changed': {'A.class': {'before': before['A.class'], 'after': after['A.class']}}, 'added': {}, 'removed': {}}
        with self.assertRaisesRegex(A.EpochError, 'delta'):
            A.check_delta(before, before, allowed)

    def test_native_provider_and_generated_class_changes_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ref = put(root, 'Native.java', b'original native provider')
            stage = {'inputs': {ref['path']: ref['sha256']}, 'delivered_sources': {},
                     'canonical_classes': {'Native.class': sha(b'native-class')}}
            classes = {'Native.class': sha(b'native-class'), 'Hkdf.class': sha(b'hkdf')}
            self.assertEqual(stage['inputs'], E.check_native_binding(root, stage, classes, {}))
            (root / 'Native.java').write_bytes(b'changed provider')
            with self.assertRaisesRegex(A.EpochError, 'native'):
                E.check_native_binding(root, stage, classes, {})
            put(root, 'Native.java', b'original native provider')
            classes['Native.class'] = sha(b'other-native-class')
            with self.assertRaisesRegex(A.EpochError, 'native'):
                E.check_native_binding(root, stage, classes, {})

    def test_unchanged_artifact_api_must_complete_on_the_same_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = {'schema': 'microproxy.crypto-current-release-artifact-validation/v1', 'status': 'complete',
                      'repository_root': str(root), 'tool_root': str(root)}
            self.assertEqual(report, E.check_artifact_result(root, report))
            for key, value in (('status', 'incomplete'), ('tool_root', str(root / 'other')),
                               ('repository_root', str(root / 'old-project'))):
                changed = {**report, key: value}
                with self.subTest(key=key), self.assertRaisesRegex(A.EpochError, 'artifact'):
                    E.check_artifact_result(root, changed)


class HkdfEvidenceControls(unittest.TestCase):
    def test_actual_projector_rejects_incomplete_raw_execution_after_rehash(self):
        projector = HERE.parents[2] / 'source/hkdf/tooling/source_evidence.py'
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp).resolve()
            put(raw, 'report.json', json.dumps({'status': 'complete bounded coverage', 'phase': 'coverage'}).encode())
            with self.assertRaisesRegex(ValueError, 'completed full'):
                E.project_hkdf(raw, projector, sha(projector.read_bytes()))

    def test_retained_parent_rejects_whole_poly_fallback(self):
        root = HERE.parents[3]
        parent_path = root / 'formal/source/epochs/keccak-004/parent/parent.py'
        parent = A.load_module('test_original_epoch_parent', parent_path, sha(parent_path.read_bytes()))
        original = json.loads((parent_path.parent / 'policy.json').read_text())
        self.assertEqual(original, parent.validate_policy(original))
        changed = copy.deepcopy(original)
        changed['reuse'].append('whole-polynomial-package')
        with self.assertRaisesRegex(ValueError, 'seven exact polynomial'):
            parent.validate_policy(changed)


class CompleteProjectInventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name, raw in (('pom.xml', b'<project/>'), ('quic/pom.xml', b'<project/>'),
                          ('microproxy-starlark/pom.xml', b'<project/>'),
                          ('quic/src/main/java/A.java', b'class A {}'),
                          ('quic/src/main/resources/NOTICE', b'notice'),
                          ('quic/target/test-classes/Fixture.class', b'original fixture')):
            put(self.root, name, raw)
        self.before = A.files(self.root)
        self.outputs = {'directories': {
            'quic/target': {'path': 'quic/pom.xml', 'sha256': sha(b'<project/>')},
            'microproxy-starlark/target': {'path': 'microproxy-starlark/pom.xml', 'sha256': sha(b'<project/>')}},
            'files': {}}

    def test_extra_non_quic_source_is_rejected_by_complete_input_inventory(self):
        put(self.root, 'microproxy-starlark/src/main/java/Injected.java', b'class Injected {}')
        with self.assertRaisesRegex(A.EpochError, 'input.*inventory'):
            E.source_inventory_unchanged(self.root, self.before)

    def test_selected_target_outputs_are_separate_from_unchanged_inputs(self):
        put(self.root, 'quic/target/classes/A.class', b'class bytes')
        put(self.root, 'microproxy-starlark/target/bundle.jar', b'jar bytes')
        maps = E.source_inventory_unchanged(self.root, self.before, self.outputs)
        self.assertEqual(self.before, maps['inputs'])
        self.assertEqual({'quic/target/classes/A.class': sha(b'class bytes'),
                          'microproxy-starlark/target/bundle.jar': sha(b'jar bytes')}, maps['outputs'])
        self.assertEqual(A.files(self.root), {**maps['inputs'], **maps['outputs']})

    def test_extra_build_extension_and_tool_inputs_cannot_hide(self):
        for name in ('.mvn/extensions.xml', 'formal/source/new-tool.py', 'microproxy-starlark/src/main/extra'):
            put(self.root, name, b'not a selected input')
            with self.subTest(name=name), self.assertRaisesRegex(A.EpochError, 'input.*inventory'):
                E.source_inventory_unchanged(self.root, self.before, self.outputs)
            (self.root / name).unlink()

    def test_preexisting_input_under_declared_target_is_still_immutable(self):
        put(self.root, 'quic/target/test-classes/Fixture.class', b'changed fixture')
        with self.assertRaisesRegex(A.EpochError, 'input.*inventory'):
            E.source_inventory_unchanged(self.root, self.before, self.outputs)

    def test_broad_output_directories_and_changed_pom_authority_reject(self):
        for name in ('quic', 'quic/src', '.mvn', 'unselected/target'):
            outputs = {'directories': {name: self.outputs['directories']['quic/target']}, 'files': {}}
            with self.subTest(name=name), self.assertRaisesRegex(A.EpochError, 'build.output'):
                E.source_inventory_unchanged(self.root, self.before, outputs)
        outputs = copy.deepcopy(self.outputs)
        outputs['directories']['quic/target']['sha256'] = sha(b'changed pom')
        with self.assertRaisesRegex(A.EpochError, 'build.output'):
            E.source_inventory_unchanged(self.root, self.before, outputs)

    def test_flattened_pom_is_allowed_only_as_an_individually_selected_file(self):
        name = 'microproxy-starlark/.flattened-pom.xml'
        put(self.root, name, b'<flattened/>')
        with self.assertRaisesRegex(A.EpochError, 'input.*inventory'):
            E.source_inventory_unchanged(self.root, self.before, self.outputs)
        self.outputs['files'][name] = {'path': 'microproxy-starlark/pom.xml', 'sha256': sha(b'<project/>')}
        result = E.source_inventory_unchanged(self.root, self.before, self.outputs)
        self.assertEqual({name: sha(b'<flattened/>')}, result['outputs'])


class PrivateMavenOperands(unittest.TestCase):
    def test_online_and_offline_commands_bind_private_repository_and_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for offline in (False, True):
                home = root / ('offline' if offline else 'online')
                home.mkdir()
                argv = list(map(str, E.private_maven_command(root / 'maven', home, offline=offline)))
                self.assertEqual(offline, '-o' in argv)
                self.assertIn('-Dmaven.repo.local=' + str(home / '.m2/repository'), argv)
                self.assertEqual(str(home / '.m2/settings.xml'), argv[argv.index('--settings') + 1])
                self.assertEqual(str(home / '.m2/settings.xml'), argv[argv.index('--global-settings') + 1])
                settings = (home / '.m2/settings.xml').read_text()
                self.assertIn('https://repo.maven.apache.org/maven2', settings)
                self.assertIn('<mirrorOf>*</mirrorOf>', settings)
                self.assertEqual(['-pl', 'microproxy-starlark', '-am', '-DskipTests', 'package'], argv[-5:])


if __name__ == '__main__':
    unittest.main()

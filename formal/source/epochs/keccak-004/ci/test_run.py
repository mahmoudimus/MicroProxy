import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).absolute().parent


def load(path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


class CurrentGate(unittest.TestCase):
    def setUp(self):
        self.ci = load(HERE / 'run.py', 'ci_gate')
        self.parent = load(HERE.parent / 'parent/parent.py', 'parent_gate')

    def selection(self):
        return {'schema': self.ci.SCHEMA, 'scope': self.ci.SCOPE,
                **self.ci.FIXED, 'retained_index_sha256': 'a' * 64,
                'current_checkout_sha256': 'b' * 64}

    def test_selection_is_external_and_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'selection.json'
            value = self.selection()
            path.write_text(json.dumps(value))
            self.assertEqual(self.ci.selection(path, hashlib.sha256(path.read_bytes()).hexdigest()), value)
            with self.assertRaises(ValueError):
                self.ci.selection(path, '0' * 64)
            for field in ['parent_sha256', 'capsule_sha256', 'scope']:
                bad = {**value, field: 'changed'}
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    self.ci.selection(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_unchanged_selected_file_accepts_stale_access_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'selected-input.json'
            raw = b'{"selected":"unchanged"}\n'
            path.write_bytes(raw)
            os.utime(path, ns=(0, path.stat().st_mtime_ns))
            before = path.stat()
            self.assertEqual(before.st_atime_ns, 0)
            self.assertEqual(self.ci.captured(path, hashlib.sha256(raw).hexdigest()), raw)
            after = path.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
                              before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                             (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
                              after.st_size, after.st_mtime_ns, after.st_ctime_ns))

    def test_missing_or_stale_parent_qualification_rejects(self):
        retained = {'status': 'selected-current-epoch-validated', 'artifact_API_called': True,
                    'complete_before_after_maps_match': True, 'policy_sha256': self.ci.FIXED['policy_sha256'],
                    'current': {name: {'complete': True} for name in self.ci.COMPONENTS}}
        cold = {**retained, 'status': 'current-prerequisites-validated', 'artifact_API_called': False}
        self.ci.parent_completion(cold, retained)
        for field, value in [('status', 'current-prerequisites-validated'), ('artifact_API_called', False),
                             ('complete_before_after_maps_match', False)]:
            bad = {**retained, field: value}
            with self.assertRaises(ValueError):
                self.ci.parent_completion(cold, bad)
        for name in self.ci.COMPONENTS:
            bad = copy.deepcopy(cold)
            del bad['current'][name]
            with self.assertRaises(ValueError):
                self.ci.parent_completion(bad, retained)

    def checkout(self, root):
        sources = {}
        for folder, count, suffix in [('quic/src/main/java', 269, '.java'),
                                      ('quic/src/main/resources', 3, '.txt'),
                                      ('quic/target/test-classes', 189, '.class'), ('other', 6, '.txt')]:
            for i in range(count):
                name = folder + '/Fixture' + str(i) + suffix
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
                sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        classes = root / 'fresh-classes'
        classes.mkdir()
        mapping = {}
        for i in range(468):
            name = 'io/github/mahmoudimus/F' + str(i) + '.class'
            path = classes / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            mapping[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for n in range(3):
            name = 'Fixture' + str(n) + '.txt'
            (classes / name).write_bytes((root / 'quic/src/main/resources' / name).read_bytes())
        return {'source_files': sources, 'class_files': mapping}, classes

    def test_actual_sources_classes_and_full_inventory_must_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            sealed, classes = self.checkout(root)
            self.ci.checkout_identity(self.parent, root, classes, sealed)
            for path in [root / 'quic/src/main/java/Fixture0.java', classes / 'io/github/mahmoudimus/F0.class']:
                raw = path.read_bytes()
                path.write_bytes(raw + b'changed')
                with self.assertRaises(ValueError):
                    self.ci.checkout_identity(self.parent, root, classes, sealed)
                path.write_bytes(raw)
            for folder in ['quic/src/main/java', 'quic/src/main/resources', 'quic/target/test-classes', 'fresh-classes']:
                extra = root / folder / 'UNSELECTED.class'
                extra.write_text('extra')
                with self.assertRaises(ValueError):
                    self.ci.checkout_identity(self.parent, root, classes, sealed)
                extra.unlink()

    def test_coherent_local_manifest_rewrite_does_not_change_external_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'current-checkout.json'
            original = {'source_files': {'Adapter.java': 'a' * 64}}
            path.write_text(json.dumps(original))
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_text(json.dumps({'source_files': {'Adapter.java': 'b' * 64}}))
            with self.assertRaises(ValueError):
                self.parent.read_json(path, expected)

    def retained_fixture(self, root):
        reports = {n: {} for n in ['api.json', 'delivery.json', 'bundle.json', 'current-checkout.json']}
        reports['report.json'] = {'status': 'current-prerequisites-validated', 'artifact_API_called': False,
                                 'complete_before_after_maps_match': True,
                                 'policy_sha256': self.ci.FIXED['policy_sha256'], 'current': {'all8': True}}
        for name, value in reports.items():
            (root / name).write_text(json.dumps(value))
        pins = {n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in reports}
        index = {'schema': 'microproxy.keccak004-retained-qualification/1', 'scope': 'retained-Darwin-arm64',
                 'files': pins, 'parent_report': 'report.json', 'api_report': 'api.json',
                 'delivery_receipt': 'delivery.json', 'bundle_receipt': 'bundle.json',
                 'current_checkout': 'current-checkout.json'}
        (root / 'index.json').write_text(json.dumps(index))
        selected = {**self.selection(), 'retained_index_sha256': hashlib.sha256((root / 'index.json').read_bytes()).hexdigest(),
                    'current_checkout_sha256': pins['current-checkout.json']}
        cold = {**reports['report.json']}
        return index, selected, cold

    def test_retained_data_requires_actual_parent_api_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            _, selected, cold = self.retained_fixture(root)
            with self.assertRaisesRegex(ValueError, 'retained parent qualification incomplete'):
                self.ci.retained_data(self.parent, {}, selected, root, root, root, cold)

    def test_coherent_retained_index_rewrite_cannot_self_authorize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            index, selected, cold = self.retained_fixture(root)
            parent = json.loads((root / 'report.json').read_bytes())
            parent.update(status='selected-current-epoch-validated', artifact_API_called=True)
            (root / 'report.json').write_text(json.dumps(parent))
            index['files']['report.json'] = hashlib.sha256((root / 'report.json').read_bytes()).hexdigest()
            (root / 'index.json').write_text(json.dumps(index))
            with self.assertRaisesRegex(ValueError, 'external input authority mismatch'):
                self.ci.retained_data(self.parent, {}, selected, root, root, root, cold)

    def test_retained_report_paths_cannot_escape_data_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            index, selected, cold = self.retained_fixture(root)
            index['parent_report'] = '../outside.json'
            (root / 'index.json').write_text(json.dumps(index))
            selected['retained_index_sha256'] = hashlib.sha256((root / 'index.json').read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'unsafe relative path'):
                self.ci.retained_data(self.parent, {}, selected, root, root, root, cold)

    def test_prepare_constructs_from_actual_checkout_and_capsule_fixtures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository, selected_dir, output = root / 'actual-checkout', root / 'selection', root / 'prepared'
            repository.mkdir()
            selected_dir.mkdir()
            selected_path = selected_dir / 'selection.json'
            selected_path.write_text(json.dumps(self.selection()))
            expected = hashlib.sha256(selected_path.read_bytes()).hexdigest()
            args = types.SimpleNamespace(repository=repository, selection=selected_path,
                                         expected_selection_sha256=expected, output=output)
            p = self.parent
            def extract(archive, archive_sha, capsule_sha, target):
                target.mkdir()
                (target / 'fixtures').mkdir()
                return {'status': 'complete'}
            def construct(policy, repo, target, fixtures, selected_root):
                self.assertEqual(repo, repository)
                self.assertEqual(selected_root, repository)
                self.assertEqual(fixtures, output / 'capsule/fixtures')
                target.mkdir()
                (target / 'receipt.json').write_text('{}')
                return {'baf_files': {'baf': 'a' * 64}, 'epoch_files': {'epoch': 'b' * 64}}
            with mock.patch.object(self.ci, 'authorities', return_value=(p, {}, self.selection(), repository)), \
                 mock.patch.object(self.ci, 'module', return_value=types.SimpleNamespace(extract_capsule=extract)), \
                 mock.patch.object(p, 'admit_capsule'), mock.patch.object(p, 'construct', side_effect=construct), \
                 mock.patch.object(p, 'check_pins'):
                result = self.ci.prepare(args)
            self.assertEqual(result['historical_root'], str(output / 'views/baf-project'))
            self.assertEqual(result['epoch_project'], str(output / 'views/epoch-project'))
            self.assertEqual(result['prepared_receipt_sha256'], hashlib.sha256((output / 'receipt.json').read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()

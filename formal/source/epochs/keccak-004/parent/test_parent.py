import copy
import types
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).absolute().parent


def load():
    module = types.ModuleType('epoch_parent')
    module.__file__ = str(HERE / 'parent.py')
    exec(compile((HERE / 'parent.py').read_bytes(), module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.p = load()

    def test_policy_cannot_omit_or_reuse_current_requirements(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        self.p.validate_policy(policy)
        for key in self.p.REPLACEMENTS:
            bad = copy.deepcopy(policy)
            del bad['replacements'][key]
            with self.assertRaises(self.p.ParentError):
                self.p.validate_policy(bad)
        for key in ['V4', 'V5/V6', 'Select', 'ownership/API', 'Keccak']:
            bad = copy.deepcopy(policy)
            bad['replacements'][key] = 'historical-supported'
            with self.assertRaises(self.p.ParentError):
                self.p.validate_policy(bad)

    def test_no_whole_polynomial_or_global_promotion(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        for value in ['whole-polynomial-package', 'old-mlkem-composition', 'erasure-linkage']:
            bad = copy.deepcopy(policy)
            bad['reuse'].append(value)
            with self.assertRaises(self.p.ParentError):
                self.p.validate_policy(bad)
        bad = copy.deepcopy(policy)
        bad['outstanding'] = []
        with self.assertRaises(self.p.ParentError):
            self.p.validate_policy(bad)

    def test_external_authority_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d).resolve() / 'input.json'
            path.write_text('{"status":"complete","status":"supported"}')
            with self.assertRaises(self.p.ParentError):
                self.p.read_json(path, self.p.digest(path.read_bytes()))
            path.write_text('{}')
            with self.assertRaises(self.p.ParentError):
                self.p.read_json(path, '0' * 64)

    def test_raw_log_change_missing_extra_and_hardlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            path = root / 'proof.log'
            path.write_text('Dafny program verifier finished with 2 verified, 0 errors\n')
            pins = {'proof.log': self.p.digest(path.read_bytes())}
            self.p.check_tree(root, pins)
            path.write_text('Dafny program verifier finished with 2 verified, 1 error\n')
            with self.assertRaises(self.p.ParentError):
                self.p.check_tree(root, pins)
            path.unlink()
            with self.assertRaises(self.p.ParentError):
                self.p.check_tree(root, pins)
            path.write_text('x')
            (root / 'extra').write_text('x')
            with self.assertRaises(self.p.ParentError):
                self.p.check_tree(root, {'proof.log': self.p.digest(b'x')})
            (root / 'extra').unlink()
            (root / 'alias').hardlink_to(path)
            with self.assertRaises(self.p.ParentError):
                self.p.file_bytes(path)

    def test_safe_output_and_closed_environment(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            source = root / 'source'
            source.mkdir()
            for output in [source / 'inside', source, root]:
                with self.assertRaises(self.p.ParentError):
                    self.p.output_admission(output, [source])
            env = self.p.child_environment(root / 'child')
            self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL', 'TZ', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'PYTHONDONTWRITEBYTECODE'})
            self.assertNotIn('PYTHONPATH', env)

    def test_recorded_parser_graph_rejects_omitted_dependency(self):
        banner = "Warning: this way of using the CLI is deprecated. Use 'dafny --help' to see help for the new Dafny CLI format"
        command = {'argv': ['/dafny', '/printIncludes:Immediate', '/noResolve', '/recorded/formal/Entry.dfy'], 'cwd': '/recorded', 'exit': 0}
        text = banner + '\n/recorded/formal/Entry.dfy;/recorded/formal/Hidden.dfy\n'
        self.assertEqual(self.p.parser_edges(command, text), {'formal/Entry.dfy', 'formal/Hidden.dfy'})
        with self.assertRaises(self.p.ParentError):
            self.p.replay_parser([command], [text], {'formal/Entry.dfy': 'a' * 64}, 'formal/Entry.dfy')

    def test_proof_controls_require_normal_intended_failure(self):
        row = {'kind': 'proof', 'counts': [2, 1], 'errors': [{'file': 'A.dfy', 'line': 3, 'column': 4, 'message': 'assertion might not hold'}]}
        text = 'A.dfy(3,4): Error: assertion might not hold\nDafny program verifier finished with 2 verified, 1 error\n'
        self.p.classify_log(row, 4, text)
        for status, body in [(-11, text), (0, text), (4, text + '\nTimed out')]:
            with self.assertRaises(self.p.ParentError):
                self.p.classify_log(row, status, body)

    def test_explicit_summary_units_and_mixed_summary_rejection(self):
        ordinary = 'Dafny program verifier finished with 11 verified, 0 errors\n'
        assertions = 'Dafny program verifier finished with 11 assertions verified, 0 errors\n'
        normal_rule = {'kind': 'proof', 'counts': [11, 0]}
        assertion_rule = {**normal_rule, 'unit': 'assertions '}
        self.p.classify_log(normal_rule, 0, ordinary)
        self.p.classify_log(assertion_rule, 0, assertions)
        for rule, text in [(normal_rule, assertions), (assertion_rule, ordinary),
                           (normal_rule, ordinary + assertions), (assertion_rule, assertions + ordinary)]:
            with self.assertRaises(self.p.ParentError):
                self.p.classify_log(rule, 0, text)

    def test_complete_git_inventory_is_recomputed(self):
        raw = b'hello\n'
        import hashlib
        blob = hashlib.sha1(b'blob 6\0' + raw).hexdigest()
        tree_raw = b'100644 hello.txt\0' + bytes.fromhex(blob)
        expected = hashlib.sha1(b'tree ' + str(len(tree_raw)).encode() + b'\0' + tree_raw).hexdigest()
        inventory = {'hello.txt': {'mode': '100644', 'git_blob': blob}}
        self.assertEqual(self.p.git_tree_identity(inventory), expected)
        inventory['hello.txt']['mode'] = '100755'
        self.assertNotEqual(self.p.git_tree_identity(inventory), expected)
        self.assertNotEqual(self.p.git_tree_identity({}), expected)

    def test_exact_root_map_rejects_alias_and_missing_input(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            for n in policy['evidence']:
                (root / n).mkdir()
            pairs = [(n, str(root / n)) for n in policy['evidence']]
            self.p.explicit_roots(pairs, policy)
            for bad in [pairs[:-1], pairs + [pairs[0]], [(n, str(root / 'poly')) for n, _ in pairs]]:
                with self.assertRaises(self.p.ParentError):
                    self.p.explicit_roots(bad, policy)

    def test_unselected_fresh_profile_is_rejected(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        policy['platform_scope']['instance'] = 'fresh-linux'
        with self.assertRaises(self.p.ParentError):
            self.p.validate_policy(policy)

    def test_explicit_junit_and_fixture_authorities_are_mandatory(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        for key in ['junit', 'fixture_classes', 'distribution']:
            bad = copy.deepcopy(policy)
            bad['artifact_prerequisites'][key].pop(next(iter(bad['artifact_prerequisites'][key])))
            with self.assertRaises(self.p.ParentError):
                self.p.validate_policy(bad)

    def test_actual_artifact_api_return_grammar(self):
        result = {'schema': 'microproxy.crypto-current-release-artifact-validation/v1', 'status': 'complete'}
        self.p.accept_artifact_result(result)
        for status in ['passed', 'running', 'incomplete', 'failed']:
            with self.assertRaises(self.p.ParentError):
                self.p.accept_artifact_result({**result, 'status': status})

    def test_qualify_output_inside_artifact_inputs_rejects_before_writes(self):
        for domain in ['stage', 'classes', 'jdk21', 'jdk25', 'junit_root', 'dafny_cache',
                       'library-parent', 'bundle-parent', 'runtime-parent', 'request-parent']:
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args, artifact = self.qualify_arguments(root)
                protected = root / domain
                args.output = protected / 'must-not-be-created'
                before = self.p.files(root)
                with mock.patch.object(self.p, 'admit_capsule', return_value={}), \
                     mock.patch.object(self.p, 'admit_constructed', return_value={}), \
                     mock.patch.object(self.p, 'run', side_effect=self.p.ParentError('worker reached')) as child:
                    try:
                        self.p.dispatch(args, {'evidence': {}})
                    except self.p.ParentError as error:
                        message = str(error)
                    else:
                        self.fail('nested output was accepted')
                    self.assertFalse(args.output.exists(), 'input directory was mutated before rejection')
                    self.assertEqual(self.p.files(root), before)
                    self.assertIn('output overlaps protected input', message)
                    child.assert_not_called()

    def test_qualify_request_authentication_precedes_output_creation(self):
        for failure in ['wrong-hash', 'missing-path', 'missing-jdk']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                args, artifact = self.qualify_arguments(root)
                args.output = root / 'otherwise-safe-output'
                if failure == 'wrong-hash':
                    args.expected_artifact_request_sha256 = '0' * 64
                else:
                    if failure == 'missing-path':
                        del artifact['runtime']
                    else:
                        artifact['java_homes'].pop()
                    args.artifact_request.write_text(json.dumps(artifact))
                    args.expected_artifact_request_sha256 = self.p.digest(args.artifact_request.read_bytes())
                before = self.p.files(root)
                with mock.patch.object(self.p, 'admit_capsule', return_value={}), \
                     mock.patch.object(self.p, 'admit_constructed', return_value={}), \
                     mock.patch.object(self.p, 'run', side_effect=self.p.ParentError('worker reached')) as child:
                    with self.assertRaises(self.p.ParentError):
                        self.p.dispatch(args, {'evidence': {}})
                    self.assertFalse(args.output.exists(), 'output exists before request admission')
                    self.assertEqual(self.p.files(root), before)
                    child.assert_not_called()

    def test_actual_jdk21_authority_preserves_same_byte_symlink_identity(self):
        policy = json.loads((HERE / 'policy.json').read_bytes())
        stage_map = next(row['value'] for row in policy['evidence']['stage']['assertions']
                         if row['path'] == ['jdk_files'])
        self.assertEqual(len(stage_map), 527)
        self.assertEqual(sum(type(v) is dict for v in stage_map.values()), 205)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            homes = [root / 'jdk21', root / 'jdk25']
            for home in homes:
                home.mkdir()
            actual = [copy.deepcopy(stage_map), policy['artifact_prerequisites']['jdk_files'][1]]
            helper = types.SimpleNamespace(tool_tree=lambda home: actual[homes.index(home)])
            expected = self.p.check_artifact_jdks(homes, policy, {'jdk_files': stage_map}, helper)
            self.assertEqual(expected[0], stage_map)
            link = next(n for n, v in actual[0].items() if type(v) is dict)
            old_sha = actual[0][link]['sha256']
            actual[0][link]['link'] = '../same-bytes-other-target/LICENSE'
            actual[0][link]['target'] = str(root / 'same-bytes-other-target/LICENSE')
            self.assertEqual(actual[0][link]['sha256'], old_sha)
            with self.assertRaisesRegex(self.p.ParentError, 'explicit JDK input map changed'):
                self.p.check_artifact_jdks(homes, policy, {'jdk_files': stage_map}, helper)
            inconsistent = copy.deepcopy(stage_map)
            inconsistent[link]['sha256'] = '0' * 64
            with self.assertRaisesRegex(self.p.ParentError, 'stage JDK21 byte pins'):
                self.p.check_artifact_jdks(homes, policy, {'jdk_files': inconsistent}, helper)

    def qualify_arguments(self, root):
        for name in ['stage', 'classes', 'jdk21', 'jdk25', 'junit_root', 'dafny_cache',
                     'library-parent', 'bundle-parent', 'runtime-parent', 'request-parent',
                     'policy-parent', 'views', 'capsule']:
            (root / name).mkdir()
            (root / name / 'sentinel').write_text('preserve this input\n')
        artifact = {name: str(root / name) for name in ['stage', 'classes', 'junit_root', 'dafny_cache']}
        for name in ['library', 'bundle', 'runtime']:
            path = root / (name + '-parent') / (name + '.jar')
            path.write_bytes(b'exact artifact input')
            artifact[name] = str(path)
        artifact['java_homes'] = [str(root / 'jdk21'), str(root / 'jdk25')]
        request = root / 'request-parent/request.json'
        request.write_text(json.dumps(artifact))
        policy = root / 'policy-parent/policy.json'
        policy.write_text('{}')
        return types.SimpleNamespace(views=root / 'views', capsule=root / 'capsule',
            expected_capsule_sha256='0' * 64, expected_views_sha256='0' * 64,
            policy=policy, expected_policy_sha256=self.p.digest(policy.read_bytes()),
            artifact_request=request, expected_artifact_request_sha256=self.p.digest(request.read_bytes())), artifact

    def test_exited_wrapper_cannot_leave_stdout_descendant_alive(self):
        self.check_descendant_cleanup(close_stdout=False)

    def test_normal_completion_cannot_leave_closed_stdout_descendant_alive(self):
        self.check_descendant_cleanup(close_stdout=True)

    def check_descendant_cleanup(self, close_stdout):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            script = root / 'wrapper.py'
            script.write_text('import os,signal,time\n'
                'child=os.fork()\n'
                'if child: os._exit(0)\n'
                'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                'print(os.getpid(),flush=True)\n' +
                ('os.close(1)\nos.close(2)\n' if close_stdout else '') +
                'while True: time.sleep(0.1)\n')
            env = self.p.child_environment(root / 'child-state')
            log = root / 'child.log'
            if close_stdout:
                self.p.run([sys.executable, '-I', '-B', script], cwd=root, env=env, log=log, timeout=2)
            else:
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.p.run([sys.executable, '-I', '-B', script], cwd=root, env=env, log=log, timeout=0.3)
            child = int(log.read_text().strip())
            # An orphan can briefly remain a zombie pending the host's reaper.
            state = subprocess.run(['/bin/ps', '-p', str(child), '-o', 'stat='], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), state)


if __name__ == '__main__':
    unittest.main()

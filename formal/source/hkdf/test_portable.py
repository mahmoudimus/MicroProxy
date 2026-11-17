"""Regression tests for admission/execution/fixtures; unit tests confer no proof credit."""
import copy
import csv
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import types
import unittest
from zipfile import ZipFile
from unittest.mock import patch

from tooling import admission as A, build_support as B, evaluation_validator as V
from tooling import outcome_rules as O, proof_rules as P, owned_call as OWN
from tooling import source_evidence as E
import replay

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


class RawLoading(unittest.TestCase):
    def test_valid_poisoned_pyc_is_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'input.py'
            good = b'value = "GOOD"\n'
            bad = b'value = "EVIL"\n'
            self.assertEqual(len(good), len(bad))
            p.write_bytes(bad)
            st = p.stat()
            py_compile.compile(str(p), doraise=True)
            p.write_bytes(good)
            os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
            # Confirm the poison is a real valid timestamp/size cache, then
            # compare the authenticated raw loader on that identical path.
            spec = importlib.util.spec_from_file_location('unit_poison_control', p)
            normal = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(normal)
            self.assertEqual('EVIL', normal.value)
            loaded = A.load_module('unit_raw_control', p, A.digest(good))
            self.assertEqual('GOOD', loaded.value)

    def test_pin_failure_precedes_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'input.py'
            p.write_text('raise RuntimeError("must not execute")')
            with self.assertRaisesRegex(ValueError, 'source pin mismatch'):
                A.load_module('unit_pin_failure', p, '0' * 64)

    def test_context_and_previous_module_restored_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'input.py'
            p.write_text('assert __file__\nassert __spec__.name == __name__\nraise RuntimeError("unit")')
            previous = types.ModuleType('unit_previous')
            with patch.dict(sys.modules, {'unit_previous': previous}):
                with self.assertRaisesRegex(RuntimeError, 'unit'):
                    A.load_module('unit_previous', p, A.sha(p))
                self.assertIs(previous, sys.modules['unit_previous'])

    def test_child_selectors_and_user_import_path_are_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'PYTHONPATH': '/poison', 'PYTHONHOME': '/poison',
                      'DOTNET_STARTUP_HOOKS': '/poison', 'LD_PRELOAD': '/poison',
                      'DYLD_INSERT_LIBRARIES': '/poison', 'JAVA_TOOL_OPTIONS': '-poison'}):
                env = A.child_environment(Path(tmp).resolve() / 'private')
            self.assertEqual({'home', 'tmp', 'config', 'cache'},
                             {p.name for p in (Path(tmp).resolve() / 'private').iterdir()})
            text = subprocess.check_output([sys.executable, '-I', '-B', '-c',
                'import os,json,sys; print(json.dumps([dict(os.environ),sys.flags.isolated,sys.flags.dont_write_bytecode]))'],
                env=env, text=True)
            actual, isolated, no_pyc = json.loads(text)
            self.assertTrue(isolated and no_pyc)
            self.assertFalse(any(n.startswith(('PYTHON', 'DOTNET', 'LD_', 'DYLD_', 'JAVA_')) for n in actual))
            self.assertEqual(str(Path(tmp).resolve() / 'private/home'), actual['HOME'])

    def test_raw_exit_survives_classifier_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            env = A.child_environment(root / 'child')
            log = root / 'actual.log'
            code, text, record = OWN.run(['/usr/bin/true'], log, root, env, 10)
            with self.assertRaisesRegex(RuntimeError, 'classifier'):
                raise RuntimeError('classifier unit fault')
            raw = json.loads(Path(record['raw_execution_record']).read_text())
            self.assertEqual(0, code)
            self.assertTrue(raw['actual_exit_observed'])
            self.assertEqual(0, raw['returncode'])
            self.assertEqual(A.sha(log), raw['log_sha256'])


class WholeJdkAdmission(unittest.TestCase):
    def test_full_tree_catches_unlisted_files_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'lib').mkdir()
            (root / 'lib/extra-native-library').write_bytes(b'first')
            first = A.tree_snapshot(root)
            self.assertEqual('file', first['lib/extra-native-library'][0])
            (root / 'lib/extra-native-library').write_bytes(b'other')
            self.assertNotEqual(first, A.tree_snapshot(root))
            before_mode = A.tree_snapshot(root)
            (root / 'lib/extra-native-library').chmod(0o700)
            self.assertNotEqual(before_mode, A.tree_snapshot(root))
            (root / 'hidden-config').write_text('new')
            self.assertIn('hidden-config', A.tree_snapshot(root))

    def test_symbolic_files_directories_cycles_and_broken_links_are_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'real').mkdir()
            (root / 'real/file').write_bytes(b'actual')
            (root / 'directory-link').symlink_to('real', target_is_directory=True)
            (root / 'file-link').symlink_to('real/file')
            (root / 'cycle').symlink_to('cycle')
            (root / 'broken').symlink_to('absent')
            data = A.tree_snapshot(root)
            self.assertEqual(['symlink', 'real', None], data['directory-link'])
            self.assertEqual(['symlink', 'real/file', None], data['file-link'])
            self.assertEqual(['symlink', 'cycle', None], data['cycle'])
            self.assertEqual(['symlink', 'absent', None], data['broken'])
            self.assertNotIn('directory-link/file', data)
            self.assertEqual('file', data['real/file'][0])

    def test_external_symlink_special_file_and_symlink_root_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            jdk = root / 'jdk'
            jdk.mkdir()
            (root / 'outside').mkdir()
            link = jdk / 'external'
            link.symlink_to('../outside', target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'escapes selected tree'):
                A.tree_snapshot(jdk)
            link.unlink()
            os.mkfifo(jdk / 'pipe')
            with self.assertRaisesRegex(ValueError, 'special JDK'):
                A.tree_snapshot(jdk)
            (jdk / 'pipe').unlink()
            (root / 'alias').symlink_to(jdk, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink JDK root'):
                A.tree_snapshot(root / 'alias')

    def test_all_input_tool_overlap_directions_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            for label in ('repository', 'manifest', 'dafny', 'dotnet', 'jdk21', 'jdk25',
                          'runtime', 'targeting-packs', 'python-prefix', 'python-executable'):
                protected = base / label
                protected.mkdir()
                with self.subTest(root=label, direction='below'):
                    self.assertIn(label, A.output_isolation_error(protected / 'new-output', {label: protected}))
                    self.assertFalse((protected / 'new-output').exists())
                with self.subTest(root=label, direction='above'):
                    self.assertIn(label, A.output_isolation_error(base, {label: protected}))
            self.assertIsNone(A.output_isolation_error(base / 'fresh', {'input': base / 'input'}))

    def test_overlap_fails_before_import_or_any_directory_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / 'new-output'
            args = types.SimpleNamespace(output=output, manifest=root / 'repo/manifest.json',
                dafny=output / 'dafny/dafny', dotnet=root / 'dotnet/dotnet',
                jdk21=root / 'jdk21', jdk25=root / 'jdk25', runtime=root / 'runtime/runtime.jar',
                targeting_packs=root / 'packs', jar=None)
            with patch.object(A, 'load_module') as load:
                with self.assertRaisesRegex(ValueError, 'overlaps.*dafny'):
                    replay.Replay(args, root / 'repo', {'inputs': {}}, A)
                load.assert_not_called()
            self.assertFalse(output.exists())


class CurrentControls(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((HERE / 'controls/v2.json').read_text())

    def test_all_exact_reviewed_recipes_reconstruct(self):
        rows = self.plan['coverage']
        self.assertEqual(115, len(rows))
        self.assertEqual(115, len({r['name'] for r in rows}))
        self.assertEqual(112, sum(r['kind'] == 'negative' for r in rows))
        self.assertEqual(5, len(self.plan['body']))
        for row in rows + self.plan['body']:
            for name, recipe in row['files'].items():
                with self.subTest(case=row['name'], file=name):
                    result = A.apply_recipe((REPO / recipe['base']).read_text(), recipe)
                    self.assertEqual(recipe['sha256'], A.digest(result.encode()))
        self.assertIn('return-exact-reviewed', {r['name'] for r in rows})

    def test_recipe_wrong_source_or_edit_is_rejected(self):
        recipe = self.plan['coverage'][0]['files']['Hkdf.dfy']
        base = (REPO / recipe['base']).read_text()
        with self.assertRaisesRegex(ValueError, 'base drift'):
            A.apply_recipe(base + '\n', recipe)
        broken = copy.deepcopy(recipe)
        broken['edits'][0]['old'].append('wrong\n')
        with self.assertRaisesRegex(ValueError, 'wrong mutation'):
            A.apply_recipe(base, broken)

    def test_named_plugin_message_must_be_real_and_plain_resolve_green(self):
        error = 'Hkdf.dfy(10,3): Error: HKDF_RETURN bare return required\n'
        footer = '1 resolution/type errors detected in Hkdf.dfy\n'
        self.assertTrue(O.named_rejection(0, '', 2, error + footer, 'HKDF_RETURN'))
        for ordinary, plugin in ((2, error), (0, '| // Error: HKDF_RETURN\n' + footer),
                (0, 'Hkdf.dfy(1,1): Error: missing required HKDF source-trace root\n' + error),
                (0, 'CLI: Error: HKDF_RETURN'), (0, 'parse error\n' + error)):
            self.assertFalse(O.named_rejection(ordinary, '', 2, plugin, 'HKDF_RETURN'))

    def test_source_substitution_and_omitted_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp).resolve()
            component = repo / 'formal/source/hkdf'
            component.mkdir(parents=True)
            source = component / 'test.py'
            source.write_text('x=1\n')
            data = {'schema': 'microproxy.hkdf-source-traces-inputs/v2',
                    'inputs': {'formal/source/hkdf/test.py': A.sha(source)}}
            manifest = component / 'inputs-v2.json'
            manifest.write_text(json.dumps(data))
            pin = A.sha(manifest)
            A.authenticate(repo, manifest, pin)
            source.write_text('x=2\n')
            with self.assertRaisesRegex(ValueError, 'input mismatch'):
                A.authenticate(repo, manifest, pin)
            source.write_text('x=1\n')
            # Exactly the independent output receipt is outside the input map.
            (component / 'SOURCE-EVIDENCE-v2.json').write_text('{"status":"unit-data"}')
            A.authenticate(repo, manifest, pin)
            for rel in ('work/omitted-control.py', 'checker/obj/Injected.cs', '__pycache__/hidden.py'):
                hidden = component / rel
                hidden.parent.mkdir(parents=True, exist_ok=True)
                hidden.write_text('unauthenticated source')
                with self.subTest(path=rel), self.assertRaisesRegex(ValueError, 'package input map'):
                    A.authenticate(repo, manifest, pin)
                hidden.unlink()
            (component / 'omitted-control.py').write_text('x=3\n')
            with self.assertRaisesRegex(ValueError, 'package input map'):
                A.authenticate(repo, manifest, pin)

    def test_original_functional_controls_and_all_eight_unrestricted_calls_remain(self):
        p = REPO / 'formal/dafny/run.py'
        functional = A.load_module('unit_current_functional_cases', p, A.sha(p))
        base = (REPO / replay.KERNEL).read_text()
        mutations = functional.mutations(base)
        self.assertEqual({'counter', 'feedback', 'truncation', 'prefix', 'public-domain'}, set(mutations))
        self.assertIn('requires false', mutations['public-domain'])
        domain = functional.domain_harness(Path('Hkdf.dfy'))
        self.assertNotIn('requires', domain)
        self.assertNotIn('disjoint', domain)
        for name in ('Extract', 'Expand', 'LabelInfo', 'ExpandLabel', 'CopyInput',
                     'ExtractArrays', 'ExpandArrays', 'LabelInfoArray'):
            self.assertEqual(1, domain.count('VerifiedHkdf.' + name + '('))

    def test_functional_cli_forwards_only_to_isolated_current_engine(self):
        p = REPO / 'formal/dafny/run.py'
        functional = A.load_module('unit_current_functional_cli', p, A.sha(p))
        with patch.object(functional.os, 'execve') as execute:
            functional.main(['--manifest', '/selected.json', '--expected-manifest', '1' * 64])
        executable, argv, env = execute.call_args.args
        self.assertEqual(['-I', '-B'], argv[1:3])
        self.assertEqual(str(REPO / 'formal/source/hkdf/run.py'), argv[3])
        self.assertEqual({'PATH', 'LANG', 'LC_ALL', 'TZ'}, set(env))

    def test_current_jar_check_rejects_missing_changed_or_duplicate_entries(self):
        instance = object.__new__(replay.Replay)
        instance.a, instance.sha = A, A.sha
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / 'artifact.jar'
            with ZipFile(p, 'w') as jar:
                jar.writestr('a/B.class', b'actual')
            expected = {'a/B.class': A.digest(b'actual')}
            self.assertEqual(1, instance.check_jar(p, expected)['matched_entries'])
            for changed in ({'a/C.class': '0' * 64}, {'a/B.class': '0' * 64}):
                with self.assertRaisesRegex(ValueError, 'missing/changed'):
                    instance.check_jar(p, changed)
            with ZipFile(p, 'w') as jar:
                jar.writestr('a/B.class', b'actual')
                with self.assertWarns(UserWarning):
                    jar.writestr('a/B.class', b'actual')
            with self.assertRaisesRegex(ValueError, 'duplicate JAR'):
                instance.check_jar(p, expected)

    def test_current_generation_utility_loads_selected_owner_without_running_child(self):
        path = REPO / 'formal/dafny/run.py'
        functional = A.load_module('unit_generation_owner_binding', path, A.sha(path))
        load = functional.raw_module
        executed = []

        def captured_owner(name, source, expected):
            owner = load(name, source, expected)  # Real current source pin check.

            def mocked_run(*args):
                executed.append(args)
                return 0, 'UNIT-ONLY: no child executed', {'unit_only': True, 'actual_child_executed': False}

            owner.run = mocked_run
            return owner

        with tempfile.TemporaryDirectory() as tmp, patch.object(functional, 'raw_module', side_effect=captured_owner):
            log = Path(tmp).resolve() / 'unit.log'
            error = None
            try:
                code, text = functional.owned_execute(['unit-only-never-executed'], log)
            except RuntimeError as failure:
                error = str(failure)
            self.assertIsNone(error, error)
            self.assertEqual(1, len(executed))
            self.assertEqual((0, 'UNIT-ONLY: no child executed'), (code, text))
            record = json.loads(log.with_suffix('.record.json').read_text())
            self.assertTrue(record['unit_only'])
            self.assertFalse(record['actual_child_executed'])


def csv_rows(names, outcomes=None):
    stream = io.StringIO()
    w = csv.writer(stream)
    w.writerow(P.HEADER)
    for name, outcome in zip(names, outcomes or ['Passed'] * len(names)):
        w.writerow([name, outcome, '0.01', '100', '0'])
    return stream.getvalue()


class ProofCSV(unittest.TestCase):
    def test_real_schema_function_wf_and_complete_method_family(self):
        raw = csv_rows(['VerifiedHkdf.EvBranchIf (well-formedness)',
                        'VerifiedHkdf.CopyInput (correctness) (assertion batch 1)',
                        'VerifiedHkdf.CopyInput (correctness) (assertion batch 2)'])
        result = P.positive(0, 'Dafny program verifier finished with 3 verified, 0 errors', raw,
                            'VerifiedHkdf.', ['VerifiedHkdf.CopyInput'], 'VerifiedHkdf.EvBranchIf')
        self.assertEqual(3, result['rows'])

    def test_duplicates_gaps_skips_and_wrong_targets_get_no_credit(self):
        cases = [csv_rows([]), csv_rows(['X (correctness)'] * 2),
                 csv_rows(['X (correctness) (assertion batch 2)']),
                 csv_rows(['X (correctness)'], ['OutOfResource']),
                 csv_rows(['X (correctness)', 'X (correctness) (assertion batch 1)'])]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                P.rows(raw)
        with self.assertRaises(ValueError):
            P.positive(0, 'Dafny program verifier finished with 1 verified, 0 errors',
                       csv_rows(['Other.CopyInput (correctness)']), 'VerifiedHkdf.')

    def test_trace_only_failure_cannot_replace_required_functional_failure(self):
        raw = csv_rows(['VerifiedHkdf.ExtractArrays (correctness)',
                        'VerifiedHkdf.ExtractArrays (well-formedness)'], ['Failed', 'Passed'])
        log = ('Hkdf.dfy(830,3): Error: a postcondition could not be proved on this return path\n'
               'Hkdf.dfy(813,5): Related location: this is the postcondition that could not be proved\n'
               'Dafny program verifier finished with 1 verified, 1 error')
        with self.assertRaises(ValueError):
            P.negative(4, log, raw, 'VerifiedHkdf.ExtractArrays', 'postcondition', 809, 813)


class SkippedProofFixture(unittest.TestCase):
    # Exact diagnostic text retained from FULL005, whose strict resolve exit2
    # is preserved as incomplete evidence rather than credited as a control.
    warning = ('/frozen/controls/functional/skipped-proof/Hkdf.dfy(586,25): Warning: '
               + replay.SKIPPED_PROOF_WARNING + '\n')

    def test_exact_warning_requires_successful_frontend_exit(self):
        replay.skipped_proof_diagnostics(0, self.warning)
        with self.assertRaisesRegex(ValueError, 'skipped-proof fixture diagnostics'):
            replay.skipped_proof_diagnostics(2, self.warning)

    def test_no_unrelated_warning_source_excerpt_or_failure_is_accepted(self):
        cases = ['', self.warning * 2, '| ' + self.warning,
                 self.warning + '/other.dfy(1,1): Warning: unexpected\n',
                 self.warning + '/other.dfy(1,1): Error: assertion might not hold\n',
                 self.warning.replace('586,25', 'line,column'),
                 self.warning + 'out of resource\n']
        for text in cases:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'skipped-proof fixture diagnostics'):
                replay.skipped_proof_diagnostics(0, text)

    def test_ordinary_inputs_still_reject_even_the_expected_warning(self):
        instance = object.__new__(replay.Replay)
        instance.dafny = Path('/tools/dafny')
        instance.outcomes = O
        instance.call = lambda *args: (0, self.warning)
        with self.assertRaisesRegex(ValueError, 'ordinary resolve failed'):
            instance.ordinary('ordinary-source-0', Path('/frozen/Hkdf.dfy'))

    def test_actual_audit_findings_are_exact_and_source_excerpts_do_not_count(self):
        mac = ('/frozen/Hkdf.dfy(484,4): Warning: Mac: Declaration has explicit '
               '`{:axiom}` attribute. Possible mitigation: Provide a proof or test.\n')
        skip = ('/frozen/Hkdf.dfy(586,25): Warning: Extract: Declaration has `{:verify false}` '
                'attribute. Possible mitigation: Remove `{:verify false}` attribute and prove if possible.\n')
        summary = 'Dafny auditor completed with 2 findings\n\nDafny program verifier did not attempt verification\n'
        actual = self.warning + mac + skip + summary
        replay.audit_control_diagnostics('skipped-proof', 0, actual)
        extra = mac.replace('Mac:', 'ExtraAssumption:') + mac + summary
        replay.audit_control_diagnostics('extra-assumption', 0, extra)
        for text in (actual + mac, actual.replace('Extract:', 'Other:'),
                     actual.replace(skip, '| ' + skip), actual.replace(self.warning, ''),
                     actual + '/other.dfy(1,1): Warning: unrelated\n',
                     actual.replace('2 findings', '1 findings')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'nonvacuity audit diagnostics'):
                replay.audit_control_diagnostics('skipped-proof', 0, text)
        with self.assertRaisesRegex(ValueError, 'nonvacuity audit diagnostics'):
            replay.audit_control_diagnostics('skipped-proof', 1, actual)


class ReceiptExport(unittest.TestCase):
    def test_preflight_never_becomes_a_full_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'report.json').write_text(json.dumps({'status': 'complete bounded preflight', 'phase': 'preflight'}))
            with self.assertRaisesRegex(ValueError, 'not a completed full replay'):
                E.project(root)

    def test_full_tree_is_not_inferred_from_five_profile_operands(self):
        # This is data admission only: an otherwise plausible old-scope record
        # cannot be relabeled as the current full-tree authority.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sources = {name: A.digest(b'unit-source') for name in E.SOURCES}
            for name in sources:
                p = root / 'frozen' / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'unit-source')
            for name in ('TOOLS-BEFORE.json', 'TOOLS-AFTER.json'):
                (root / name).write_text('{}')
            r = {'status': 'complete bounded full', 'phase': 'full', 'qualification': False,
                 'tools_after_equal': True, 'inputs_before': sources, 'inputs_after': sources,
                 'frozen_inputs_after': sources, 'official_parser_closure': sources,
                 'manifest_sha256': '0' * 64, 'manifest_after_sha256': '0' * 64,
                 'tools_before': {'sha256': A.sha(root / 'TOOLS-BEFORE.json')},
                 'tools_after': {'sha256': A.sha(root / 'TOOLS-AFTER.json')}}
            (root / 'report.json').write_text(json.dumps(r))
            with self.assertRaisesRegex(ValueError, 'old five-operand evidence cannot be relabeled'):
                E.project(root)


class EvaluationClosure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.package = self.root / 'package'
        self.package.mkdir()
        self.authority = types.SimpleNamespace(root=self.root / 'authority',
            immutable_before={'packs': {}}, properties=lambda: {'UseSharedCompilation': 'false'})
        authored = self.package / 'HkdfCoverage.cs'
        authored.write_text('// unit fixture')
        ref = self.root / 'reference.dll'
        ref.write_bytes(b'unit-reference')
        self.tools = {str(ref): A.sha(ref)}
        self.data = {'Properties': {'UseSharedCompilation': 'false', 'MSBuildAllProjects': ''},
                     'Items': {'ReferencePath': [{'Identity': str(ref)}], 'Compile': [{'Identity': str(authored)}]}}
        for name in ('HkdfCoverage.AssemblyInfo.cs', 'HkdfCoverage.GlobalUsings.g.cs',
                     '.NETCoreApp,Version=v6.0.AssemblyAttributes.cs'):
            p = self.package / 'obj' / name
            p.parent.mkdir(exist_ok=True)
            p.write_text('// generated unit fixture')
            self.data['Items']['Compile'].append({'Identity': str(p)})

    def check(self, data):
        return V.validate_evaluation(self.authority, json.dumps(data), self.package, self.package,
                                     'HkdfCoverage', self.tools)

    def test_one_authored_plus_three_generated_exact_closure(self):
        self.assertEqual(4, len(self.check(self.data)['compile_inputs']))

    def test_source_and_nonsource_policy_mutations_are_rejected(self):
        mutations = [
            lambda d: d['Items']['Compile'].pop(0),
            lambda d: d['Items']['Compile'].append({'Identity': str(self.package / 'NativeCanonicalEncoderPolicy.cs')}),
            lambda d: d['Items']['Compile'][0].update(Identity=str(self.package / 'Other.cs')),
            lambda d: d['Items']['Compile'].append({'Identity': str(self.package / 'obj/Other.g.cs')}),
            lambda d: d['Properties'].update(UseSharedCompilation='true'),
            lambda d: d['Items']['ReferencePath'].append({'Identity': '/unknown/native.dll'}),
            lambda d: d['Properties'].update(MSBuildAllProjects='/unknown/hook.targets'),
            lambda d: d['Items'].update(EditorConfigFiles=[{'Identity': '/unknown/config.editorconfig'}]),
            lambda d: d['Items'].update(ReferencePath=[]),
        ]
        for mutate in mutations:
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, FileNotFoundError)):
                self.check(data)

    def test_output_scope_rejects_repo_symlink_and_existing_paths(self):
        self.assertIsNotNone(B.output_admission_error(self.package, REPO, REPO))
        self.assertIsNotNone(B.output_admission_error(REPO / 'new', REPO, REPO))
        (self.root / 'link').symlink_to(self.package, target_is_directory=True)
        self.assertIsNotNone(B.output_admission_error(self.root / 'link/new', REPO, REPO))


def _optimization_probe():
    """Child DATA probe; Popen/killpg below are mocked, never real signals."""
    import csv
    import io
    import json
    import os
    from pathlib import Path
    import shutil
    import signal
    import sys
    import types
    from unittest.mock import patch

    source, scratch, case = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]

    def load(name, path):
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        return module

    def table(header, names, outcomes):
        text = io.StringIO()
        writer = csv.writer(text)
        writer.writerow(header)
        for name, outcome in zip(names, outcomes):
            writer.writerow((name, outcome, '0.01', '100', '0'))
        return text.getvalue()

    result, calls = {'accepted': False, 'optimize': sys.flags.optimize}, []
    try:
        if case.startswith(('positive-', 'negative-')):
            rules = load('unit_optimized_rules', source / 'tooling/proof_rules.py')
            if case.startswith('negative-'):
                names = ['Control.Target (correctness)', 'Control.Target (well-formedness)']
                raw = table(rules.HEADER, names, ['Passed', 'Failed'] if case == 'negative-reversed-WF'
                            else ['Failed', 'Passed'])
                rules.negative(4, 'Control.dfy(10,2): Error: assertion might not hold\n'
                    'Dafny program verifier finished with 1 verified, 1 error', raw,
                    'Control.Target', 'assertion', 10)
            else:
                names = ['Control.Target (correctness) (assertion batch ' + str(i) + ')' for i in range(1, 258)]
                outcomes, code = ['Passed'] * 257, 0
                if case == 'positive-timeout': outcomes[0], code = 'TimeOut', 4
                if case == 'positive-wrong-exit': code = 4
                if case == 'positive-failed-correctness': outcomes[0] = 'Failed'
                function = 'Control.Marker' if case in ('positive-failed-WF', 'positive-missing-WF') else None
                if case == 'positive-failed-WF': names[-1], outcomes[-1] = 'Control.Marker (well-formedness)', 'Failed'
                rules.positive(code, 'Dafny program verifier finished with 257 verified, 0 errors',
                    table(rules.HEADER, names, outcomes), 'Control.', ['Control.Target'], function)
            result['accepted'] = True
        else:
            package = scratch / (case + '-' + str(sys.flags.optimize))
            package.mkdir()
            shutil.copyfile(source / 'tooling/owned_call.py', package / 'owned_call.py')
            if case == 'passive-hash-tampered':
                (package / 'passive_drain.py').write_text('UNAUTHENTICATED_BODY_EXECUTED = True\n')
            else:
                shutil.copyfile(source / 'tooling/passive_drain.py', package / 'passive_drain.py')
            owner = load('unit_optimized_owner', package / 'owned_call.py')
            if case == 'passive-hash-tampered':
                result['accepted'] = bool(owner._passive.UNAUTHENTICATED_BODY_EXECUTED)
            elif case == 'signal-foreign-member':
                rows = [{'pid': 4243, 'ppid': 1, 'pgid': 4242, 'uid': os.getuid() + 1, 'comm': 'unit-only'}]
                with patch.object(owner.os, 'killpg', side_effect=lambda *args: calls.append(args)):
                    owner.signal_observed_group(rows, 4242, {4242}, signal.SIGTERM, {})
                result['accepted'] = True
            else:
                process = types.SimpleNamespace(pid=4242, returncode=0, poll=lambda: 0, wait=lambda **kw: 0)
                row = {'pid': 4242, 'ppid': 1, 'pgid': 4242, 'uid': os.getuid(), 'comm': 'unit-only'}
                pgid = 4243 if case == 'launch-group-mismatch' else 4242
                remaining = [] if case == 'launch-group-mismatch' else [row]
                with patch.object(owner.subprocess, 'Popen', return_value=process), \
                     patch.object(owner.os, 'getpgid', return_value=pgid), \
                     patch.object(owner.os, 'killpg', side_effect=lambda *args: calls.append(args)), \
                     patch.object(owner, 'roster', return_value=remaining), \
                     patch.object(owner.time, 'sleep'), \
                     patch.object(owner._passive, 'passive_drain', return_value=(remaining, [])):
                    owner.run(['unit-only-never-executed'], package / 'mocked.log', package, {}, 5)
                result['accepted'] = True
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    result['mocked_signal_calls'] = len(calls)
    print(json.dumps(result))


class OptimizationSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scratch = Path(self.tmp.name).resolve()
        self.probe = self.scratch / 'probe.py'
        self.probe.write_text(inspect.getsource(_optimization_probe) + '\n_optimization_probe()\n')

    def child(self, flags, case):
        actual = subprocess.run([sys.executable, *flags, '-I', '-B', self.probe, HERE, self.scratch, case],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(0, actual.returncode, actual.stderr)
        return json.loads(actual.stdout)

    def test_invalid_csv_outcomes_and_wf_roles_fail_under_O_and_OO(self):
        for flags in ((), ('-O',), ('-OO',)):
            for case in ('positive-valid', 'negative-valid', 'positive-timeout', 'positive-wrong-exit',
                         'positive-failed-correctness', 'positive-failed-WF', 'positive-missing-WF', 'negative-reversed-WF'):
                with self.subTest(flags=flags, case=case):
                    result = self.child(flags, case)
                    self.assertEqual(case in ('positive-valid', 'negative-valid'), result['accepted'])

    def test_hash_ownership_and_signal_guards_survive_optimization_with_mocks(self):
        for flags in ((), ('-O',), ('-OO',)):
            for case in ('passive-hash-tampered', 'signal-foreign-member', 'launch-group-mismatch', 'residual-group-persisted'):
                with self.subTest(flags=flags, case=case):
                    result = self.child(flags, case)
                    self.assertFalse(result['accepted'])
                    if case != 'residual-group-persisted':
                        self.assertEqual(0, result['mocked_signal_calls'])

    def test_direct_entry_rejects_optimization_before_manifest_admission(self):
        for flags in (('-O',), ('-OO',)):
            with self.subTest(flags=flags):
                actual = subprocess.run([sys.executable, *flags, '-I', '-B', HERE / 'run.py',
                    '--manifest', self.scratch / 'ABSENT.json', '--expected-manifest', '0' * 64],
                    capture_output=True, text=True, timeout=20)
                self.assertNotEqual(0, actual.returncode)
                self.assertIn('Python optimization is not supported for HKDF replay', actual.stderr)
                self.assertNotIn('FileNotFoundError', actual.stderr)
                self.assertFalse((self.scratch / 'ABSENT.json').exists())

    def test_projection_requires_all_24_positive_proof_exits_zero(self):
        self.assertEqual(24, len(E.POSITIVE_PROOF_LABELS))
        valid = [{'label': name, 'exit': 0} for name in E.POSITIVE_PROOF_LABELS]
        # Normal negative control exits must remain legal in a full replay.
        E.require_positive_proof_exits(valid + [{'label': 'functional-counter', 'exit': 4}])
        for name in E.POSITIVE_PROOF_LABELS:
            with self.subTest(name=name):
                for changed in ([dict(row, exit=4) if row['label'] == name else row for row in valid],
                                [row for row in valid if row['label'] != name]):
                    with self.assertRaisesRegex(ValueError, 'required positive proof command did not exit zero'):
                        E.require_positive_proof_exits(changed)
        with self.assertRaisesRegex(ValueError, 'duplicate command label'):
            E.require_positive_proof_exits(valid + [valid[0]])


if __name__ == '__main__':
    unittest.main()

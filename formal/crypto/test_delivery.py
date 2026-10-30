"""Trust-gate tests; small real Java artifacts exercise the delivery boundary."""
import ast
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from zipfile import ZipFile

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('crypto_delivery', Path(__file__).with_name('delivery.py'))
delivery = importlib.util.module_from_spec(SPEC)
if SPEC.loader and Path(SPEC.origin).exists():
    SPEC.loader.exec_module(delivery)

JDK = Path(os.environ.get('MICROPROXY_JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
DAFNY = Path(os.environ.get('MICROPROXY_DAFNY', Path.home()/'.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'))


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='crypto-delivery-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, text):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_delivered_facade_must_match_the_reviewed_source(self):
        generated = self.write('production/checked/C.java', 'package checked; public class C {}')
        template = self.write('reviewed/Facade.java', 'final class Facade { void checked() {} }')
        actual = self.write('production/Facade.java', template.read_text())
        manifest = {'destination':'production', 'namespace':'checked', 'providers':[],
                    'facades':[{'source':'reviewed/Facade.java','destination':'production/Facade.java',
                                'sha256':delivery.digest(template)}]}
        with patch.object(delivery, 'ROOT', self.root):
            delivery.production_sources(manifest, {'checked/C.java':delivery.digest(generated)})
            actual.write_text('final class Facade { void unchecked() {} }')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                delivery.production_sources(manifest, {'checked/C.java':delivery.digest(generated)})

    def test_complete_closure_and_source_drift(self):
        entry = self.write('a.dfy', 'include "b.dfy"\nmodule A {}\n')
        dependency = self.write('b.dfy', 'module B {}\n')
        pins = delivery.source_closure(self.root, entry, DAFNY)
        self.assertEqual(set(pins), {'a.dfy', 'b.dfy'})
        delivery.check_pins(self.root, pins)
        dependency.write_text('module B { function Changed(): int { 1 } }\n')
        with self.assertRaisesRegex(RuntimeError, 'changed'):
            delivery.check_pins(self.root, pins)

    def test_per_source_composition_solver_policy_preserves_kernel_and_reference_settings(self):
        manifest = json.loads(Path(delivery.__file__).with_name('delivery.json').read_text())
        self.assertEqual(delivery.source_verify_options('formal/crypto/NativeMlKem.dfy', manifest),
                         ['--solver-option', 'O:smt.case_split=3'])
        self.assertEqual(delivery.source_verify_options('formal/crypto/NativeCodec.dfy', manifest),
                         manifest['dafny']['native_verify_options'])
        self.assertEqual(delivery.source_verify_options('formal/crypto/Polynomial.dfy', manifest), [])
        for value in (True, -1, 4, ['--filter-symbol', 'OneMethod']):
            changed = json.loads(json.dumps(manifest))
            changed['dafny']['source_solver_case_split']['formal/crypto/NativeMlKem.dfy'] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                delivery.source_verify_options('formal/crypto/NativeMlKem.dfy', changed)
        for path in ('../outside.dfy', '/absolute.dfy', 'formal/crypto/not-dafny.java'):
            changed = json.loads(json.dumps(manifest))
            changed['dafny']['source_solver_case_split'] = {path:3}
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                delivery.source_verify_options('formal/crypto/NativeMlKem.dfy', changed)

    def test_generation_uses_frozen_exact_inputs(self):
        source = self.write('original/a.dfy', 'module A {}\n')
        pins = {'a.dfy':delivery.digest(source)}
        destination = self.root/'frozen'
        delivery.freeze_inputs(self.root/'original', pins, destination)
        source.write_text('module Changed {}\n')
        delivery.check_pins(destination, pins)
        self.assertEqual((destination/'a.dfy').read_text(), 'module A {}\n')
        with self.assertRaises(RuntimeError):
            delivery.check_pins(self.root/'original', pins)

    def test_include_escape_syntax_and_symlink_rejected(self):
        entry = self.write('a.dfy', 'include "../outside.dfy"\n')
        with self.assertRaises(RuntimeError):
            delivery.source_closure(self.root, entry, DAFNY)
        entry.write_text('include {:verify false} "b.dfy"\n')
        with self.assertRaisesRegex(RuntimeError, 'dependency parser'):
            delivery.source_closure(self.root, entry, DAFNY)
        self.write('b.dfy', 'module B {}\n')
        (self.root/'alias.dfy').symlink_to(self.root/'b.dfy')
        entry.write_text('include "alias.dfy"\n')
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            delivery.source_closure(self.root, entry, DAFNY)

    def test_dependency_parser_covers_bom_comments_multiline_and_encoding(self):
        self.write('b.dfy', 'include "c.dfy"\nmodule B {}\n')
        self.write('c.dfy', 'module C {}\n')
        forms = ('\ufeffinclude "b.dfy"\nmodule A {}\n',
                 '/* before */include "b.dfy"\nmodule A {}\n',
                 'include/* nested /* comment */ */\n"b.dfy"\nmodule A {}\n',
                 'include "b.dfy" include "c.dfy"\nmodule A {}\n',
                 '// include "missing.dfy"\ninclude "b.dfy"\r\nmodule A {}\r\n')
        for source in forms:
            with self.subTest(source=source):
                entry = self.write('a.dfy', source)
                pins = delivery.source_closure(self.root, entry, DAFNY)
                self.assertEqual(set(pins), {'a.dfy', 'b.dfy', 'c.dfy'})
                self.assertEqual(pins['a.dfy'], delivery.digest(entry))
        for encoding in ('utf-16', 'utf-16-le', 'utf-32', 'latin1'):
            entry = self.root/'a.dfy'
            entry.write_bytes('include "b.dfy"\n// café\n'.encode(encoding))
            with self.subTest(encoding=encoding), self.assertRaisesRegex(RuntimeError, 'UTF-8'):
                delivery.source_closure(self.root, entry, DAFNY)

    def test_dependency_parser_rejects_missing_invalid_and_ambiguous_paths(self):
        for source in ('include "missing.dfy"\nmodule A {}\n', 'module A { bad ! }'):
            entry = self.write('a.dfy', source)
            with self.subTest(source=source), self.assertRaises(RuntimeError):
                delivery.source_closure(self.root, entry, DAFNY)
        entry = self.write('a;ambiguous.dfy', 'module A {}\n')
        with self.assertRaisesRegex(RuntimeError, 'dependency path'):
            delivery.source_closure(self.root, entry, DAFNY)

    def test_ambiguous_include_cannot_be_split_into_other_existing_dependencies(self):
        first = self.write('b.dfy', 'module B {}\n')
        second = self.write('c.dfy', 'module C {}\n')
        # Dafny's delimiter has no escaping. Both split paths exist, so merely
        # validating each output token would silently omit the true dependency.
        relative = 'b.dfy;'+str(second.resolve())
        actual = self.root/relative
        actual.parent.mkdir(parents=True)
        actual.write_text('module Hidden {}\n')
        entry = self.write('a.dfy', 'include "'+relative+'"\nmodule A {}\n')
        with self.assertRaisesRegex(RuntimeError, 'dependency path'):
            delivery.source_closure(self.root, entry, DAFNY)

    def test_dependency_parser_diagnostics_and_source_drift_fail_closed(self):
        entry = self.write('a.dfy', 'module A {}\n')
        clean = delivery.LEGACY_PARSER_BANNER+'\n'
        for status, output in ((1, clean), (0, ''), (0, clean+'Warning: source warning\n'),
                               (0, clean+'unrecognized parser output\n'),
                               (0, clean+'Dafny program verifier finished with 1 verified, 0 errors\n')):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                delivery.source_closure(self.root, entry, DAFNY, call=lambda *args: (status, output))

        def changed_source(label, command):
            entry.write_text('module Changed {}\n')
            return 0, clean

        with self.assertRaisesRegex(RuntimeError, 'changed'):
            delivery.source_closure(self.root, entry, DAFNY, call=changed_source)
        folder = self.root/'nested'
        folder.mkdir()
        (folder/'a.dfy').write_text('module A {}\n')
        (self.root/'alias').symlink_to(folder, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            delivery.source_closure(self.root, self.root/'alias/a.dfy', DAFNY)

    def test_exact_file_inventory_rejects_tamper_missing_extra_and_symlinks(self):
        folder = self.root/'sources'
        file = self.write('sources/a.java', 'class A {}')
        pins = delivery.file_map(folder)
        file.write_text('class B {}')
        with self.assertRaisesRegex(RuntimeError, 'artifact'):
            delivery.check_tree(folder, pins)
        file.unlink()
        with self.assertRaises(RuntimeError):
            delivery.check_tree(folder, pins)
        file.write_text('class A {}')
        self.write('sources/extra.txt', 'unexpected')
        with self.assertRaises(RuntimeError):
            delivery.check_tree(folder, pins)
        (folder/'extra.txt').unlink()
        (folder/'alias.java').symlink_to(file)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            delivery.file_map(folder)

    def test_generation_must_be_verified_without_diagnostics(self):
        clean = 'Dafny program verifier finished with 12 verified, 0 errors\n'
        self.assertEqual(delivery.proof_result(0, clean), 12)
        for status, output in [(1, clean), (0, ''), (0, clean+clean),
                               (0, clean+'Warning: unexpected\n'),
                               (0, clean+'timed out\n'),
                               (0, clean+'resource limit\n'),
                               (0, 'Dafny program verifier did not attempt verification'),
                               (0, 'Dafny program verifier finished with 0 verified, 0 errors')]:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                delivery.proof_result(status, output)

    def test_zero_proof_count_requires_explicit_provider_only_policy(self):
        empty = 'Dafny program verifier finished with 0 verified, 0 errors\n'
        with self.assertRaises(RuntimeError):
            delivery.proof_result(0, empty)
        self.assertEqual(delivery.proof_result(0, empty, minimum=0), 0)
        with self.assertRaises(RuntimeError):
            delivery.proof_result(0, empty+'Warning: skipped owned code\n', minimum=0)

    def test_translation_is_separate_from_complete_frozen_source_verification(self):
        clean = 'Dafny program verifier did not attempt verification\n'
        delivery.generation_result(0, clean)
        for status, output in [(1, clean), (0, ''), (0, clean+'Warning: unsupported\n'),
                               (0, clean+'resource limit\n'), (0, clean+clean)]:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                delivery.generation_result(status, output)

    def test_audit_names_and_owners_are_exact(self):
        names = [('formal/crypto/JdkHash.dfy', 'H'), ('formal/crypto/JdkHash.dfy', 'G'),
                 ('formal/crypto/NativeJdkHash.dfy', 'Hash'), ('formal/crypto/NativeJdkHash.dfy', 'Expand')]
        output = '\n'.join(f'{self.root/file}(1,1): Warning: {name}: Declaration has explicit `{{:axiom}}` attribute. Possible mitigation: Provide a proof or test.' for file, name in names)
        output += '\nDafny auditor completed with 4 findings\n'
        delivery.audit_result(0, output, self.root, names)
        for changed in [output.replace('NativeJdkHash.dfy', 'OtherJdkHash.dfy'),
                        output.replace('Warning: Hash:', 'Warning: Other:'), output+'Warning: other\n']:
            with self.assertRaises(RuntimeError):
                delivery.audit_result(0, changed, self.root, names)

    def test_namespace_and_provider_owner_rejected(self):
        package = 'io.example.verified'
        self.write('generated/io/example/verified/A.java', 'package io.example.verified;\npublic class A {}\n')
        delivery.generated_inventory(self.root/'generated', package, 'NativeCrypto')
        self.write('generated/io/example/verified/Bad.java', 'package attacker; public class Bad {}\n')
        with self.assertRaisesRegex(RuntimeError, 'namespace'):
            delivery.generated_inventory(self.root/'generated', package, 'NativeCrypto')
        provider = self.write('P.java', 'package wrong; public final class P {}\n')
        with self.assertRaisesRegex(RuntimeError, 'owner'):
            delivery.provider_inventory(self.root, [{'source':'P.java', 'owner':'expected.P', 'sha256':delivery.digest(provider)}])

    def test_all_four_configured_provider_bindings_match_actual_dafny_sources(self):
        manifest = json.loads(Path(delivery.__file__).with_name('delivery.json').read_text())
        sources = {binding['source']:None for binding in manifest['provider_bindings']}
        delivery.check_bindings(sources, manifest)
        changed = json.loads(json.dumps(manifest))
        changed['provider_bindings'][0]['owner'] = 'wrong.Provider'
        with self.assertRaisesRegex(RuntimeError, 'ABI mismatch'):
            delivery.check_bindings(sources, changed)

    def test_extra_external_binding_anywhere_in_closure_is_rejected(self):
        self.write('Trusted.dfy', 'module Trusted { function {:extern "trusted.P", "hash"} {:axiom} H(): int }')
        self.write('Rogue.dfy', 'module Rogue { method {:extern "attacker.P", "run"} Run() {} }')
        manifest = {'provider_bindings':[{'source':'Trusted.dfy', 'owner':'trusted.P', 'method':'hash', 'symbol':'H'}]}
        delivery.check_bindings({'Trusted.dfy':None}, manifest, self.root)
        with self.assertRaisesRegex(RuntimeError, 'external'):
            delivery.check_bindings({'Trusted.dfy':None, 'Rogue.dfy':None}, manifest, self.root)

    def native_fixture(self):
        manifest = json.loads(Path(delivery.__file__).with_name('delivery.json').read_text())
        contract = manifest['native_evidence']
        pins = delivery.source_closure(delivery.ROOT, delivery.ROOT/manifest['entry'], DAFNY)
        inputs = dict(pins)
        for name in [contract['domain_source'], *contract['additional_inputs']]:
            inputs[name] = delivery.digest(delivery.ROOT/name)
        repository = self.root/'repository'
        delivery.freeze_inputs(delivery.ROOT, inputs, repository)
        guard_policy = contract['native_runtime_guard']
        # Synthetic receipt data exercises the schema boundary, not a timing or
        # implementation proof. Only its fixture inventory digest is substituted;
        # the real manifest pins the independently reviewable 193-site inventory.
        inventory = [{'file':guard_policy['caller_inventory']['files'][i % len(guard_policy['caller_inventory']['files'])],
                      'method':'FixtureMetadata', 'line':i+1, 'source':'dafny.Helpers.toInt(publicIndex);'}
                     for i in range(guard_policy['caller_inventory']['count'])]
        guard_policy['caller_inventory']['sha256'] = delivery.json_digest(inventory)
        guard = json.loads(json.dumps(guard_policy['fixed_fields']))
        guard['constant_zero_boxings'] = [
            {'instruction':f'{i}: invokestatic #1 // Method java/lang/{kind}.valueOf:({descriptor})Ljava/lang/{kind};',
             'source':guard_policy['constant_zero_boxings']['source']}
            for kind, descriptor in (('Byte', 'B'), ('Integer', 'I'), ('Long', 'J'))
            for i in range(guard_policy['constant_zero_boxings']['kinds'][kind])]
        guard['caller_inventory'] = inventory
        guard['caller_review'] = guard_policy['caller_review']
        native = {'scope':'full', 'inputs':inputs,
                  'proofs':{name:123 for name in contract['proof_phases']},
                  'controls':{name:{'verified':1, 'errors':1} for name in contract['semantic_controls']},
                  'commands':[{'label':name, 'command':['schema-fixture', name], 'exit':status}
                              for name, status in contract['command_exits'].items()],
                  'java':[{'version':'openjdk version "21.0.12.1"', 'tests':contract['replay_inventory']},
                          {'version':'openjdk version "25.0.5"', 'tests':contract['replay_inventory']}],
                  'provider_assumptions':{'primitive_count':2, 'declaration_count':4},
                  'native_runtime_guard':guard,
                  'bytecode_controls':{name:{'rejected':reason if name != 'selector-payload-boxing' else
                      reason+' 47: invokestatic #35 // Method java/lang/Byte.valueOf:(B)Ljava/lang/Byte;'}
                      for name, reason in contract['bytecode_control_rejections'].items()},
                  'generated_java':{name:'e'*64 for name in guard_policy['caller_inventory']['files']},
                  'compiled_classes':{'NativeMlKem/__default.class':'f'*64},
                  'runtime_coordinate':manifest['runtime']['coordinate'],
                  'runtime_sha256':manifest['runtime']['sha256']}

        def accept(receipt, *, declared_contract=contract, expected_inputs=inputs):
            path = self.write('native-kem/receipt.json', json.dumps(receipt))
            envelope = {'schema':'microproxy.crypto-input-evidence/v1', 'status':'complete', 'scope':'full',
                        'inputs_before':pins, 'inputs_after':pins,
                        'receipts':[{'path':'native-kem/receipt.json', 'sha256':delivery.digest(path)}]}
            return delivery.validate_input_evidence(envelope, self.root, pins, manifest['runtime']['sha256'],
                expected_inputs=expected_inputs, contract=declared_contract, root=repository)

        return manifest, pins, inputs, native, repository, accept

    def test_complete_input_receipt_required_and_bound_to_all_sources(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        self.assertTrue(accept(native))
        for change in ({'scope':'owned'}, {'proofs':{'proof-owned':1}}, {'java':native['java'][:1]},
                       {'inputs':{}}, {'controls':{}}, {'status':'failed'}, {'commands':[]}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                accept(dict(native, **change))
        for name in inputs:
            stale = dict(inputs, **{name:'0'*64})
            with self.subTest(stale_input=name), self.assertRaises(RuntimeError):
                accept(dict(native, inputs=stale))
        for name in manifest['native_evidence']['additional_inputs']+[manifest['native_evidence']['domain_source']]:
            path = repository/name
            before = path.read_bytes()
            path.write_bytes(before+b'\n// changed after replay\n')
            try:
                with self.subTest(current_input_drift=name), self.assertRaises(RuntimeError):
                    accept(native)
            finally:
                path.write_bytes(before)

    def test_full_partitioned_runner_receipt_schema_and_missing_phases(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        contract = manifest['native_evidence']
        runner_path = delivery.ROOT/contract['runner']['path']
        runner_spec = importlib.util.spec_from_file_location('delivery_receipt_runner', runner_path)
        runner = importlib.util.module_from_spec(runner_spec)
        runner_spec.loader.exec_module(runner)
        self.assertEqual(delivery.digest(runner_path), contract['runner']['sha256'])
        self.assertEqual(runner.EXPECTED_TESTS, contract['replay_inventory'])
        self.assertEqual(runner.MAVEN_RUNTIME_SHA256, manifest['runtime']['sha256'])
        tree = ast.parse(runner_path.read_text())
        controls = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == 'controls' for target in node.targets))
        self.assertEqual([row[0] for row in ast.literal_eval(controls)], contract['semantic_controls'])
        control_lists = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == 'controls' for target in node.targets)]
        self.assertEqual([row.elts[0].value for row in control_lists[-1].elts],
                         list(contract['bytecode_control_rejections']))
        caller_review = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                    and target.slice.value == 'caller_review' for target in node.targets))
        self.assertEqual(ast.literal_eval(caller_review), contract['native_runtime_guard']['caller_review'])
        full = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                    and isinstance(node.test, ast.Compare)
                    and isinstance(node.test.left, ast.Attribute) and node.test.left.attr == 'scope'
                    and any(isinstance(value, ast.Constant) and value.value == 'full'
                            for value in node.test.comparators))
        declared = {node.value.args[0].value for node in full.body if isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'prove'}
        self.assertEqual(declared | {'generate-java'}, set(contract['proof_phases']))
        self.assertEqual(accept(native), [(self.root/'native-kem/receipt.json').resolve()])
        expected = delivery.native_input_pins(repository, pins, contract, DAFNY)
        self.assertEqual(expected, inputs)
        for missing in native['proofs']:
            incomplete = {name:count for name, count in native['proofs'].items() if name != missing}
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                accept(dict(native, proofs=incomplete))
        for invalid in ({'proof-owned':9999, 'generate-java':9999},
                        {'proof-native-graph':9999, 'proof-reference-graph':9999, 'generate-java':9999},
                        dict(native['proofs'], **{'proof-native-kernels':0}),
                        dict(native['proofs'], **{'proof-native-kernels':True}),
                        dict(native['proofs'], **{'unrelated-positive-phase':9999})):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                accept(dict(native, proofs=invalid))

    def test_native_domain_dependencies_use_dafny_parser_and_full_current_hash_map(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        contract = manifest['native_evidence']
        domain = repository/contract['domain_source']
        domain.write_text('\ufeff/* leading comment */ include "NativeMlKem.dfy"\ninclude "extra-domain.dfy"\n')
        extra = domain.parent/'extra-domain.dfy'
        extra.write_text('module ExtraDomain {}\n')
        expected = delivery.native_input_pins(repository, pins, contract, DAFNY)
        self.assertIn(extra.relative_to(repository).as_posix(), expected)
        with self.assertRaises(RuntimeError):
            accept(native, expected_inputs=expected)
        updated = dict(native, inputs=expected)
        self.assertTrue(accept(updated, expected_inputs=expected))
        for name in [*contract['additional_inputs'], contract['domain_source']]:
            incomplete = {key:sha for key, sha in expected.items() if key != name}
            with self.subTest(omitted_input=name), self.assertRaises(RuntimeError):
                accept(dict(updated, inputs=incomplete), expected_inputs=incomplete)

    def test_exact_native_controls_inventory_commands_and_contract_are_required(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        contract = manifest['native_evidence']
        for missing in native['controls']:
            controls = {name:result for name, result in native['controls'].items() if name != missing}
            with self.subTest(missing_control=missing), self.assertRaises(RuntimeError):
                accept(dict(native, controls=controls))
        for invalid in ({'wrong-coins':{'errors':1}},
                        dict(native['controls'], unrelated={'verified':1, 'errors':1}),
                        dict(native['controls'], **{'wrong-coins':{'verified':1, 'errors':0}}),
                        dict(native['controls'], **{'wrong-coins':{'verified':True, 'errors':1}})):
            with self.subTest(controls=invalid), self.assertRaises(RuntimeError):
                accept(dict(native, controls=invalid))
        for tests in ({'assertions':1}, dict(contract['replay_inventory'], malformed=0),
                      dict(contract['replay_inventory'], unrelated=1)):
            java = [dict(run, tests=tests) for run in native['java']]
            with self.subTest(tests=tests), self.assertRaises(RuntimeError):
                accept(dict(native, java=java))
        for java in (native['java'][:1], native['java']+[native['java'][0]],
                     [native['java'][0], native['java'][0]]):
            with self.subTest(java=java), self.assertRaises(RuntimeError):
                accept(dict(native, java=java))
        for index, command in enumerate(native['commands']):
            missing = native['commands'][:index]+native['commands'][index+1:]
            wrong_exit = [dict(item) for item in native['commands']]
            wrong_exit[index]['exit'] = 0 if command['exit'] else 1
            for commands in (missing, wrong_exit):
                with self.subTest(command=command['label'], commands=commands), self.assertRaises(RuntimeError):
                    accept(dict(native, commands=commands))
        # A native replay emitted a genuine semantic-failure summary and then
        # died with SIGSEGV. Valid remaining phases cannot excuse a tool crash.
        for abnormal in (-11, -9):
            commands = [dict(item) for item in native['commands']]
            next(item for item in commands if item['label'] == 'control-modulus-error-kind')['exit'] = abnormal
            with self.subTest(abnormal_control_exit=abnormal), self.assertRaises(RuntimeError):
                accept(dict(native, commands=commands))
        drifted = dict(contract, schema='microproxy.native-kem-evidence-contract/v3')
        with self.assertRaises(RuntimeError):
            accept(native, declared_contract=drifted)
        runner = repository/contract['runner']['path']
        runner.write_bytes(runner.read_bytes()+b'\n# runner drift\n')
        with self.assertRaises(RuntimeError):
            delivery.native_input_pins(repository, pins, contract, DAFNY)

    def test_selector_runtime_guard_missing_partial_or_wrong_inventory_is_rejected(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        contract = manifest['native_evidence']
        # The direct validator must reject incomplete receipt claims, before any
        # large proof, code generation or compatibility replay is attempted.
        delivery.validate_native_runtime_guard(native, contract)
        for missing in native['native_runtime_guard']:
            guard = {name:value for name, value in native['native_runtime_guard'].items() if name != missing}
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                delivery.validate_native_runtime_guard(dict(native, native_runtime_guard=guard), contract)
        invalid = [
            {'selector_bounds':[1087,32]}, {'selector_bounds':[1088,31]},
            {'selector_conditional_opcodes':['if_icmpge','if_icmpge','ifeq']},
            {'payload_scalar_boxings':1}, {'payload_scalar_boxings':False},
            {'runtime_helper_calls':native['native_runtime_guard']['runtime_helper_calls'][:1]},
            {'runtime_helper_calls':native['native_runtime_guard']['runtime_helper_calls']+[['bv16ShiftRight','(SB)S']]},
            {'wide_shift_helpers':{'bv64ShiftRight':'payload branch'}},
            {'unsigned_byte_conversions':'not inspected'},
            {'constant_zero_boxings':native['native_runtime_guard']['constant_zero_boxings'][:1]},
            {'caller_inventory':native['native_runtime_guard']['caller_inventory'][:-1]},
            {'caller_review':{}}, {'scope':'JVM timing is proved'}]
        changed = json.loads(json.dumps(native['native_runtime_guard']['caller_inventory']))
        changed[0]['source'] = 'dafny.Helpers.bv16ShiftRight(payload,(byte)8);'
        invalid.append({'caller_inventory':changed})
        for change in invalid:
            guard = dict(native['native_runtime_guard'], **change)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                delivery.validate_native_runtime_guard(dict(native, native_runtime_guard=guard), contract)
        for absent in ('native_runtime_guard','bytecode_controls'):
            with self.subTest(absent=absent), self.assertRaises(RuntimeError):
                accept({name:value for name,value in native.items() if name != absent})

    def test_all_three_compiled_selector_controls_and_ordered_commands_are_required(self):
        manifest, pins, inputs, native, repository, accept = self.native_fixture()
        contract = manifest['native_evidence']
        for missing in native['bytecode_controls']:
            controls = {name:value for name, value in native['bytecode_controls'].items() if name != missing}
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                accept(dict(native, bytecode_controls=controls))
        for invalid in ({}, {'selector-narrow-helper':{'rejected':'anything'}},
                        dict(native['bytecode_controls'], extra={'rejected':'Payload scalar boxing:'}),
                        dict(native['bytecode_controls'], **{'selector-payload-branch':{'rejected':'accepted'}}),
                        dict(native['bytecode_controls'], **{'selector-payload-boxing':{'rejected':'Payload scalar boxing:'}})):
            with self.subTest(controls=invalid), self.assertRaises(RuntimeError):
                accept(dict(native, bytecode_controls=invalid))
        commands = [dict(item) for item in native['commands']]
        commands[-2], commands[-1] = commands[-1], commands[-2]
        with self.assertRaises(RuntimeError):
            accept(dict(native, commands=commands))
        reordered = dict(contract, command_exits=dict(reversed(list(contract['command_exits'].items()))))
        with self.assertRaises(RuntimeError):
            delivery.check_native_contract(reordered)
        with self.assertRaises(RuntimeError):
            accept(native, declared_contract=dict(contract, schema='microproxy.native-kem-evidence-contract/v1'))
        source = repository/'formal/crypto/NativeMlKem.dfy'
        source.write_bytes(source.read_bytes()+b'\n// source drift\n')
        with self.assertRaises(RuntimeError):
            delivery.native_input_pins(repository, pins, contract, DAFNY)

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_actual_class_and_jar_identity_includes_arrays_and_extra_classes(self):
        source = self.write('java/io/example/verified/A.java',
                            'package io.example.verified; public final class A { public static int f(int[] a) { return a[0]+1; } }\n')
        canonical = self.root/'canonical'
        canonical.mkdir()
        subprocess.run([str(JDK/'bin/javac'), '--release', '21', '-g:lines,vars,source', '-d', str(canonical), str(source)], check=True, capture_output=True)
        expected = delivery.class_map(canonical, ['io/example/verified/'])
        target = self.root/'target/classes'
        target.mkdir(parents=True)
        owner = 'io/example/verified/A.class'
        artifact = target/owner
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes((canonical/owner).read_bytes())
        jar = self.root/'quic.jar'
        with ZipFile(jar, 'w') as bundle:
            bundle.writestr(owner, artifact.read_bytes())
        delivery.compare_delivered(expected, target, jar, ['io/example/verified/'])
        # This same array method keeps its ABI while changing its actual code.
        source.write_text(source.read_text().replace('a[0]+1', 'a[0]+2'))
        subprocess.run([str(JDK/'bin/javac'), '--release', '21', '-g:lines,vars,source', '-d', str(target), str(source)], check=True, capture_output=True)
        with self.assertRaisesRegex(RuntimeError, 'classes'):
            delivery.compare_delivered(expected, target, jar, ['io/example/verified/'])
        changed_code = artifact.read_bytes()
        artifact.write_bytes((canonical/owner).read_bytes())
        with ZipFile(jar, 'w') as bundle:
            bundle.writestr(owner, artifact.read_bytes())
            bundle.writestr('io/example/verified/Unexpected.class', artifact.read_bytes())
        with self.assertRaises(RuntimeError):
            delivery.compare_delivered(expected, target, jar, ['io/example/verified/'])
        # A normal class inventory must not overlook code the JVM selects from
        # a multi-release JAR on a supported JDK.
        with ZipFile(jar, 'w') as bundle:
            bundle.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n')
            bundle.writestr(owner, artifact.read_bytes())
            bundle.writestr('META-INF/versions/21/'+owner, changed_code)
        with self.assertRaisesRegex(RuntimeError, 'multi-release'):
            delivery.compare_delivered(expected, target, jar, ['io/example/verified/'])

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_handwritten_sources_retain_cast_and_rawtypes_lint(self):
        generated = self.write('source/io/example/generated/G.java',
                               'package io.example.generated; public class G { public static int f(){return 1;} }')
        canonical = self.root/'generated-classes'
        canonical.mkdir()
        subprocess.run([str(JDK/'bin/javac'), '--release', '21', '-d', str(canonical), str(generated)],
                       check=True, capture_output=True)
        handwritten = self.write('source/io/example/handwritten/H.java',
                                 'package io.example.handwritten; public class H { java.util.List raw; '
                                 'public static int f(){return (int)3+io.example.generated.G.f();} }')
        options = {'debug':'lines,vars,source', 'encoding':'UTF-8', 'handwritten_lint':['-Xlint:all,-serial']}
        with self.assertRaises(RuntimeError) as failure:
            delivery.compile_handwritten(self.root/'source', 'io.example.generated', JDK, [canonical],
                                         self.root/'bad-check', options)
        self.assertIn('[cast]', str(failure.exception))
        self.assertIn('[rawtypes]', str(failure.exception))
        handwritten.write_text('package io.example.handwritten; public class H { '
                               'public static int f(){return 3+io.example.generated.G.f();} }')
        result = delivery.compile_handwritten(self.root/'source', 'io.example.generated', JDK, [canonical],
                                              self.root/'good-check', options)
        self.assertEqual(set(result['classes']), {'io/example/handwritten/H.class'})
        self.assertEqual(set(result['sources']), {'io/example/handwritten/H.java'})
        self.assertEqual(result['lint'], ['-Xlint:all,-serial'])

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_existing_compiler_output_exemption_is_an_exact_source_pin(self):
        old_generated = self.write('source/legacy/L.java',
                                   'package legacy; public class L { public static int f(){return (int)1;} }')
        self.write('source/handwritten/H.java',
                   'package handwritten; public class H { public static int f(){return legacy.L.f();} }')
        pins = {'legacy/L.java':delivery.digest(old_generated)}
        options = {'debug':'lines,vars,source', 'encoding':'UTF-8',
                   'handwritten_lint':['-Xlint:all,-serial'], 'lint':['-Xlint:all,-serial,-cast,-rawtypes']}
        result = delivery.compile_handwritten(self.root/'source', 'new.generated', JDK, [],
                    self.root/'strict', options, existing_generated_sources=pins)
        self.assertEqual(set(result['sources']), {'handwritten/H.java'})
        self.assertEqual(set(result['classes']), {'legacy/L.class', 'handwritten/H.class'})
        old_generated.write_text(old_generated.read_text().replace('(int)1', '(int)2'))
        with self.assertRaisesRegex(RuntimeError, 'changed input'):
            delivery.compile_handwritten(self.root/'source', 'new.generated', JDK, [],
                    self.root/'stale', options, existing_generated_sources=pins)

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_non_name_modified_utf8_constants_do_not_change_class_identity(self):
        source = self.write('C.java', 'public class C { public static String f(){return "before\\0after";} }')
        subprocess.run([str(JDK/'bin/javac'), '--release', '21', '-d', str(self.root), str(source)],
                       check=True, capture_output=True)
        self.assertEqual(delivery.class_owner((self.root/'C.class').read_bytes()), 'C')

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_relative_handwritten_paths_refer_to_the_checked_inputs(self):
        self.write('source/C.java', 'public class C {}')
        options = {'debug':'lines,vars,source', 'encoding':'UTF-8', 'handwritten_lint':['-Xlint:all,-serial']}
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            result = delivery.compile_handwritten(Path('source'), 'new.generated', JDK, [], Path('check'), options)
        finally:
            os.chdir(previous)
        self.assertEqual(set(result['classes']), {'C.class'})

    @unittest.skipUnless((JDK/'bin/javac').exists(), 'explicit JDK21 unavailable')
    def test_package_info_is_emitted_by_the_same_canonical_compiler(self):
        self.write('source/p/C.java', 'package p; public class C {}')
        self.write('source/p/package-info.java', '/** Package documentation. */\npackage p;\n')
        options = {'debug':'lines,vars,source', 'encoding':'UTF-8',
                   'handwritten_lint':['-Xlint:all,-serial'], 'common_args':['-Xpkginfo:always']}
        result = delivery.compile_handwritten(self.root/'source', 'new.generated', JDK, [], self.root/'check', options)
        self.assertEqual(set(result['classes']), {'p/C.class', 'p/package-info.class'})

    def test_timeout_reaps_owned_process_and_removes_partial_stage(self):
        output = self.root/'stage'
        with self.assertRaises(RuntimeError):
            with delivery.staging_directory(output) as work:
                delivery.run_command([sys.executable, '-c', 'import time; time.sleep(60)'], work/'sleep.log', self.root, timeout=.1)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_official_compiler_distribution_rejects_tool_archive_and_extra_file_drift(self):
        cache = self.root/'cache'
        cache.mkdir()
        archive = cache/'official.zip'
        members = {'dafny/dafny':b'compiler', 'dafny/z3/bin/z3-4.12.1':b'solver',
                   'dafny/DafnyRuntime.jar':b'runtime'}
        with ZipFile(archive, 'w') as bundle:
            for name, content in members.items():
                bundle.writestr(name, content)
                path = cache/'official'/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        asset = {'archive':'official.zip', 'directory':'official', 'sha256':delivery.digest(archive),
                 'runtime_sha256':delivery.digest(cache/'official/dafny/DafnyRuntime.jar')}
        manifest = {'dafny':{'assets':{delivery.platform.system()+'-'+delivery.platform.machine():asset}}}
        delivery.official_distribution(cache, manifest)
        compiler = cache/'official/dafny/dafny'
        compiler.write_bytes(b'changed compiler')
        with self.assertRaises(RuntimeError):
            delivery.official_distribution(cache, manifest)
        compiler.write_bytes(b'compiler')
        (cache/'official/extra').write_text('unexpected compiler input')
        with self.assertRaises(RuntimeError):
            delivery.official_distribution(cache, manifest)
        (cache/'official/extra').unlink()
        archive.write_bytes(archive.read_bytes()+b'tamper')
        with self.assertRaises(RuntimeError):
            delivery.official_distribution(cache, manifest)

    def test_exact_maven_runtime_pin_rejects_tampering(self):
        path = self.write('runtime.jar', 'changed runtime')
        with self.assertRaisesRegex(RuntimeError, 'runtime checksum'):
            delivery.check_runtime(path, {'runtime':{'sha256':'0'*64}})

    def test_timeout_kills_descendant_work(self):
        marker = self.root/'survived'
        child = 'import time; from pathlib import Path; time.sleep(.6); Path('+repr(str(marker))+').write_text("bad")'
        leader = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",'+repr(child)+']); time.sleep(60)'
        with self.assertRaisesRegex(RuntimeError, 'timeout'):
            delivery.run_command([sys.executable, '-c', leader], self.root/'process.log', self.root, timeout=.2)
        time.sleep(.7)
        self.assertFalse(marker.exists(), 'a descendant survived delivery cancellation')

    def test_sigterm_cleans_stage_and_child(self):
        started = self.root/'started'
        survived = self.root/'survived'
        destination = self.root/'stage'
        child = ('from pathlib import Path; import time; Path('+repr(str(started))+').write_text("started"); '
                 'time.sleep(.6); Path('+repr(str(survived))+').write_text("bad")')
        loader = ('import importlib.util,sys; from pathlib import Path; '
                  's=importlib.util.spec_from_file_location("delivery",'+repr(str(Path(delivery.__file__)))+'); '
                  'd=importlib.util.module_from_spec(s); s.loader.exec_module(d)\n'
                  'with d.staging_directory(Path('+repr(str(destination))+')) as work:\n'
                  ' d.run_command([sys.executable,"-c",'+repr(child)+'],work/"child.log",Path('+repr(str(self.root))+'))\n')
        process = subprocess.Popen([sys.executable, '-c', loader], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while not started.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(started.exists(), 'child did not start')
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            time.sleep(.7)
            self.assertFalse(survived.exists(), 'SIGTERM left the owned child running')
            self.assertFalse(destination.exists())
            self.assertFalse(list(self.root.glob('.crypto-delivery-*')))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()

    def test_initial_publish_rolls_back_owned_files_and_preserves_existing_work(self):
        canonical = self.root/'canonical'
        first = self.write('canonical/p/A.java', 'class A {}')
        second = self.write('canonical/p/B.java', 'class B {}')
        destination = self.root/'production'
        unrelated = self.write('production/p/B.java', 'unrelated existing edit')
        pins = {'p/A.java':delivery.digest(first), 'p/B.java':delivery.digest(second)}
        with self.assertRaisesRegex(RuntimeError, 'stale existing'):
            with delivery.initial_sources(canonical, destination, pins):
                pass
        self.assertFalse((destination/'p/A.java').exists())
        self.assertEqual(unrelated.read_text(), 'unrelated existing edit')
        unrelated.unlink()
        with self.assertRaisesRegex(RuntimeError, 'later gate'):
            with delivery.initial_sources(canonical, destination, pins):
                raise RuntimeError('later gate failed')
        self.assertFalse((destination/'p/A.java').exists())
        self.assertFalse((destination/'p/B.java').exists())

    def test_adoption_evidence_changed_during_reproduction_blocks_source_writes(self):
        stage = self.write('stage/receipt.json', '{"status":"complete"}')
        compat = self.write('compat.json', '{"status":"complete"}')
        perf = self.write('perf.json', '{"status":"complete"}')
        approval = {'schema':'microproxy.crypto-delivery-approval/v1', 'status':'approved', 'scope':'full',
                    'approved_by':'user', 'decision':'Accept checked tradeoffs',
                    'stage_receipt_sha256':delivery.digest(stage),
                    'compatibility_receipts':[{'path':'compat.json', 'sha256':delivery.digest(compat)}],
                    'performance_receipt':{'path':'perf.json', 'sha256':delivery.digest(perf)}}
        approval_path = self.write('approval.json', json.dumps(approval))
        args = type('Args', (), {'approval':approval_path, 'stage':stage.parent})()
        with patch.object(delivery, 'load_stage', return_value=(stage, {'delivered_sources':{}})), \
                patch.object(delivery, 'reproduce_stage', side_effect=lambda *args: perf.write_text('{"status":"changed"}')), \
                patch.object(delivery, 'production_sources'), \
                patch.object(delivery, 'initial_sources') as writes:
            with self.assertRaises(RuntimeError):
                delivery.publish(args, {'destination':'unused'})
            writes.assert_not_called()

    def test_delegated_adoption_separates_prior_user_authority_and_agent_evaluation(self):
        sources = {'formal/crypto/NativeMlKem.dfy':'a'*64}
        stage = self.write('stage.json', json.dumps({'status':'complete', 'sources':sources}))
        compat = self.write('compat.json', '{"status":"complete"}')
        perf = self.write('perf.json', '{"status":"complete"}')
        authorization = {'schema':'microproxy.crypto-user-authorization/v1', 'authority':'user',
                         'action':'integrate-after-checks', 'instruction':'Integrate after checks',
                         'source':'Prior user reply selecting production integration after checks'}
        record = self.write('authorization.json', json.dumps(authorization))
        evaluation = {'evaluated_by':'codex/root', 'decision':'Accept the measured compatibility and performance tradeoff',
                      'stage_receipt_sha256':delivery.digest(stage), 'source_map_sha256':delivery.json_digest(sources),
                      'compatibility_receipts':[{'path':'compat.json', 'sha256':delivery.digest(compat)}],
                      'performance_receipt':{'path':'perf.json', 'sha256':delivery.digest(perf)}}
        approval = {'schema':'microproxy.crypto-delivery-approval/v2', 'status':'approved', 'scope':'full',
                    'mode':'user-delegated', 'prior_user_authorization':{'path':'authorization.json', 'sha256':delivery.digest(record)},
                    'agent_evaluation':evaluation}
        self.assertEqual(set(delivery.validate_approval(approval, self.root, stage)),
                         {record.resolve(), compat.resolve(), perf.resolve()})
        for change in ({'source_map_sha256':'0'*64}, {'stage_receipt_sha256':'0'*64},
                       {'evaluated_by':'user'}, {'performance_receipt':None}, {'decision':''}):
            with self.subTest(evaluation=change), self.assertRaises(RuntimeError):
                delivery.validate_approval(dict(approval, agent_evaluation=dict(evaluation, **change)), self.root, stage)
        for change in ({'authority':'agent'}, {'source':''}, {'action':'unconditional-adoption'}):
            record.write_text(json.dumps(dict(authorization, **change)))
            reference = {'path':'authorization.json', 'sha256':delivery.digest(record)}
            with self.subTest(authorization=change), self.assertRaises(RuntimeError):
                delivery.validate_approval(dict(approval, prior_user_authorization=reference), self.root, stage)
        record.write_text(json.dumps(authorization))
        stage.write_text(json.dumps({'status':'complete', 'sources':dict(sources, extra='b'*64)}))
        changed_evaluation = dict(evaluation, stage_receipt_sha256=delivery.digest(stage))
        with self.assertRaises(RuntimeError):
            delivery.validate_approval(dict(approval, agent_evaluation=changed_evaluation), self.root, stage)

    def test_performance_approval_is_explicit_and_stage_bound(self):
        stage = self.write('stage.json', '{"status":"complete"}')
        compat = self.write('compat.json', '{"status":"complete"}')
        perf = self.write('perf.json', '{"status":"complete"}')
        approval = {'schema':'microproxy.crypto-delivery-approval/v1', 'status':'approved', 'scope':'full',
                    'approved_by':'user', 'decision':'Accept measured throughput and allocation tradeoff',
                    'stage_receipt_sha256':delivery.digest(stage),
                    'compatibility_receipts':[{'path':'compat.json', 'sha256':delivery.digest(compat)}],
                    'performance_receipt':{'path':'perf.json', 'sha256':delivery.digest(perf)}}
        delivery.validate_approval(approval, self.root, stage)
        for change in [{'status':'pending'}, {'stage_receipt_sha256':'0'*64}, {'approved_by':''}, {'performance_receipt':None}]:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                delivery.validate_approval(dict(approval, **change), self.root, stage)


if __name__ == '__main__':
    unittest.main()

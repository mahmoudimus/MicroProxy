import importlib.util
from pathlib import Path
import unittest
import tempfile


def replay_module():
    spec = importlib.util.spec_from_file_location('source_assurance_replay',
                                                 Path(__file__).with_name('replay.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProofDiagnosticsTests(unittest.TestCase):
    def test_replay_and_tool_inputs_cannot_be_dropped(self):
        replay = replay_module()
        sources = {'formal/source/ShakeOwnership.dfy': 'a' * 64}
        pins = {name: 'a' * 64 for name in set(sources) | replay.REPLAY_FILES}
        replay.check_inventory(sources, pins)
        for omitted in pins:
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                replay.check_inventory(sources, {k: v for k, v in pins.items() if k != omitted})
        with self.assertRaises(ValueError):
            replay.check_inventory(sources, {**pins, 'unknown': 'b' * 64})

    def test_pins_reject_changed_and_redirected_source(self):
        replay = replay_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / 'source.dfy'
            source.write_text('module A {}')
            expected = replay.digest(source)
            replay.check_pins(root, {'source.dfy': expected})
            source.write_text('module B {}')
            with self.assertRaises(ValueError):
                replay.check_pins(root, {'source.dfy': expected})
            (root / 'redirect.dfy').symlink_to(source)
            with self.assertRaises(ValueError):
                replay.check_pins(root, {'redirect.dfy': replay.digest(source)})

    def test_positive_requires_nonempty_clean_proof(self):
        replay = replay_module()
        self.assertEqual(replay.proof_result(0,
            'Dafny program verifier finished with 20 verified, 0 errors\n'),
            {'verified': 20, 'errors': 0})
        for status, text in ((0, 'Dafny program verifier did not attempt verification'),
                             (0, 'Dafny program verifier finished with 0 verified, 0 errors'),
                             (4, 'Dafny program verifier finished with 20 verified, 1 error'),
                             (0, 'Dafny program verifier finished with 20 verified, 0 errors\n'
                                 'Error: Verification out of resource')):
            with self.subTest(status=status, text=text), self.assertRaises(ValueError):
                replay.proof_result(status, text)

    def test_negative_requires_named_assertion_and_actual_semantic_failure(self):
        replay = replay_module()
        text = ('control.dfy(10,5): Error: assertion might not hold\n'
                '10 | assert s.lanes == s.scratch;\n'
                'Dafny program verifier finished with 1 verified, 1 error\n')
        self.assertEqual(replay.proof_result(4, text, negative='s.lanes == s.scratch'),
                         {'verified': 1, 'errors': 1})
        for status, altered in ((0, text), (4, text.replace('assertion might not hold', 'parse error')),
                                (4, text + 'Verification out of resource'),
                                (4, text.replace('s.lanes == s.scratch', 'unrelated_condition')),
                                (4, text + '\nInternal error: verifier crashed')):
            with self.subTest(status=status, altered=altered), self.assertRaises(ValueError):
                replay.proof_result(status, altered, negative='s.lanes == s.scratch')


if __name__ == '__main__':
    unittest.main()

import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('vocabulary_replay', Path(__file__).with_name('replay.py'))
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


class ProofGateTests(unittest.TestCase):
    def test_reviewed_positive_count_is_required(self):
        with self.assertRaises(ValueError):
            REPLAY.proof_result(0, 'Dafny program verifier finished with 1 verified, 0 errors\n', expected=29)

    def test_named_control_must_be_the_actual_error(self):
        output = ('Error: unrelated failed assertion\n'
                  'source snippet mentions control-read-role\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_control_cannot_have_unreviewed_extra_obligations(self):
        output = ('Error: control-read-role\n'
                  'Dafny program verifier finished with 3 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_resource_failure_cannot_count_as_control(self):
        output = ('Error: control-read-role\nVerification out of resource\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        with self.assertRaises(ValueError):
            REPLAY.proof_result(4, output, negative='control-read-role')

    def test_exact_assertion_control_is_accepted(self):
        output = ('Control.dfy(8,4): Error: control-read-role\n'
                  'Dafny program verifier finished with 0 verified, 1 error\n')
        self.assertEqual(REPLAY.proof_result(4, output, negative='control-read-role'),
                         {'verified': 0, 'errors': 1})


if __name__ == '__main__':
    unittest.main()

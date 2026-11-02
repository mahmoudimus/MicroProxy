"""Proof controls for the optional large-program certificate emitter.

The production replay must supply Dafny. This standalone test module skips its
integration controls when no prover is installed, like other optional local
tool tests; a skipped test is not proof evidence.
"""
import copy
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

if __package__:
    from . import compact_certificates as compact
else:
    import compact_certificates as compact

HERE = Path(__file__).resolve().parent
DAFNY = os.environ.get('DAFNY') or shutil.which('dafny')
if not DAFNY:
    cached = Path.home() / '.cache/microproxy-formal/dafny-4.9.1-macos-arm64/dafny/dafny'
    DAFNY = str(cached) if cached.is_file() else None
SOLVER = os.environ.get('DAFNY_SOLVER')
if not SOLVER and DAFNY:
    bundled = Path(DAFNY).resolve().parent / 'z3/bin/z3-4.12.1'
    SOLVER = str(bundled) if bundled.is_file() else None


def program():
    # Public guard, with private values kept live through 65 word operations.
    code = [{'type': 'step', 'site': i, 'dst': 3,
             'kind': ('op', 'xor', 0 if i == 0 else 3, 2), 'ann': 'sec'}
            for i in range(65)]
    code += [{'type': 'branch', 'site': 65, 'cond': 1, 'thn': 66, 'els': 67},
             {'type': 'stop', 'ret': 3}, {'type': 'stop', 'ret': 3}]
    return {'code': code, 'registers': 4, 'inputs': 2,
            'roles': {}, 'reg_taints': {0: 'pub', 1: 'pub', 2: 'sec', 3: 'sec'}}


@unittest.skipUnless(DAFNY, 'Dafny unavailable; no proof evidence produced')
class CompactProofTests(unittest.TestCase):
    def verify(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'Control.dfy'
            path.write_text(source.replace('include "SecretTrace.dfy"',
                                           'include "%s"' % (HERE / 'SecretTrace.dfy')))
            command = [DAFNY, 'verify', '--verification-time-limit', '30',
                       '--resource-limit', '50000000', '--solver-option', 'O:smt.case_split=0']
            if SOLVER:
                command += ['--solver-path', SOLVER]
            result = subprocess.run(
                command + [str(path)],
                capture_output=True, text=True, timeout=180)
            return result.returncode, result.stdout + result.stderr

    def assert_proof_reject(self, source):
        status, output = self.verify(source)
        self.assertEqual(4, status, output)
        self.assertRegex(output, r'Error: .*postcondition')
        self.assertNotRegex(output.lower(), r'timed out|out of resource|resolution/type errors|parse errors')

    def test_unrestricted_two_run_for_large_program(self):
        status, output = self.verify(compact.certificate_module('Large', program()))
        self.assertEqual(0, status, output)
        self.assertRegex(output, r'\d+ verified, 0 errors')

    def test_secret_guard_still_fails_structure_proof(self):
        mutated = copy.deepcopy(program())
        mutated['code'][65]['cond'] = 2
        self.assert_proof_reject(compact.certificate_module('SecretGuard', mutated))

    def test_opaque_function_cannot_assert_false_program_fact(self):
        source = compact.certificate_module('FalseContract', program())
        source = re.sub(r'ensures P\(\)\.instructions == \d+',
                        'ensures P().instructions == 1', source)
        self.assert_proof_reject(source)


if __name__ == '__main__':
    unittest.main()

"""A crashed verifier must not qualify as a semantic counterexample."""
import ast
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
RUNNERS = ('codec_sampling_checks.py', 'native_codec_checks.py', 'kem_checks.py',
           'native_kem_checks.py', 'polynomial_checks.py', 'native_polynomial_checks.py')


class ControlExitTests(unittest.TestCase):
    def test_actual_rejection_predicates_require_normal_semantic_exit(self):
        # Evaluate each real runner's rejection predicate with an otherwise valid
        # diagnostic. This reproduces the observed crash-after-diagnostic case
        # without launching a verifier or duplicating its exit-check expression.
        diagnostic = ('Error: a postcondition could not be proved\n'
                      'Dafny program verifier finished with 1 verified, 1 error\n')
        for runner in RUNNERS:
            source = (HERE/runner).read_text()
            candidates = []
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node, ast.If) or not any(
                        isinstance(item, ast.Name) and item.id == 'status' for item in ast.walk(node.test)):
                    continue
                failures = [item for item in node.body if isinstance(item, ast.Raise)]
                if any(re.search(r'semantic|intended proof|counterexample|genuine proof', ast.unparse(item), re.I)
                       for item in failures):
                    candidates.append(node.test)
            self.assertEqual(len(candidates), 1, runner+' rejection gate changed; review its test')
            predicate = compile(ast.Expression(candidates[0]), runner, 'eval')
            for status in (-11, 0, 1, 2, 3, 4, 5, 137):
                with self.subTest(runner=runner, status=status):
                    context = {'status':status, 'output':diagnostic, 'text':diagnostic,
                               'result':diagnostic, 'match':True, 'semantic':True,
                               'bad':('timed out', 'out of resource', 'parse errors', 'Warning:'),
                               'any':any, 're':re}
                    environment = {'__builtins__':{}, **context}
                    rejected = bool(eval(predicate, environment, environment))
                    self.assertEqual(rejected, status != 4)


if __name__ == '__main__':
    unittest.main()

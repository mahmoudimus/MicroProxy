"""The index witness must exercise the mutated lane on a legal input."""
from pathlib import Path
import unittest

import native_polynomial_checks as checks

HERE = Path(__file__).resolve().parent


class NativePolynomialControlTests(unittest.TestCase):
    def mutant(self):
        return checks.absolute_includes((HERE/'NativePolynomial.dfy').read_text()).replace(
            'var t := F.Mul(z,f[i+l]);', 'var t := F.Mul(z,f[i]);', 1)

    def test_sparse_witness_is_legal_and_detects_actual_index_mutation(self):
        source, position, witness = checks.index_control_witness(self.mutant())
        coefficients = [0]*256
        coefficients[witness['nonzero_coefficient']] = witness['value']
        self.assertTrue(all(0 <= value < 3329 for value in coefficients))
        self.assertEqual(witness['stage'], 0)
        self.assertEqual(witness['checked_lane'], 0)
        self.assertEqual((coefficients[0]+1729*coefficients[128]) % 3329, 1729)
        self.assertEqual((coefficients[0]+1729*coefficients[0]) % 3329, 0)
        self.assertNotEqual(witness['expected_lane'], witness['mutant_lane'])
        self.assertIn('var t := F.Mul(z,f[i]);', source)
        self.assertIn('r[i] := F.Add(f[i],t);\n'+source.splitlines()[position-1], source)
        self.assertIn('assert r[i] as int == S.ForwardLane(T.Ints(f),s as int,i as int)',
                      source.splitlines()[position-1])
        original = self.mutant()
        inverse = '  method {:isolate_assertions} InverseStage('
        self.assertEqual(source[source.index(inverse):], original[original.index(inverse):])

    def test_changed_or_ambiguous_body_cannot_silently_move_the_witness(self):
        for source in (self.mutant().replace('r[i] := F.Add(f[i],t);', 'r[i] := 0;', 1),
                       self.mutant().replace('r[i] := F.Add(f[i],t);',
                                            'r[i] := F.Add(f[i],t);\n        r[i] := F.Add(f[i],t);', 1)):
            with self.subTest(source=source[-60:]), self.assertRaises(RuntimeError):
                checks.index_control_witness(source)


if __name__ == '__main__':
    unittest.main()

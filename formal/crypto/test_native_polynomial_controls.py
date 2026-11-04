"""The index witness must exercise the mutated lane on a legal input."""
from pathlib import Path
import unittest

import native_polynomial_checks as checks

HERE = Path(__file__).resolve().parent


class NativePolynomialControlTests(unittest.TestCase):
    def mutant(self):
        return checks.absolute_includes((HERE/'NativePolynomial.dfy').read_text()).replace(
            'var t, ftMul := F.Mul(z,f[i+l]);', 'var t, ftMul := F.Mul(z,f[i]);', 1)

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
        self.assertIn('var t, ftMul := F.Mul(z,f[i]);', source)
        self.assertIn('r[i], ftAdd := F.Add(f[i],t);\n'+source.splitlines()[position-1], source)
        self.assertIn('assert r[i] as int == S.ForwardLane(T.Ints(f),s as int,i as int)',
                      source.splitlines()[position-1])
        original = self.mutant()
        inverse = '  method {:isolate_assertions} InverseStage('
        self.assertEqual(source[source.index(inverse):], original[original.index(inverse):])

    def test_sign_witness_checks_the_actual_right_lane(self):
        original = checks.absolute_includes((HERE/'NativePolynomial.dfy').read_text())
        wrong = original.replace('r[i+l], ftSub := F.Sub(f[i],t);',
                                 'r[i+l], ftSub := F.Add(f[i],t);', 1)
        source, position, witness = checks.sign_control_witness(wrong)
        coefficients = [0]*256
        coefficients[witness['nonzero_coefficient']] = witness['value']
        self.assertEqual(witness['checked_lane'], 128)
        self.assertEqual(witness['expected_lane'], (-1729) % 3329)
        self.assertEqual(witness['mutant_lane'], 1729)
        self.assertTrue(all(0 <= x < 3329 for x in coefficients))
        line = source.splitlines()[position-1]
        self.assertIn('assert r[i+l] as int == S.ForwardLane', line)
        self.assertIn('r[i+l], ftSub := F.Add(f[i],t);\n'+line, source)
        for changed in (wrong.replace('r[i+l], ftSub := F.Add(f[i],t);', '', 1),
                        wrong.replace('r[i+l], ftSub := F.Add(f[i],t);',
                                      'r[i+l], ftSub := F.Add(f[i],t);\n        r[i+l], ftSub := F.Add(f[i],t);', 1)):
            with self.assertRaises(RuntimeError):
                checks.sign_control_witness(changed)

    def test_changed_or_ambiguous_body_cannot_silently_move_the_witness(self):
        for source in (self.mutant().replace('r[i], ftAdd := F.Add(f[i],t);', 'r[i] := 0;', 1),
                       self.mutant().replace('r[i], ftAdd := F.Add(f[i],t);',
                                            'r[i], ftAdd := F.Add(f[i],t);\n        r[i], ftAdd := F.Add(f[i],t);', 1)):
            with self.subTest(source=source[-60:]), self.assertRaises(RuntimeError):
                checks.index_control_witness(source)

    def inverse_mutant(self):
        return checks.absolute_includes((HERE/'NativePolynomial.dfy').read_text()).replace(
            'r[i+l], ftMulSub := F.MulSub(z,f[i+l],f[i]);',
            'r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);', 1)

    def test_inverse_sparse_first_pair_witness_is_legal_and_checks_actual_lane(self):
        source, position, witness = checks.inverse_control_witness(self.inverse_mutant())
        self.assertEqual(witness['stage'], 0)
        self.assertEqual(witness['nonzero_coefficient'], 2)
        self.assertEqual(witness['value'], 1)
        self.assertEqual(witness['other_coefficients'], 0)
        self.assertEqual(witness['checked_lane'], 2)
        self.assertEqual(witness['expected_lane'], 2154)
        self.assertEqual(witness['mutant_lane'], 1175)
        coefficients = [0]*256
        coefficients[witness['nonzero_coefficient']] = witness['value']
        self.assertTrue(all(0 <= value < 3329 for value in coefficients))
        self.assertEqual((2154*(coefficients[2]-coefficients[0])) % 3329, 2154)
        self.assertEqual((2154*(coefficients[0]-coefficients[2])) % 3329, 1175)
        line = source.splitlines()[position-1]
        self.assertIn('assert r[2] as int == S.InverseLane(T.Ints(f),s as int,2)', line)
        self.assertIn('if i == 0 {', line)
        anchor = 'r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);'
        ghost = 'assert ftMulSub == FieldMulSubCallee();'
        self.assertIn(anchor+'\n'+line, source)
        self.assertLess(source.index(line), source.index(ghost, source.index(line)))
        self.assertIn('requires s == 0 && T.Ints(f) == seq(256,i => if i == 2 then 1 else 0)',
                      source)

    def test_inverse_wrong_operand_is_repaired_in_paired_body(self):
        source, position, witness = checks.inverse_control_witness(self.inverse_mutant())
        self.assertIn('F.MulSub(z,f[i],f[i+l])', source)
        correct = source.replace('F.MulSub(z,f[i],f[i+l])',
                                 'F.MulSub(z,f[i+l],f[i])', 1)
        self.assertIn('F.MulSub(z,f[i+l],f[i])', correct)
        self.assertNotIn('F.MulSub(z,f[i],f[i+l])', correct)
        self.assertEqual(correct.count('assert r[2] as int == S.InverseLane'), 1)
        self.assertEqual(source.splitlines()[position-1], correct.splitlines()[position-1])

    def test_inverse_anchor_must_be_unique_and_present(self):
        for source in (self.inverse_mutant().replace(
                           'r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);', '', 1),
                       self.inverse_mutant().replace(
                           'r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);',
                           'r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);\n'
                           '        r[i+l], ftMulSub := F.MulSub(z,f[i],f[i+l]);', 1)):
            with self.subTest(source=source[-80:]), self.assertRaises(RuntimeError):
                checks.inverse_control_witness(source)


if __name__ == '__main__':
    unittest.main()

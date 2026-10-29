import unittest
from lowering import lower


class BoundedShifts(unittest.TestCase):
    def source(self, right='count', left='count'):
        return ('import PacketSpec.*;\npublic class __default { '
                'public static long ShiftRight(long value,long count){return '
                'dafny.Helpers.bv64ShiftRight(value, ((byte) '+right+'));}\n'
                'public static long ShiftLeft(long value,long count){return '
                'dafny.Helpers.bv64ShiftLeft(value, ((byte) '+left+'));} }')

    def test_only_two_contract_bound_intrinsics_are_lowered(self):
        result = lower(self.source())
        self.assertIn('(value >>> ((byte) count))', result)
        self.assertIn('(value << ((byte) count))', result)
        self.assertNotIn('dafny.', result)
        self.assertNotIn('import PacketSpec', result)

    def test_adding_a_shift_outside_the_verified_helpers_is_rejected(self):
        with self.assertRaises(RuntimeError):
            lower(self.source() + 'dafny.Helpers.bv64ShiftRight(a,b)')

    def test_changing_helper_arguments_requires_review(self):
        with self.assertRaises(RuntimeError):
            lower(self.source(right='64'))

    def test_backend_parenthesized_count_keeps_exact_expression(self):
        result = lower(self.source(right='(count)', left='(count)'))
        self.assertIn('(value >>> ((byte) (count)))', result)

    def test_unexpected_runtime_calls_are_rejected(self):
        with self.assertRaises(RuntimeError):
            lower(self.source() + 'dafny.Helpers.unknown()')

    def test_real_reference_to_erased_spec_module_is_rejected(self):
        with self.assertRaises(RuntimeError):
            lower(self.source() + 'PacketSpec.__default.Sign()')


if __name__ == '__main__':
    unittest.main()

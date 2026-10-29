import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import bytecode_guard as guard

JDK = Path(os.environ.get('JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))


class BytecodePolicy(unittest.TestCase):
    def inspect(self, body):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        source = root / 'Fixture.java'
        source.write_text('public class Fixture { ' + body + ' }')
        subprocess.run([str(JDK / 'bin/javac'), '--release', '21', '-d', str(root), str(source)], check=True, capture_output=True)
        return guard.disassemble(JDK / 'bin/javap', root, 'Fixture')

    def test_actual_scalar_class_expands_helper_calls(self):
        methods = self.inspect('public static long helper(long a,long b){return (a-b)>>>63;} '
                               'public static long run(long a,long b){return helper(a,b)^1L;}')
        result = guard.flatten(methods, 'run')
        self.assertEqual(2, result['inputs'])
        self.assertGreater(len(result['nodes']), 4)
        self.assertIn('lushr', result['opcodes'])
        for i, (kind, a, b, literal) in enumerate(result['nodes']):
            if kind == 1:
                self.assertLess(a, result['inputs'])
            elif kind >= 2:
                self.assertLess(a, i)
                self.assertLess(b, i)

    def test_secret_branch_is_rejected(self):
        methods = self.inspect('public static long run(long a){return a==0?1L:2L;}')
        with self.assertRaisesRegex(RuntimeError, 'opcode'):
            guard.flatten(methods, 'run')

    def test_secret_memory_lookup_is_rejected(self):
        methods = self.inspect('public static long run(long a){long[] table={1,2};return table[(int)a];}')
        with self.assertRaisesRegex(RuntimeError, 'opcode'):
            guard.flatten(methods, 'run')

    def test_division_is_outside_atomic_word_policy(self):
        methods = self.inspect('public static long run(long a,long b){return a/b;}')
        with self.assertRaisesRegex(RuntimeError, 'opcode'):
            guard.flatten(methods, 'run')

    def test_unexpected_library_calls_are_rejected(self):
        methods = self.inspect('public static long run(long a){return Math.abs(a);}')
        with self.assertRaisesRegex(RuntimeError, 'call'):
            guard.flatten(methods, 'run')

    def test_recursive_helper_cannot_hide_a_loop(self):
        methods = self.inspect('public static long run(long a){return run(a);} ')
        with self.assertRaisesRegex(RuntimeError, 'recurs'):
            guard.flatten(methods, 'run')

    def test_class_initializer_is_rejected(self):
        methods = self.inspect('static long x=System.nanoTime(); public static long run(long a){return a;}')
        with self.assertRaisesRegex(RuntimeError, 'initializer'):
            guard.flatten(methods, 'run')

    def test_missing_target_is_rejected(self):
        with self.assertRaises(RuntimeError):
            guard.flatten({}, 'missing')

    def test_implicit_synchronized_monitor_is_rejected(self):
        methods = self.inspect('public static synchronized long run(long a){return a;}')
        with self.assertRaisesRegex(RuntimeError, 'synchronized'):
            guard.flatten(methods, 'run')

    def test_unused_object_descriptor_is_not_a_method_header(self):
        methods = self.inspect('public Fixture other(){return this;} public static long run(long a){return a;}')
        self.assertEqual(1, guard.flatten(methods, 'run')['inputs'])


if __name__ == '__main__':
    unittest.main()

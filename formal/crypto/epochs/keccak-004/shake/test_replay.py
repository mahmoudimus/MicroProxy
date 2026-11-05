"""Admission/control regressions; fixtures are materialized only in temporary private outputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
import argparse
import os
import subprocess
import py_compile
import re

sys.dont_write_bytecode = True
JAVA_HOME = Path(os.environ['JAVA_HOME']).resolve(strict=True) if os.environ.get('JAVA_HOME') else None

SPEC = importlib.util.spec_from_file_location('current_shake_replay', Path(__file__).with_name('replay.py'))
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class ReplayBoundaryTests(unittest.TestCase):
    def configured_java_home(self):
        if JAVA_HOME is None:
            self.skipTest('Java integration prerequisite: set JAVA_HOME or run test_replay.py --java-home /absolute/jdk/home')
        self.assertTrue((JAVA_HOME / 'bin/javac').is_file(), 'Java integration prerequisite: selected JDK lacks bin/javac')
        version = re.search(r'^JAVA_VERSION="(\d+)', (JAVA_HOME / 'release').read_text(), re.M)
        if not version or int(version[1]) < 21:
            self.skipTest('Java integration prerequisite: select JDK 21 or newer explicitly; inherited JAVA_HOME is older')
        return JAVA_HOME

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.child_home = self.root / 'child-home'
        self.child_temp = self.root / 'child-temp'
        self.child_home.mkdir()
        self.child_temp.mkdir()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def test_wrong_external_digest_rejected_before_declared_input_is_used(self):
        path = self.write('authority.json', '{"arbitrary": "data"}')
        with self.assertRaisesRegex(ValueError, 'digest'):
            replay.authenticated_json(path, '0' * 64)

    def test_duplicate_authority_keys_rejected_even_with_matching_digest(self):
        path = self.write('authority.json', '{"scope": "good", "scope": "bad"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            replay.authenticated_json(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_complete_recursive_include_graph_has_no_unmapped_escape(self):
        a = self.write('formal/a.dfy', 'include "sub/b.dfy"\nmodule A {}\n')
        b = self.write('formal/sub/b.dfy', 'include "../c.dfy"\nmodule B {}\n')
        c = self.write('formal/c.dfy', 'module C {}\n')
        pins = {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (a, b, c)}
        self.assertEqual(sorted(pins), replay.include_closure(self.root, pins, 'formal/a.dfy'))
        b.write_text('include "../../escape.dfy"\nmodule B {}\n')
        pins['formal/sub/b.dfy'] = hashlib.sha256(b.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            replay.include_closure(self.root, pins, 'formal/a.dfy')

    def test_unsupported_include_syntax_is_not_silently_ignored(self):
        p = self.write('formal/a.dfy', 'include opened "b.dfy"\n')
        with self.assertRaisesRegex(ValueError, 'include syntax'):
            replay.include_closure(self.root, {'formal/a.dfy': hashlib.sha256(p.read_bytes()).hexdigest()}, 'formal/a.dfy')

    def test_changed_source_bytes_rejected_before_parser(self):
        self.write('formal/a.dfy', 'module Changed {}\n')
        with self.assertRaisesRegex(ValueError, 'hash'):
            replay.include_closure(self.root, {'formal/a.dfy': '0' * 64}, 'formal/a.dfy')

    def test_wrong_semantic_location_cannot_substitute_for_intended_failure(self):
        output = 'formal/crypto/NativeShake.dfy(156,20): Error: a postcondition could not be proved on this return path\n'
        errors = replay.error_locations(output)
        self.assertEqual([{'file': 'formal/crypto/NativeShake.dfy', 'line': 156, 'column': 20,
                           'message': 'a postcondition could not be proved on this return path'}], errors)
        with self.assertRaisesRegex(ValueError, 'locations'):
            replay.require_errors(output, [dict(errors[0], line=157)])

    def test_duplicate_semantic_errors_are_preserved_for_domain_slices(self):
        line = 'formal/crypto/native_shake_domain.dfy(62,15): Error: a precondition for this call could not be proved\n'
        self.assertEqual(2, len(replay.error_locations(line + line)))
        with self.assertRaisesRegex(ValueError, 'locations'):
            replay.require_errors(line + line, replay.error_locations(line))

    def test_output_cannot_overlap_any_selected_input(self):
        protected = self.root / 'source'
        protected.mkdir()
        with self.assertRaisesRegex(ValueError, 'overlap'):
            replay.output_admission(protected / 'output', [protected])
        out = self.root / 'output'
        replay.output_admission(out, [protected])
        out.mkdir()
        with self.assertRaisesRegex(ValueError, 'exists'):
            replay.output_admission(out, [protected])

    def test_symlink_input_cannot_alias_a_selected_source(self):
        p = self.write('source.dfy', 'module A {}\n')
        (self.root / 'alias.dfy').symlink_to(p)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            replay.file_bytes(self.root / 'alias.dfy')

    def test_hardlink_input_cannot_alias_a_selected_source(self):
        p = self.write('source.dfy', 'module A {}\n')
        (self.root / 'alias.dfy').hardlink_to(p)
        with self.assertRaisesRegex(ValueError, 'unaliased'):
            replay.file_bytes(p)

    def test_ambient_javac_option_cannot_inject_an_unmapped_compiler_input(self):
        source = self.write('CompilerPoisonProbe.java', 'final class CompilerPoisonProbe {}\n')
        poisoned = dict(os.environ, JDK_JAVAC_OPTIONS='--unmapped-compiler-input=poison')
        javac = self.configured_java_home() / 'bin/javac'
        command = [str(javac), '--release', '21', '-d', str(self.root / 'classes'), str(source)]
        unsafe = subprocess.run(command, env=poisoned, capture_output=True, text=True)
        self.assertNotEqual(0, unsafe.returncode, 'the real compiler must observe the poison before sanitizing')
        self.assertIn('--unmapped-compiler-input=poison', unsafe.stderr)
        safe = subprocess.run(command, env=replay.child_environment(poisoned, self.child_home, self.child_temp),
                              capture_output=True, text=True)
        self.assertEqual(0, safe.returncode, safe.stdout + safe.stderr)
        self.assertTrue((self.root / 'classes/CompilerPoisonProbe.class').is_file())

    def test_unpinned_bytecode_cache_cannot_override_authenticated_helper_source(self):
        source = self.write('cached_helper.py', 'VALUE = 2\n')
        original = source.stat()
        py_compile.compile(str(source), doraise=True)
        source.write_text('VALUE = 1\n')
        os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        module = replay.load('cache_poison_probe', source, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(1, module.VALUE, 'loader must execute the selected source bytes, not an unpinned cache')

    def test_executable_bytes_must_match_selected_pin_at_the_load_boundary(self):
        source = self.write('changed_helper.py', 'raise AssertionError("unselected code executed")\n')
        with self.assertRaisesRegex(ValueError, 'executable.*digest'):
            replay.load('changed_helper_probe', source, '0' * 64)

    def test_unrecognized_ambient_selector_cannot_reach_a_pinned_child(self):
        poisoned = {'HOME': str(self.root), 'TMPDIR': str(self.root), 'LANG': 'C', 'TZ': 'UTC',
                    'PATH': '/unmapped/toolchain', 'JDK_ALTERNATE_VM': '/unmapped/vm',
                    'LD_PRELOAD': '/unmapped/loader.so', 'DYLD_LIBRARY_PATH': '/unmapped/library',
                    'UNREVIEWED_EXECUTOR_OPTION': 'poison'}
        child = subprocess.run(['/usr/bin/env'], env=replay.child_environment(poisoned, self.child_home, self.child_temp),
                               capture_output=True, text=True, check=True)
        observed = dict(line.split('=', 1) for line in child.stdout.splitlines())
        self.assertEqual({'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'TZ', 'PATH'}, set(observed))
        self.assertEqual('/usr/bin:/bin:/usr/sbin:/sbin', observed['PATH'])
        self.assertEqual(str(self.child_home), observed['HOME'])
        self.assertEqual(str(self.child_temp), observed['TMPDIR'])

    def test_real_jvm_tools_use_private_home_and_temp_properties(self):
        java_home = self.configured_java_home()
        env = replay.child_environment(os.environ, self.child_home, self.child_temp)
        for tool in ('java', 'javac', 'javap'):
            options = ['-XshowSettings:properties' if tool == 'java' else '-J-XshowSettings:properties', '-version']
            command = replay.java_command(java_home, tool, self.child_home, self.child_temp, options)
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            properties = dict(re.findall(r'^\s*(user.home|java.io.tmpdir) = (.+)$', result.stderr, re.M))
            self.assertEqual(str(self.child_home), properties['user.home'], tool)
            self.assertEqual(str(self.child_temp), properties['java.io.tmpdir'], tool)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--java-home', type=Path, default=JAVA_HOME, required=JAVA_HOME is None)
    options, remaining = parser.parse_known_args()
    JAVA_HOME = options.java_home.resolve(strict=True)
    version = re.search(r'^JAVA_VERSION="(\d+)', (JAVA_HOME / 'release').read_text(), re.M)
    if not version or int(version[1]) < 21:
        parser.error('--java-home/JAVA_HOME must select JDK 21 or newer for the real Java integration probes')
    unittest.main(argv=[sys.argv[0], *remaining])

"""Adversarial artifact fixtures; these do not claim the stub classes implement crypto."""
import os
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest
import warnings
from zipfile import ZipFile

import bundle_checks as bundle
import delivery

JDK = Path(os.environ.get('MICROPROXY_JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
RUNTIME = Path.home() / '.m2/repository/org/dafny/DafnyRuntime/4.9.1/DafnyRuntime-4.9.1.jar'


@unittest.skipUnless((JDK/'bin/javac').exists() and RUNTIME.is_file(), 'explicit JDK and pinned Maven runtime unavailable')
class BundleArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix='crypto-bundle-fixture-')
        cls.base = Path(cls.workspace.name)
        cls.classes = cls.base / 'classes'
        sources = []
        for name in sorted(bundle.REQUIRED_ROOTS | {"io/github/mahmoudimus/quic/FixtureExtra.class"}):
            path = cls.base / ('src/' + name.removesuffix('.class') + '.java')
            path.parent.mkdir(parents=True, exist_ok=True)
            package, owner = name.removesuffix('.class').rsplit('/', 1)
            path.write_text('package ' + package.replace('/', '.') + '; public class ' + owner + ' {}')
            sources.append(path)
        subprocess.run([str(JDK/'bin/javac'), '--release', '21', '-d', str(cls.classes), *map(str, sources)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix='crypto-bundle-check-')
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.library, self.bundle = self.root/'library.jar', self.root/'bundle.jar'
        self.entries = {name: (self.classes/name).read_bytes() for name in bundle.REQUIRED_ROOTS | {'io/github/mahmoudimus/quic/FixtureExtra.class'}}
        resources = {name: (delivery.ROOT/'quic/src/main/resources'/name).read_bytes() for name in bundle.RESOURCES}
        self.write_jar(self.library, {**self.entries, **resources})
        with ZipFile(RUNTIME) as jar:
            runtime = {n: jar.read(n) for n in ['dafny/Helpers.class', 'dafny/TypeDescriptor.class', 'dafny/DafnySequence.class']}
        self.bundle_entries = {**self.entries, **resources, **runtime}
        self.write_jar(self.bundle, self.bundle_entries)
        self.receipt = {'status': 'checked', 'class_count': len(self.entries),
                        'classes': {n: delivery.digest(self.classes/n) for n in self.entries},
                        'jar_sha256': delivery.digest(self.library),
                        'stage_receipt_sha256': 'a'*64, 'generated_class_count': 2,
                        'handwritten_sources': 6, 'handwritten_lint': ['-Xlint:all,-serial'],
                        'existing_generated_sources': {'fixture.java': 'b'*64},
                        'comparison': 'exact class bytes including all debug attributes'}
        self.canonical = deepcopy({k: v for k, v in self.receipt.items() if k not in ('status', 'jar_sha256', 'class_count')})

    @staticmethod
    def write_jar(path, entries):
        with ZipFile(path, 'w') as jar:
            for name, value in entries.items():
                jar.writestr(name, value)

    def inspect(self):
        return bundle.inspect(self.library, self.bundle, self.receipt, RUNTIME, self.canonical)

    def test_complete_matching_artifacts_pass(self):
        self.assertEqual(set(self.inspect()['crypto_classes']), bundle.REQUIRED_ROOTS)

    def test_duplicate_class_entries_fail(self):
        name = next(iter(self.entries))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with ZipFile(self.bundle, 'a') as jar:
                jar.writestr(name, self.entries[name])
        with self.assertRaisesRegex(RuntimeError, 'Duplicate JAR'):
            self.inspect()

    def test_multi_release_crypto_and_runtime_overrides_fail(self):
        for owner in [next(iter(self.entries)), 'dafny/Helpers.class']:
            self.write_jar(self.bundle, {**self.bundle_entries,
                'META-INF/versions/21/' + owner: self.bundle_entries[owner]})
            with self.subTest(owner=owner), self.assertRaisesRegex(RuntimeError, 'multi-release'):
                self.inspect()

    def test_missing_and_changed_crypto_class_fail(self):
        name = next(iter(self.entries))
        for value in (None, self.entries[name][:-1] + bytes([self.entries[name][-1] ^ 1])):
            entries = dict(self.bundle_entries)
            if value is None:
                del entries[name]
            else:
                entries[name] = value
            self.write_jar(self.bundle, entries)
            with self.subTest(missing=value is None), self.assertRaises(RuntimeError):
                self.inspect()

    def test_notice_and_runtime_changes_fail(self):
        for name in ['META-INF/NOTICE-crypto.txt', 'dafny/Helpers.class']:
            entries = dict(self.bundle_entries)
            entries[name] = entries[name][:-1] + bytes([entries[name][-1] ^ 1])
            self.write_jar(self.bundle, entries)
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.inspect()

    def test_stale_or_incomplete_delivery_receipt_fails(self):
        for key, value in [('status', 'incomplete'), ('class_count', True), ('jar_sha256', 'a'*64), ('classes', {})]:
            original = self.receipt
            self.receipt = {**original, key: value}
            try:
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    self.inspect()
            finally:
                self.receipt = original

    def test_dropped_canonical_library_entries_fail(self):
        name = next(iter(self.entries))
        del self.receipt['classes'][name]
        self.receipt['class_count'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'canonical'):
            self.inspect()

    def test_self_consistent_truncated_library_and_receipt_fail(self):
        name = 'io/github/mahmoudimus/quic/FixtureExtra.class'
        with ZipFile(self.library) as jar:
            entries = {n: jar.read(n) for n in jar.namelist() if n != name}
        self.write_jar(self.library, entries)
        self.receipt['classes'] = {n:h for n,h in self.receipt['classes'].items() if n != name}
        self.receipt['class_count'] -= 1
        self.receipt['jar_sha256'] = delivery.digest(self.library)
        with self.assertRaisesRegex(RuntimeError, 'canonical'):
            self.inspect()

    def test_stage_binding_and_delivery_metadata_fail(self):
        for key, value in [('stage_receipt_sha256', 'c'*64), ('generated_class_count', 0),
                           ('handwritten_sources', 0), ('existing_generated_sources', {}),
                           ('comparison', 'self-hash')]:
            original = self.receipt
            self.receipt = {**original, key: value}
            try:
                with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'canonical'):
                    self.inspect()
            finally:
                self.receipt = original

    def test_non_crypto_multi_release_override_fails(self):
        owner = 'io/github/mahmoudimus/quic/tls/TlsSession.class'
        self.write_jar(self.bundle, {**self.bundle_entries,
            'META-INF/MANIFEST.MF': b'Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n',
            'META-INF/versions/21/' + owner: next(iter(self.entries.values()))})
        with self.assertRaisesRegex(RuntimeError, 'multi-release'):
            self.inspect()

    def test_load_origins_include_non_crypto_and_lambda_hosts(self):
        owner = 'io.github.mahmoudimus.quic.internal.verifiedhkdf.VerifiedHkdf.__default'
        log = ('[0s][info][class,load] dafny.Helpers source: ' + self.bundle.as_uri() + '\n'
               '[0s][info][class,load] ' + owner + ' source: ' + self.bundle.as_uri() + '\n')
        base = bundle.assert_load_origins(log, self.bundle, {}, {})
        self.assertIn(owner, base)
        derived = log + '[0s][info][class,load] ' + owner + '$$Lambda/0x123 source: ' + owner + '\n'
        self.assertIn(owner + '$$Lambda/0x123', bundle.assert_load_origins(derived, self.bundle, {}, {}))
        derived = log + '[0s][info][class,load] ' + owner + '$$TypeSwitch/0x123 source: ' + owner + '\n'
        self.assertIn(owner + '$$TypeSwitch/0x123', bundle.assert_load_origins(derived, self.bundle, {}, {}))
        for bad in [
            '[0s][info][class,load] io.github.mahmoudimus.quic.tls.TlsSession source: file:/unexpected.jar\n',
            '[0s][info][class,load] ' + owner + '$$Lambda/0x123 source: unknown.Host\n',
        ]:
            with self.subTest(bad=bad), self.assertRaisesRegex(RuntimeError, 'class-load origin'):
                bundle.assert_load_origins(log + bad, self.bundle, {}, {})

    def test_ordinary_retained_library_class_replacement_fails(self):
        name = 'io/github/mahmoudimus/quic/FixtureExtra.class'
        changed = dict(self.bundle_entries)
        changed[name] = changed[name][:-1] + bytes([changed[name][-1] ^ 1])
        self.write_jar(self.bundle, changed)
        with self.assertRaisesRegex(RuntimeError, 'retained library'):
            self.inspect()


if __name__ == '__main__':
    unittest.main()

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
        # FixtureExtra is optional; every required crypto root must be rejected.
        for name in sorted(bundle.REQUIRED_ROOTS):
            for value in (None, self.entries[name][:-1] + bytes([self.entries[name][-1] ^ 1])):
                entries = dict(self.bundle_entries)
                if value is None:
                    del entries[name]
                else:
                    entries[name] = value
                self.write_jar(self.bundle, entries)
                with self.subTest(name=name, missing=value is None), self.assertRaises(RuntimeError):
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


class NonceSmokeTests(unittest.TestCase):
    """Fail-closed regressions for the separate executed nonce bundle smoke."""

    ORIGINS = {
        'PacketKey': '/fixture/bundle.jar',
        'VerifiedNonce': '/fixture/bundle.jar',
        'DafnyRuntime': '/fixture/bundle.jar',
        'harness': '/fixture/nonce-harness',
    }

    def summary(self, **changes):
        detail = [{'suite': suite, 'packet_number': pn, 'nonce': '00' * 12,
                   'ciphertext_sha256': 'a' * 64}
                  for suite in bundle.NONCE_SMOKE_SUITES for pn in (0, 1, -1)]
        value = {'schema': bundle.NONCE_SMOKE_SCHEMA, 'cases': 9, 'passed': 9,
                 'origins': dict(self.ORIGINS), 'cases_detail': detail}
        value.update(changes)
        return value

    def test_valid_executed_summary_passes(self):
        self.assertEqual(bundle.check_nonce_smoke_summary(self.summary(), self.ORIGINS),
                         {'cases': 9, 'passed': 9, 'origins': self.ORIGINS,
                          'cases_detail': self.summary()['cases_detail']})

    def test_missing_short_duplicate_and_unknown_cases_fail(self):
        cases = []
        cases.append(('cases', 8, 'did not execute all 9'))
        cases.append(('passed', 8, 'did not execute all 9'))
        bad = self.summary()
        bad['cases_detail'] = bad['cases_detail'][:-1]
        cases.append(('detail-short', bad['cases_detail'], 'case inventory changed'))
        bad = self.summary()
        bad['cases_detail'] = bad['cases_detail'][:-1] + [bad['cases_detail'][0]]
        cases.append(('duplicate', bad['cases_detail'], 'Duplicate nonce smoke case'))
        bad = self.summary()
        bad['cases_detail'][0] = dict(bad['cases_detail'][0], suite='TLS_UNKNOWN')
        cases.append(('unknown-suite', bad['cases_detail'], 'Unexpected nonce smoke case'))
        for name, value, pattern in cases:
            with self.subTest(name=name):
                summary = self.summary()
                if name in ('cases', 'passed'):
                    summary[name] = value
                else:
                    summary['cases_detail'] = value
                with self.assertRaisesRegex(RuntimeError, pattern):
                    bundle.check_nonce_smoke_summary(summary, self.ORIGINS)

    def test_wrong_origins_nonce_and_ciphertext_digest_fail(self):
        for origins in ({**self.ORIGINS, 'VerifiedNonce': '/elsewhere/nonce.jar'},
                        {**self.ORIGINS, 'DafnyRuntime': '/elsewhere/runtime.jar'},
                        {**self.ORIGINS, 'harness': self.ORIGINS['PacketKey']}):
            with self.assertRaisesRegex(RuntimeError, 'origins differ'):
                bundle.check_nonce_smoke_summary(self.summary(), origins)
        for field, value, pattern in (
                ('nonce', 'not-a-nonce', 'Malformed nonce smoke nonce'),
                ('ciphertext_sha256', 'x' * 64, 'Malformed nonce smoke ciphertext')):
            summary = self.summary()
            summary['cases_detail'][0] = dict(summary['cases_detail'][0], **{field: value})
            with self.assertRaisesRegex(RuntimeError, pattern):
                bundle.check_nonce_smoke_summary(summary, self.ORIGINS)

    def test_classload_requires_all_executed_classes_from_the_actual_bundle(self):
        harness = Path('/fixture/nonce-harness')
        bundle_path = Path('/fixture/bundle.jar')
        lines = {
            'io.github.mahmoudimus.quic.crypto.PacketKey': bundle_path,
            'io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default': bundle_path,
            'nonceadoption.BundleNonceSmoke': harness,
            'dafny.Helpers': bundle_path,
        }

        def log(overrides=None):
            entries = dict(lines, **(overrides or {}))
            return ''.join('[0s][info][class,load] ' + owner + ' source: ' + source.as_uri() + '\n'
                           for owner, source in entries.items())

        loaded = bundle.assert_nonce_smoke_origins(log(), bundle_path, harness)
        self.assertEqual(set(loaded), set(lines))
        # Loaded values are normalized plain real paths, not file: URLs, so the
        # parent consumer can compare them directly with the summary origins.
        for owner, value in loaded.items():
            self.assertFalse(value.startswith('file:'), owner)
            self.assertEqual(value, str(lines[owner].resolve()))
        missing = {k: v for k, v in lines.items() if 'verifiednonce' not in k}
        with self.assertRaisesRegex(RuntimeError, 'did not actually execute/load'):
            bundle.assert_nonce_smoke_origins(
                ''.join('[0s][info][class,load] ' + owner + ' source: ' + source.as_uri() + '\n'
                        for owner, source in missing.items()), bundle_path, harness)
        with self.assertRaisesRegex(RuntimeError, 'Unexpected nonce smoke class-load origin'):
            bundle.assert_nonce_smoke_origins(
                log({'io.github.mahmoudimus.quic.crypto.PacketKey': Path('/elsewhere/bundle.jar')}),
                bundle_path, harness)
        # External runtime fallback: dafny.Helpers must not come from a separate jar.
        with self.assertRaisesRegex(RuntimeError, 'Unexpected nonce smoke class-load origin'):
            bundle.assert_nonce_smoke_origins(
                log({'dafny.Helpers': Path('/fixture/runtime.jar')}), bundle_path, harness)


if __name__ == '__main__':
    unittest.main()

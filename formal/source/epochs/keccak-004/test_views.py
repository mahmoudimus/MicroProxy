#!/usr/bin/env python3
"""Exercise the real constructor on an explicitly supplied authenticated seed."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ViewsTests(unittest.TestCase):
    def setUp(self):
        self.work = self.work_root / self.id().split('.')[-1]
        self.work.mkdir()
        self.candidate = self.work / 'candidate'
        shutil.copytree(self.seed, self.candidate)
        self.epoch = self.work / 'epoch'
        self.epoch.mkdir()
        shutil.copy2(self.manifest, self.epoch / 'manifest.json')
        shutil.copytree(self.manifest.parent / 'predecessor', self.epoch / 'predecessor')
        self.mpath = self.epoch / 'manifest.json'
        self.expected = self.expected_sha
        self.output = self.work / 'output'

    def edit(self, rel, data=b'// changed\n'):
        path = self.candidate / rel
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + data)

    def alter_manifest(self, change):
        data = json.loads(self.mpath.read_text())
        change(data)
        self.mpath.write_text(json.dumps(data, sort_keys=True) + '\n')
        self.expected = sha(self.mpath)  # Deliberately authorize schema probes only.

    def build(self, **kwargs):
        arguments = dict(candidate_root=self.candidate, manifest=self.mpath,
                         expected_manifest_sha256=self.expected, output=self.output)
        arguments.update(kwargs)
        return self.api.build_views(**arguments)

    def rejected(self, **kwargs):
        with self.assertRaises(self.api.ViewError):
            self.build(**kwargs)
        self.assertFalse(self.output.exists())

    def test_exact_three_diff_creates_both_views(self):
        result = self.build()
        self.assertEqual(result['status'], 'complete')
        self.assertFalse(result['qualification'])
        self.assertEqual(result['scope'], 'source-views-only')
        self.assertEqual(result['legacy_select']['dafny_files'], 85)
        self.assertEqual(result['legacy_select']['package_files'], 311)
        self.assertEqual(result['legacy_select']['used_inputs'], 8)
        self.assertEqual(result['views']['current']['source_map_sha256'], self.api.CURRENT_MAP_SHA256)
        self.assertEqual(result['views']['historical']['source_map_sha256'], self.api.PREDECESSOR_MAP_SHA256)
        for name in ('current', 'historical'):
            root = self.output / name
            self.assertFalse((root / 'formal/source/NativeKeccakTraceHarness.dfy').exists())
            self.assertTrue((root / self.api.HARNESS_TEMPLATE).is_file())
            self.assertEqual(len(result['views'][name]['sources']), 85)
        self.assertEqual(set(result['changed_sources']), set(self.api.CHANGES))
        self.assertEqual(result['historical_consumer_scope'], 'historical-only; no current-source admission')

    def test_constructor_requires_explicit_external_digest(self):
        with self.assertRaises(TypeError):
            self.api.build_views(candidate_root=self.candidate, manifest=self.mpath, output=self.output)

    def test_cli_requires_explicit_external_digest(self):
        p = subprocess.run([sys.executable, '-B', str(HERE / 'views.py'),
                            '--manifest', str(self.mpath), '--candidate-root', str(self.candidate),
                            '--output', str(self.output)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn('--expected-manifest-sha256', p.stderr)
        self.assertFalse(self.output.exists())

    def test_missing_source(self):
        (self.candidate / 'formal/crypto/NativeTypes.dfy').unlink()
        self.rejected()

    def test_extra_source(self):
        (self.candidate / 'formal/extra.dfy').write_text('module Extra {}')
        self.rejected()

    def test_extra_live_paired_harness(self):
        shutil.copy2(self.candidate / self.api.HARNESS_TEMPLATE,
                     self.candidate / 'formal/source/NativeKeccakTraceHarness.dfy')
        self.rejected()

    def test_fourth_source_change(self):
        self.edit('formal/crypto/NativeTypes.dfy')
        self.rejected()

    def test_stale_predecessor_root_substitution(self):
        for rel in self.api.CHANGES:
            (self.candidate / rel).write_bytes((self.epoch / 'predecessor' / (Path(rel).name + '.in')).read_bytes())
        self.rejected()

    def test_changed_predecessor_snapshot(self):
        path = self.epoch / 'predecessor/NativeKeccak.dfy.in'
        path.write_bytes(path.read_bytes() + b'// changed\n')
        self.rejected()

    def test_extra_predecessor_snapshot(self):
        (self.epoch / 'predecessor/Fourth.dfy.in').write_text('module Fourth {}')
        self.rejected()

    def test_changed_package(self):
        self.edit('formal/source/select/package.json', b' ')
        self.rejected()

    def test_extra_package_file(self):
        (self.candidate / 'formal/source/select/extra.txt').write_text('extra')
        self.rejected()

    def test_changed_profile(self):
        self.edit('formal/source/select/profiles/linux-sdk10.0.400.json', b' ')
        self.rejected()

    def test_changed_helper(self):
        self.edit('formal/dafny/toolchain.py', b'\n# changed\n')
        self.rejected()

    def test_changed_legacy_manifest(self):
        self.edit('assurance/shake-api/inputs.json', b' ')
        self.rejected()

    def test_changed_legacy_validator(self):
        self.edit('scripts/security/check_select_source.py', b'\n# changed\n')
        self.rejected()

    def test_changed_current_checker(self):
        self.edit('formal/source/keccak/method-checker/KeccakMethodCoverage.cs')
        self.rejected()

    def test_changed_current_project(self):
        self.edit('formal/source/keccak/function-checker/KeccakFunctionCoverage.csproj')
        self.rejected()

    def test_changed_current_runner(self):
        self.edit('formal/source/keccak/coverage_replay.py', b'\n# changed\n')
        self.rejected()

    def test_missing_build_authority_helper(self):
        (self.candidate / 'formal/source/keccak/encoder/build_authority.py').unlink()
        self.rejected()

    def test_changed_build_authority_helper(self):
        self.edit('formal/source/keccak/encoder/build_authority.py', b'\n# changed\n')
        self.rejected()

    def test_missing_targeting_pack_catalog(self):
        (self.candidate / 'formal/source/keccak/encoder/net6-targeting-packs.json').unlink()
        self.rejected()

    def test_changed_targeting_pack_catalog(self):
        self.edit('formal/source/keccak/encoder/net6-targeting-packs.json', b' ')
        self.rejected()

    def test_manifest_omits_build_authority_helper(self):
        self.alter_manifest(lambda d: d['current_tooling'].pop(
            'formal/source/keccak/encoder/build_authority.py'))
        self.rejected()

    def test_manifest_omits_targeting_pack_catalog(self):
        self.alter_manifest(lambda d: d['current_tooling'].pop(
            'formal/source/keccak/encoder/net6-targeting-packs.json'))
        self.rejected()

    def test_old_six_file_tooling_schema_rejected(self):
        def omit_authority(d):
            for name in ('build_authority.py', 'net6-targeting-packs.json'):
                d['current_tooling'].pop('formal/source/keccak/encoder/' + name)
        self.alter_manifest(omit_authority)
        self.rejected()

    def test_changed_paired_template(self):
        self.edit(self.api.HARNESS_TEMPLATE)
        self.rejected()

    def test_manifest_digest_substitution(self):
        self.mpath.write_bytes(self.mpath.read_bytes() + b' ')
        self.rejected()

    def test_invalid_expected_digest(self):
        self.rejected(expected_manifest_sha256='not-a-digest')

    def test_unknown_manifest_key_even_with_authorized_digest(self):
        self.alter_manifest(lambda d: d.update(success=True))
        self.rejected()

    def test_missing_manifest_key_even_with_authorized_digest(self):
        self.alter_manifest(lambda d: d.pop('scope'))
        self.rejected()

    def test_duplicate_json_key(self):
        raw = self.mpath.read_text().rstrip()
        self.mpath.write_text(raw[:-1] + ',"epoch":"keccak-004"}\n')
        self.expected = sha(self.mpath)
        self.rejected()

    def test_fixed_source_map_rejects_authorized_fourth_difference(self):
        def change(d):
            d['current']['sources']['formal/crypto/NativeTypes.dfy'] = '0' * 64
            d['current']['map_sha256'] = self.api.map_sha(d['current']['sources'])
        self.alter_manifest(change)
        self.rejected()

    def test_support_cannot_overlap_source_domain(self):
        self.alter_manifest(lambda d: d['support_inputs'].update(
            {'formal/crypto/NativeTypes.dfy': d['predecessor']['sources']['formal/crypto/NativeTypes.dfy']}))
        self.rejected()

    def test_legacy_consumer_map_must_match_entire_original_manifest(self):
        self.alter_manifest(lambda d: d['legacy_consumers']['api']['inputs'].pop('formal/crypto/NativeKeccak.dfy'))
        self.rejected()

    def test_unknown_nested_schema_key(self):
        self.alter_manifest(lambda d: d['paired_harness'].update(allow_extra=True))
        self.rejected()

    def test_unknown_legacy_select_policy(self):
        self.alter_manifest(lambda d: d['legacy_select'].update(allow_changed_inputs=True))
        self.rejected()

    def test_snapshot_path_cannot_escape(self):
        self.alter_manifest(lambda d: d['predecessor_snapshots']['formal/crypto/NativeKeccak.dfy'].update(path='../outside'))
        self.rejected()

    def test_symlink_selected_source(self):
        path = self.candidate / 'formal/crypto/NativeTypes.dfy'
        outside = self.work / 'outside.dfy'
        shutil.copy2(path, outside)
        path.unlink()
        path.symlink_to(outside)
        self.rejected()

    def test_symlink_candidate_root(self):
        link = self.work / 'linked-candidate'
        link.symlink_to(self.candidate, target_is_directory=True)
        self.rejected(candidate_root=link)

    def test_symlink_selected_ancestor(self):
        path = self.candidate / 'formal/source/select'
        outside = self.work / 'external-package'
        path.rename(outside)
        path.symlink_to(outside, target_is_directory=True)
        self.rejected()

    def test_hardlink_source_alias(self):
        path = self.candidate / 'formal/crypto/NativeTypes.dfy'
        os.link(path, self.work / 'outside.dfy')
        self.rejected()

    def test_existing_output_preserved(self):
        self.output.mkdir()
        marker = self.output / 'keep'
        marker.write_text('preserve')
        with self.assertRaises(self.api.ViewError):
            self.build()
        self.assertEqual(marker.read_text(), 'preserve')

    def test_output_inside_candidate(self):
        output = self.candidate / 'nested-output'
        with self.assertRaises(self.api.ViewError):
            self.build(output=output)
        self.assertFalse(output.exists())

    def test_output_case_alias_uses_physical_directory_identity(self):
        alias = self.candidate.with_name(self.candidate.name.upper())
        if not alias.exists():
            alias.mkdir()  # A distinct directory on a case-sensitive volume.
        same_directory = alias.samefile(self.candidate)
        output = alias / 'case-alias-output'
        (self.work / 'case-alias-filesystem.json').write_text(json.dumps({
            'same_directory': same_directory,
            'candidate_identity': [self.candidate.stat().st_dev, self.candidate.stat().st_ino],
            'alias_identity': [alias.stat().st_dev, alias.stat().st_ino],
        }, indent=2) + '\n')
        if same_directory:
            with self.assertRaisesRegex(self.api.ViewError, 'overlaps'):
                self.build(output=output)
            self.assertFalse(output.exists())
        else:
            result = self.build(output=output)
            self.assertEqual(result['status'], 'complete')
            self.assertFalse(output.is_relative_to(self.candidate))

    def test_output_is_candidate_ancestor(self):
        with self.assertRaises(self.api.ViewError):
            self.build(output=self.work)

    def test_symlink_output(self):
        destination = self.work / 'untouched'
        self.output.symlink_to(destination)
        with self.assertRaises(self.api.ViewError):
            self.build()
        self.assertFalse(destination.exists())

    def test_symlink_output_ancestor(self):
        outside = self.work / 'outside'
        outside.mkdir()
        link = self.work / 'linked-output-parent'
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(self.api.ViewError):
            self.build(output=link / 'output')
        self.assertEqual(list(outside.iterdir()), [])

    def test_relative_output(self):
        with self.assertRaises(self.api.ViewError):
            self.build(output=Path('relative-output'))

    def test_test_launcher_rejects_symlink_work_parent_before_writes(self):
        outside = self.work / 'outside-test-work'
        outside.mkdir()
        link = self.work / 'linked-test-work'
        link.symlink_to(outside, target_is_directory=True)
        # A missing manifest makes any wrongly launched nested suite fail in
        # setUp, so this CLI admission probe cannot recursively run this test.
        p = subprocess.run([sys.executable, '-B', str(HERE / 'test_views.py'),
            '--candidate-root', str(self.seed), '--manifest', str(self.work / 'missing.json'),
            '--expected-manifest-sha256', self.expected_sha,
            '--work-root', str(link / 'output')], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(list(outside.iterdir()), [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=HERE / 'manifest.json')
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--work-root', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('epoch_views_tested', HERE / 'views.py')
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    try:
        seed = api.absolute(args.candidate_root)
        manifest = api.absolute(args.manifest)
        work = api.output_admission(args.work_root, [seed, manifest.parent, HERE])
        api.require(seed.is_dir(), 'test candidate is missing')
        raw, _ = api.file_bytes(manifest)
        api.require(api.digest(raw) == args.expected_manifest_sha256,
                    'test manifest differs from external expected digest')
    except (api.ViewError, OSError) as error:
        parser.error(str(error))
    work.mkdir()
    ViewsTests.seed = seed
    ViewsTests.manifest = manifest
    ViewsTests.expected_sha = args.expected_manifest_sha256
    ViewsTests.work_root = work
    ViewsTests.api = api
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ViewsTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {'tests': result.testsRun, 'failures': len(result.failures),
               'errors': len(result.errors), 'skipped': len(result.skipped),
               'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses)}
    (work / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if result.wasSuccessful() and not result.skipped and not result.expectedFailures else 1


if __name__ == '__main__':
    raise SystemExit(main())

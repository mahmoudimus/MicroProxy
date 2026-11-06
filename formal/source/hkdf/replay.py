#!/usr/bin/env python3
"""Authenticated eight-root HKDF replay. Invoked through run.py's raw-source gate."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
from zipfile import ZipFile

COMPONENT = Path('formal/source/hkdf')
KERNEL = 'formal/dafny/hkdf/Hkdf.dfy'
SOURCES = (KERNEL, 'formal/source/hkdf/HkdfTrace.dfy', 'formal/source/hkdf/ArrayInputTrace.dfy')
JAVA = Path('quic/src/main/java')
PACKAGE = Path('io/github/mahmoudimus/quic/internal/verifiedhkdf/VerifiedHkdf')
PROVIDERS = ('io/github/mahmoudimus/quic/Hkdf.java',
             'io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java',
             'io/github/mahmoudimus/verifiedcrypto/JdkHmac.java')
METHODS = tuple('VerifiedHkdf.' + x for x in
                ('Extract', 'Expand', 'LabelInfo', 'ExpandLabel', 'CopyInput',
                 'ExtractArrays', 'ExpandArrays', 'LabelInfoArray'))
JAVAC = ['--release', '21', '-g:lines,vars,source', '-encoding', 'UTF-8',
         '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes']
DLL_PIN = '96a275e60ab2a9a90187310fee01cdb8797a1276e3fe3e869f518c2dad0e8d89'
SKIPPED_PROOF_WARNING = ('The {:verify false} attribute should only be used during development. '
    'Consider using a bodyless method together with the {:axiom} attribute instead')


def skipped_proof_diagnostics(code, text):
    """Only the deliberately skipped proof may emit this exact frontend warning.

    This is audit-fixture admission, never positive proof/coverage admission.
    Match actual diagnostic headers, not a quoted warning in a source excerpt.
    """
    warning = re.compile(r'^[^\r\n|]+\([0-9]+,[0-9]+\): Warning: '
                         + re.escape(SKIPPED_PROOF_WARNING) + r'$', re.M)
    matches = list(warning.finditer(text))
    remainder = warning.sub('', text)
    if code != 0 or len(matches) != 1 or \
            re.search(r'warning|error|timed? out|out of resource|unhandled exception', remainder, re.I):
        raise ValueError('unexpected skipped-proof fixture diagnostics')


def audit_control_diagnostics(name, code, text):
    """Admit only the exact findings of the two deliberate trust controls."""
    axiom = ': Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.'
    expected = {'Mac' + axiom}
    if name == 'extra-assumption':
        expected.add('ExtraAssumption' + axiom)
    elif name == 'skipped-proof':
        expected.update((SKIPPED_PROOF_WARNING,
            'Extract: Declaration has `{:verify false}` attribute. Possible mitigation: '
            'Remove `{:verify false}` attribute and prove if possible.'))
    else:
        raise ValueError('unknown audit control')
    warnings = re.findall(r'^[^\r\n|]+\([0-9]+,[0-9]+\): Warning: ([^\r\n]+)$', text, re.M)
    if code != 0 or len(warnings) != len(expected) or set(warnings) != expected or \
            len(re.findall('warning', text, re.I)) != len(warnings) or \
            text.count('Dafny auditor completed with 2 findings') != 1 or \
            re.search(r'error|timed? out|out of resource|unhandled exception', text, re.I):
        raise ValueError('unexpected nonvacuity audit diagnostics: ' + name)


class Replay:
    def __init__(self, args, repo, data, admission):
        self.args, self.repo, self.data, self.a = args, repo, data, admission
        self.out = args.output
        self.inputs = data['inputs']
        self.sha = admission.sha
        protected = {'repository': repo, 'manifest': args.manifest,
                     'dafny': args.dafny.parent, 'dotnet': args.dotnet.parent,
                     'jdk21': args.jdk21, 'jdk25': args.jdk25,
                     'runtime': args.runtime.parent, 'targeting-packs': args.targeting_packs,
                     'python-prefix': Path(sys.base_prefix),
                     'python-executable': Path(sys.executable).resolve().parent}
        if args.jar is not None:
            protected['jar'] = args.jar
        error = admission.output_isolation_error(self.out, protected)
        if error:
            raise ValueError(error)
        self.jar_before = self.sha(admission.regular(args.jar)) if args.jar is not None else None
        self.shared = self.load('hkdf_build_support', str(COMPONENT / 'tooling/build_support.py'))
        error = self.shared.output_admission_error(self.out, repo, repo)
        if error:
            raise ValueError(error)
        self.out.mkdir(parents=True)
        (self.out / 'logs').mkdir()
        self.frozen = self.out / 'frozen'
        self.frozen.mkdir()
        for name, pin in self.inputs.items():
            target = self.frozen / name
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (repo / name).read_bytes()
            if admission.digest(raw) != pin:
                raise ValueError('input changed before copy: ' + name)
            target.write_bytes(raw)
        self.owner = self.load('hkdf_owned', str(COMPONENT / 'tooling/owned_call.py'))
        self.rules = self.load('hkdf_proof_rules', str(COMPONENT / 'tooling/proof_rules.py'))
        self.outcomes = self.load('hkdf_outcome_rules', str(COMPONENT / 'tooling/outcome_rules.py'))
        self.validator = self.load('hkdf_one_source_validator', str(COMPONENT / 'tooling/evaluation_validator.py'))
        self.legacy = self.load('hkdf_legacy_controls', str(COMPONENT / 'run.py'))
        self.functional = self.load('hkdf_functional_controls', 'formal/dafny/run.py')
        self.evidence = self.load('hkdf_evidence_projection', str(COMPONENT / 'tooling/source_evidence.py'))
        self.build_authority = self.load('hkdf_build_authority', 'formal/source/keccak/encoder/build_authority.py')
        self.delivery = self.load('hkdf_delivery_parser', 'formal/crypto/delivery.py')
        profile_raw = (repo / 'formal/source/select/profiles' / (args.profile + '.json')).read_bytes()
        self.profile = self.shared.validate_profile(args.profile, profile_raw)
        self.dafny, self.dotnet, self.tool_pins = self.shared.check_tool_pins(self.profile, args.dafny, args.dotnet)
        for name, home in (('jdk21', args.jdk21), ('jdk25', args.jdk25)):
            for rel, expected in self.profile[name + '_tools'].items():
                if self.sha(admission.regular(home / rel)) != expected:
                    raise ValueError('unselected ' + name + ' tool: ' + rel)
        if self.sha(admission.regular(args.runtime)) != self.profile['runtime_sha256']:
            raise ValueError('unselected Dafny runtime JAR')
        pack_raw = (repo / 'formal/source/keccak/encoder/net6-targeting-packs.json').read_bytes()
        _, archives, payloads = self.build_authority.admit_archives(args.targeting_packs, pack_raw)
        if len(payloads) != 577:
            raise ValueError('wrong offline targeting-pack inventory')
        self.authority = self.build_authority.BuildAuthority(self.out / 'build-authority', pack_raw,
                                                           archives, payloads, self.dotnet.parent)
        self.env = admission.child_environment(self.out / 'child')
        self.build_env = self.authority.environment()
        self.build_env.update(PATH=self.env['PATH'], LANG='C', LC_ALL='C', TZ='UTC')
        self.tools_before = self.tool_map()
        self.owner.durable_json(self.out / 'TOOLS-BEFORE.json', self.tools_before)
        self.result = {'schema': 'microproxy.hkdf-source-replay/2', 'qualification': False,
                       'phase': args.phase, 'status': 'running', 'profile': args.profile,
                       'manifest_sha256': args.expected_manifest, 'inputs_before': self.inputs,
                       'tools_before': {'path': 'TOOLS-BEFORE.json', 'sha256': self.sha(self.out / 'TOOLS-BEFORE.json')},
                       'tool_snapshot_scope': 'Complete Dafny/.NET file maps plus complete typed JDK trees; symlinks recorded, never traversed; five profile-pinned JDK operands additionally authenticated',
                       'output_protected_roots': {k: str(p) for k, p in protected.items()},
                       'jar_input_before': self.jar_before,
                       'tool_pins': self.tool_pins, 'commands': [], 'coverage': [], 'proofs': [],
                       'scope': 'Eight declared source observation roots and functional/NI proofs; trusted C#/compiler/JVM/JCE boundaries; no physical timing or whole-crypto qualification'}
        self.save()

    def load(self, name, rel):
        root = self.frozen if hasattr(self, 'frozen') else self.repo
        return self.a.load_module(name, root / rel, self.inputs[rel])

    def save(self):
        self.owner.durable_json(self.out / 'report.json', self.result)

    def tool_map(self):
        result = self.shared.tool_map(self.dafny.parent, self.dotnet.parent)
        for home, key in ((self.args.jdk21, 'jdk21'), (self.args.jdk25, 'jdk25')):
            result.update({str(home / rel): self.sha(home / rel) for rel in self.profile[key + '_tools']})
            result[key + '-typed-tree:' + str(home)] = self.a.tree_snapshot(home)
        result[str(self.args.runtime)] = self.sha(self.args.runtime)
        result[str(Path(sys.executable).resolve())] = self.sha(Path(sys.executable).resolve())
        return result

    def call(self, label, argv, cwd=None, build=False, timeout=240):
        log = self.out / 'logs' / (label + '.log')
        code, text, record = self.owner.run(argv, log, cwd or self.frozen,
                                            self.build_env if build else self.env, timeout)
        row = {'label': label, 'argv': list(map(str, argv)), 'exit': code,
               'log': str(log.relative_to(self.out)), 'log_sha256': self.sha(log), **record}
        # Supervisor has already fsynced its raw record. Persist returned exit
        # BEFORE parsing/classifying any compiler output or CSV.
        self.owner.durable_json(self.out / 'logs' / (label + '.record.json'), row)
        self.result['commands'].append(row)
        self.save()
        print(label, 'exit', code, flush=True)
        return code, text

    def ordinary(self, label, path):
        code, text = self.call(label, [self.dafny, 'resolve', path, '--allow-external-contracts'])
        if code != 0 or 'warning' in text.lower() or self.outcomes.BAD.search(text):
            raise ValueError('ordinary resolve failed: ' + label)
        return code, text

    def checked(self, label, path):
        code, text = self.call(label, [self.dafny, 'resolve', path, '--allow-external-contracts', '--plugin', self.dll])
        checked = [l for l in text.splitlines() if l.startswith('HKDF-CHECKED-ROOT ')]
        if code != 0 or 'warning' in text.lower() or self.outcomes.BAD.search(text) or \
                'HKDF-SOURCE-COVERAGE OK:' not in text or len(set(checked)) != 8 or len(checked) != 8:
            raise ValueError('eight-root coverage positive failed: ' + label)
        if label == 'coverage-source-0':
            declarations = [l for l in text.splitlines() if l.startswith('HKDF-DECL ')]
            if declarations != (self.frozen / COMPONENT / 'declarations.txt').read_text().splitlines():
                raise ValueError('reviewed resolved declaration inventory changed')
        return checked

    def closure(self):
        todo, found = list(SOURCES), {}
        while todo:
            name = todo.pop()
            if name in found:
                continue
            if name not in self.inputs:
                raise ValueError('unadmitted parser dependency: ' + name)
            path = self.frozen / name
            children = []
            for include in self.shared.include_paths(path.read_text()):
                if Path(include).is_absolute() or '\\' in include:
                    raise ValueError('unsupported include')
                target = (path.parent / include).resolve()
                if not target.is_relative_to(self.frozen):
                    raise ValueError('include escapes frozen source')
                children.append(str(target.relative_to(self.frozen)))
            found[name] = children
            todo += children
        if set(found) != set(SOURCES):
            raise ValueError('unexpected complete parser closure')
        self.result['parser_closure'] = found
        official = {}
        for i, rel in enumerate(SOURCES):
            closure = self.delivery.source_closure(self.frozen, self.frozen / rel, self.dafny,
                call=lambda label, argv: self.call('parser-' + str(i) + '-' + label, argv))
            official.update(closure)
        if official != {n: self.inputs[n] for n in SOURCES}:
            raise ValueError('official complete parser closure differs from selected source3')
        self.result['official_parser_closure'] = official

    def materialize(self):
        self.plan = json.loads((self.frozen / COMPONENT / 'controls/v2.json').read_text())
        if len(self.plan['coverage']) != 115 or sum(r['kind'] == 'negative' for r in self.plan['coverage']) != 112 or len(self.plan['body']) != 5:
            raise ValueError('omitted/changed control inventory')
        for group in ('coverage', 'body'):
            for row in self.plan[group]:
                folder = self.out / 'controls' / group / row['name']
                folder.mkdir(parents=True)
                for rel, recipe in row['files'].items():
                    target = folder / self.a.relative(rel)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    base = (self.frozen / recipe['base']).read_text()
                    target.write_text(self.a.apply_recipe(base, recipe))
                if group == 'coverage' and row['name'] in (
                        'old-block-boundary-pending', 'old-callee-suchthat-model-erasure',
                        'old-third-callee-dup', 'old-third-expdup', 'supplement-old-bijective-site-relabel'):
                    harness = folder / 'HkdfTrace.dfy'
                    if not harness.exists():
                        harness.write_text((self.frozen / SOURCES[1]).read_text().replace(
                            'include "../../dafny/hkdf/Hkdf.dfy"', 'include "Hkdf.dfy"'))
        base = (self.frozen / KERNEL).read_text()
        mutations = self.functional.mutations(base)
        if set(mutations) != {'counter', 'feedback', 'truncation', 'prefix', 'public-domain'}:
            raise ValueError('original functional/domain controls omitted')
        mutations['baseline'] = base
        self.functional_plan = []
        for name, text in mutations.items():
            folder = self.out / 'controls/functional' / name
            folder.mkdir(parents=True)
            (folder / 'Hkdf.dfy').write_text(text)
            (folder / 'PublicDomain.dfy').write_text(self.functional.domain_harness(Path('Hkdf.dfy')))
            self.functional_plan.append({'name': name,
                'kernel_sha256': self.sha(folder / 'Hkdf.dfy'),
                'domain_sha256': self.sha(folder / 'PublicDomain.dfy')})
        for name, text in (
                ('extra-assumption', base.replace('module VerifiedHkdf {',
                    'module VerifiedHkdf {\n  lemma {:axiom} ExtraAssumption()', 1)),
                ('skipped-proof', base.replace('method Extract(', 'method {:verify false} Extract(', 1))):
            folder = self.out / 'controls/functional' / name
            folder.mkdir()
            (folder / 'Hkdf.dfy').write_text(text)
            self.functional_plan.append({'name': name, 'kernel_sha256': self.sha(folder / 'Hkdf.dfy')})
        self.result['functional_plan'] = self.functional_plan
        self.result['materialized_controls'] = self.shared.file_map(self.out / 'controls')

    def build(self):
        package = self.out / 'checker'
        package.mkdir()
        for name in ('HkdfCoverage.cs', 'HkdfCoverage.csproj'):
            shutil.copyfile(self.frozen / COMPONENT / 'checker' / name, package / name)
        # SDK selection is explicit even if an ancestor has a different global.json.
        (package / 'global.json').write_text(json.dumps({'sdk': {'version': '10.0.400', 'rollForward': 'disable'}}))
        project = package / 'HkdfCoverage.csproj'
        common = [self.dotnet, 'msbuild', project, *self.authority.arguments(self.dafny.parent)]
        self.authority.verify()
        code, text = self.call('checker-restore', [*common, '-t:Restore', '-v:minimal'], package, True)
        if code != 0:
            raise ValueError('strict offline restore failed')
        assets = self.authority.validate_assets(package / 'obj/project.assets.json')
        code, text = self.call('checker-build', [*common, '-t:Build', '-v:minimal',
            '-getProperty:' + ','.join([*self.authority.properties(), 'MSBuildAllProjects']),
            '-getItem:ReferencePath,ReferencePathWithRefAssemblies,Compile,Analyzer,EditorConfigFiles,GlobalAnalyzerConfigFiles,AnalyzerConfigFiles'], package, True)
        if code != 0 or text.find('{\n') < 0:
            raise ValueError('strict checker build failed/missing evaluation')
        actual, _ = json.JSONDecoder().raw_decode(text[text.find('{\n'):])
        evaluated = self.validator.validate_evaluation(self.authority, json.dumps(actual), package,
                                                       package, 'HkdfCoverage', self.tools_before)
        self.dll = package / 'bin/Debug/net6.0/HkdfCoverage.dll'
        if self.sha(self.dll) != DLL_PIN:
            raise ValueError('built checker differs from reviewed deterministic DLL')
        self.result['build'] = {'assets': assets, 'evaluation': evaluated, 'dll_sha256': self.sha(self.dll)}
        self.authority.verify()

    def coverage(self):
        for i, rel in enumerate(SOURCES):
            path = self.frozen / rel
            self.ordinary('ordinary-source-' + str(i), path)
            self.checked('coverage-source-' + str(i), path)
        # Ordinary resolution for EVERY fixture precedes ALL intended outcomes.
        ordinary = {}
        for row in self.plan['coverage']:
            entry = self.out / 'controls/coverage' / row['name'] / 'Hkdf.dfy'
            ordinary[row['name']] = self.ordinary('ordinary-' + row['name'], entry)
        for row in self.plan['coverage']:
            entry = self.out / 'controls/coverage' / row['name'] / 'Hkdf.dfy'
            if row['kind'] == 'positive':
                self.checked('coverage-' + row['name'], entry)
                outcome = 'accepted valid control'
            else:
                code, text = self.call('coverage-' + row['name'], [self.dafny, 'resolve', entry,
                                      '--allow-external-contracts', '--plugin', self.dll])
                if not self.outcomes.named_rejection(*ordinary[row['name']], code, text, row['needle']):
                    raise ValueError('missing actual named coverage rejection: ' + row['name'])
                outcome = 'ordinary-valid named coverage rejection'
            self.result['coverage'].append({'name': row['name'], 'kind': row['kind'], 'outcome': outcome})
            self.save()

    def java(self):
        out = self.out / 'java'
        out.mkdir()
        code, text = self.call('translate', [self.dafny, 'translate', 'java', self.frozen / KERNEL,
            '--no-verify', '--allow-external-contracts', '--outer-module',
            'io.github.mahmoudimus.quic.internal.verifiedhkdf', '--output', out / 'HkdfCrypto'])
        if code != 0 or 'warning' in text.lower():
            raise ValueError('Java translation failed')
        generated = out / 'HkdfCrypto-java'
        reference = json.loads((self.frozen / COMPONENT / 'fixtures/approved-r2.json').read_text())
        actual = self.shared.file_map(generated)
        changed = sorted(n for n in set(actual) | set(reference['generated_sources'])
                         if actual.get(n) != reference['generated_sources'].get(n))
        self.result['java'] = {'generated_sources': actual, 'raw_changed_files': changed, 'classes': {}}
        diff = ''
        for name in changed:
            baseline = self.frozen / JAVA / PACKAGE / Path(name).name
            if name.endswith('.java') and baseline.is_file():
                diff += ''.join(difflib.unified_diff(baseline.read_text().splitlines(True),
                      (generated / name).read_text().splitlines(True), fromfile='committed/' + name, tofile='generated/' + name))
        (out / 'RAW-JAVA.diff').write_text(diff)
        self.save()
        if changed:
            raise ValueError('literal generated artifact delta; no normalization allowed')
        erased = out / 'binding-erasure'
        erased.mkdir()
        code, text = self.call('translate-binding-erasure', [self.dafny, 'translate', 'java',
            self.out / 'controls/coverage/old-callee-suchthat-model-erasure/Hkdf.dfy',
            '--no-verify', '--allow-external-contracts', '--outer-module',
            'io.github.mahmoudimus.quic.internal.verifiedhkdf', '--output', erased / 'HkdfCrypto'])
        if code != 0 or self.shared.file_map(erased / 'HkdfCrypto-java') != actual:
            raise ValueError('former full-gate ghost-binding bypass changed executable generation')
        self.result['java']['binding_erasure_exact'] = True
        fresh = sorted((generated / PACKAGE).glob('*.java'))
        committed = sorted((self.frozen / JAVA / PACKAGE).glob('*.java'))
        if len(fresh) != 9 or {p.name: self.sha(p) for p in fresh} != {p.name: self.sha(p) for p in committed}:
            raise ValueError('generated package differs from committed production')
        providers = [self.frozen / JAVA / p for p in PROVIDERS]
        for major, home in ((21, self.args.jdk21), (25, self.args.jdk25)):
            inventories = []
            for label, files in (('committed', committed), ('generated', fresh)):
                classes = out / (label + '-' + str(major))
                classes.mkdir()
                code, text = self.call('javac-' + label + '-' + str(major),
                    [home / 'bin/javac', *JAVAC, '-cp', self.args.runtime, '-d', classes, *files, *providers])
                if code != 0 or text.strip():
                    raise ValueError('actual Java compile failed/diagnostics')
                inventories.append(self.shared.file_map(classes))
            if inventories[0] != inventories[1] or len(inventories[0]) != 12:
                raise ValueError('actual same-JDK production/generated class delta')
            selected = reference['classes_by_profile'].get(self.args.profile, {}).get(str(major))
            if selected is not None and inventories[0] != selected:
                raise ValueError('class delta against independently reviewed same-profile R2 image')
            self.result['java']['classes'][str(major)] = inventories[0]
            # Original conversion discipline and deliberate select/cast/decoy
            # controls run on these ACTUAL production class files, separately
            # from the array functional tests below.
            for action, extra in (('discipline', []), ('self-test', ['--self-test'])):
                code, text = self.call('adapter-' + action + '-' + str(major),
                    [sys.executable, '-I', '-B', self.frozen / 'formal/dafny/check_adapter_discipline.py',
                     '--java-home', home, '--classes', out / ('generated-' + str(major)),
                     '--runtime', self.args.runtime, *extra])
                if code != 0:
                    raise ValueError('original adapter gate/control failed')
                self.result.setdefault('adapter_checks', []).append({'jdk': major, 'action': action,
                                                                    'output': text.strip()})
            test_classes = out / ('runtime-' + str(major))
            test_classes.mkdir()
            cp = str(out / ('generated-' + str(major))) + ':' + str(self.args.runtime)
            code, text = self.call('runtime-compile-' + str(major), [home / 'bin/javac', '--release', '21',
                '-cp', cp, '-d', test_classes, self.frozen / COMPONENT / 'runtime/ArrayInputIntegrationTest.java'])
            if code != 0 or text.strip():
                raise ValueError('runtime harness compile failed/diagnostics')
            code, text = self.call('runtime-' + str(major), [home / 'bin/java', '-cp',
                str(test_classes) + ':' + cp, 'ArrayInputIntegrationTest'])
            if code != 0 or text.strip() != 'HKDF-ARRAY-INTEGRATION-PASS cases=150 assertions=346':
                raise ValueError('actual generated array/JCE runtime regression')
            original = out / ('original-runtime-' + str(major))
            original.mkdir()
            helpers = sorted((self.frozen / 'formal/dafny/java').rglob('*.java'))
            code, text = self.call('original-runtime-compile-' + str(major),
                [home / 'bin/javac', *JAVAC, '-cp', cp, '-d', original, *helpers])
            if code != 0 or text.strip():
                raise ValueError('original GeneratedHkdfTest compile failed')
            code, text = self.call('original-runtime-' + str(major), [home / 'bin/java', '-ea',
                '-cp', str(original) + ':' + cp, 'io.github.mahmoudimus.verifiedcrypto.GeneratedHkdfTest'])
            if code != 0 or not re.fullmatch(r'PASS GeneratedHkdfTest: 45 cases, 2766 assertions; providers: [^\r\n]+', text.strip()):
                raise ValueError('original generated/JCE integration regression')
            self.result.setdefault('original_runtime', {})[str(major)] = text.strip()
        if self.args.jar is not None:
            self.result['jar'] = self.check_jar(self.args.jar, self.result['java']['classes']['21'])
        self.save()

    def check_jar(self, path, classes):
        before = self.sha(self.a.regular(path))
        with ZipFile(path) as jar:
            names = jar.namelist()
            if len(names) != len(set(names)):
                raise ValueError('duplicate JAR entries')
            for name, expected in classes.items():
                if name not in names or self.a.digest(jar.read(name)) != expected:
                    raise ValueError('actual HKDF JAR class entry missing/changed: ' + name)
        if self.sha(path) != before:
            raise ValueError('JAR changed during inspection')
        return {'sha256': before, 'matched_entries': len(classes),
                'scope': 'HKDF generated/facade/bridge/provider entries only; no whole-JAR or runtime refinement claim'}

    def flags(self):
        return [*self.legacy.FLAGS, '--solver-path', self.dafny.parent / 'z3/bin/z3-4.12.1']

    def proof(self, name, entry, prefix, methods=(), marker=None, symbol=None):
        csv = self.out / 'logs' / (name + '.csv')
        argv = [self.dafny, 'verify', entry, '--progress', 'Symbol',
                '--log-format', 'csv;LogFileName=' + str(csv), *self.flags()]
        if symbol:
            argv += ['--filter-symbol', symbol + '.']
        code, text = self.call(name, argv, timeout=600)
        result = self.rules.positive(code, text, csv.read_text(), prefix, methods, marker)
        self.result['proofs'].append({'name': name, **result, 'csv_sha256': self.sha(csv)})
        self.save()
        return result

    def audit(self, name, entry, findings):
        code, text = self.call(name, [self.dafny, 'audit', entry, '--allow-external-contracts'])
        actual = re.findall(r'^[^\r\n]+\([0-9]+,[0-9]+\): Warning: ([^\r\n]+)$', text, re.M)
        summary = re.findall(r'Dafny auditor completed with ([0-9]+) findings', text)
        if code != 0 or summary != [str(findings)] or len(actual) != findings or \
                (findings == 1 and actual != ['Mac: Declaration has explicit `{:axiom}` attribute. Possible mitigation: Provide a proof or test.']):
            raise ValueError('unexpected trust/assumption audit: ' + name)
        self.result.setdefault('audits', []).append({'name': name, 'findings': findings})

    def proofs(self):
        for i, (rel, prefix, count) in enumerate(zip(SOURCES,
                ('VerifiedHkdf.', 'HkdfTrace.', 'HkdfArrayInputTrace.'), (257, 11, 13))):
            path = self.frozen / rel
            proof = self.proof('proof-source-' + str(i), path, prefix,
                               METHODS if i == 0 else (), 'VerifiedHkdf.EvBranchIf' if i == 0 else None)
            if proof['rows'] != count:
                raise ValueError('current own-file VC count changed')
            self.audit('audit-source-' + str(i), path, 1 if i == 0 else 0)
        for name in ('nested-mixed-AND-OR', 'nested-mixed-OR-AND'):
            path = self.out / 'controls/coverage' / name / 'Hkdf.dfy'
            proof = self.proof('proof-' + name, path, 'VerifiedHkdf.', METHODS, 'VerifiedHkdf.EvBranchIf')
            if proof['rows'] != 257:
                raise ValueError('mixed guard proof scope changed')
            self.audit('audit-' + name, path, 1)
        for row in self.plan['body']:
            entry = self.out / 'controls/body' / row['name'] / row['entry']
            self.ordinary('ordinary-body-' + row['name'], entry)
            csv = self.out / 'logs' / ('body-' + row['name'] + '.csv')
            code, text = self.call('body-' + row['name'], [self.dafny, 'verify', entry,
                '--filter-symbol', row['symbol'] + '.', '--progress', 'Symbol',
                '--log-format', 'csv;LogFileName=' + str(csv), *self.flags()])
            result = self.rules.negative(code, text, csv.read_text(), row['symbol'], row['kind'],
                                         row['required_failure']['line'], row['optional_post_line'])
            self.result['proofs'].append({'name': row['name'], 'kind': 'negative', **result})
        self.legacy_controls()
        self.functional_controls()

    def functional_controls(self):
        """Original functional/domain/nonvacuity controls on the current kernel."""
        folder = self.out / 'controls/functional'
        baseline = folder / 'baseline/PublicDomain.dfy'
        self.ordinary('ordinary-public-domain', baseline)
        self.proof('public-domain', baseline, 'PublicDomain.', ('PublicDomain.AllInputs',))
        targets = {'counter': 'VerifiedHkdf.Expand', 'feedback': 'VerifiedHkdf.Expand',
                   'truncation': 'VerifiedHkdf.Expand', 'prefix': 'VerifiedHkdf.LabelInfo',
                   'public-domain': 'PublicDomain.AllInputs'}
        # Every fixture must resolve before any intended failure is admitted.
        for name in targets:
            self.ordinary('ordinary-functional-' + name, folder / name / 'PublicDomain.dfy')
        for name, symbol in targets.items():
            entry = folder / name / ('PublicDomain.dfy' if name == 'public-domain' else 'Hkdf.dfy')
            csv = self.out / 'logs' / ('functional-' + name + '.csv')
            code, text = self.call('functional-' + name, [self.dafny, 'verify', entry,
                '--filter-symbol', symbol + '.', '--progress', 'Symbol',
                '--log-format', 'csv;LogFileName=' + str(csv), *self.flags()])
            self.functional.check_rejected(code, text)
            data, families = self.rules.rows(csv.read_text())
            if not any(r['TestResult.Outcome'] == 'Failed' for r in data) or \
                    any(target != symbol for target, kind in families):
                raise ValueError('wrong actual functional failure target')
            self.result['proofs'].append({'name': 'functional-' + name,
                'kind': 'negative', 'target': symbol, 'actual_vc_rows': len(data),
                'csv_sha256': self.sha(csv), 'classification': 'normal original functional/domain proof failure'})
        for name in ('extra-assumption', 'skipped-proof'):
            entry = folder / name / 'Hkdf.dfy'
            extra = []
            if name == 'skipped-proof':
                # This fixture intentionally triggers Dafny's development
                # warning. Keep strict warning rejection for every other input.
                extra = ['--allow-warnings']
                code, text = self.call('ordinary-functional-' + name,
                    [self.dafny, 'resolve', entry, '--allow-external-contracts', *extra])
                skipped_proof_diagnostics(code, text)
            else:
                self.ordinary('ordinary-functional-' + name, entry)
            # Dafny 4.9.1's legacy audit command has no --allow-warnings option.
            # Its warnings are the trust findings that this control must reject.
            code, text = self.call('functional-' + name,
                [self.dafny, 'audit', entry, '--allow-external-contracts'])
            audit_control_diagnostics(name, code, text)
            try:
                self.functional.check_audit(code, text)
            except RuntimeError:
                self.result.setdefault('functional_audit_controls', {})[name] = 'unexpected trust/skip rejected'
            else:
                raise ValueError('nonvacuity audit control accepted')

    def legacy_controls(self):
        """Retain the existing named metadata, observed-secret and audit controls."""
        base = (self.frozen / KERNEL).read_text()
        for name in ('old-block-boundary-pending', 'old-callee-suchthat-model-erasure',
                     'old-third-callee-dup', 'old-third-expdup', 'supplement-old-bijective-site-relabel'):
            folder = self.out / 'controls/coverage' / name
            self.proof('legacy-body-' + name, folder / 'Hkdf.dfy', 'VerifiedHkdf.', METHODS,
                       'VerifiedHkdf.EvBranchIf')
            self.proof('legacy-NI-' + name, folder / 'HkdfTrace.dfy', 'HkdfTrace.')
        metadata = self.out / 'legacy-metadata'
        self.legacy.metadata_mutants(base, metadata)
        for encoder in sorted(set(self.legacy.METADATA_ENCODERS.values())):
            self.proof('metadata-positive-' + encoder, self.frozen / KERNEL, 'VerifiedHkdf.',
                       marker='VerifiedHkdf.' + encoder, symbol='VerifiedHkdf.' + encoder)
        for name, needle in self.legacy.metadata_mutants(base, self.out / 'legacy-metadata-negative').items():
            entry = self.out / 'legacy-metadata-negative' / name / 'Hkdf.dfy'
            self.ordinary('ordinary-' + name, entry)
            code, text = self.call('proof-' + name, self.legacy.metadata_command(self.dafny, entry, name)
                                   + ['--solver-path', self.dafny.parent / 'z3/bin/z3-4.12.1'])
            result = self.legacy.require_named_proof_failure(code, text, needle, name)
            self.result['proofs'].append({'name': name, **result})
        for name in self.legacy.observed_mutants(base, self.out / 'legacy-observed', self.frozen / SOURCES[1]):
            entry = self.out / 'legacy-observed' / name / 'Hkdf.dfy'
            self.ordinary('ordinary-' + name, entry)
            # The legacy counterexample instruments Extract only. New array
            # wrapper trace equations are deliberately not secret-declassified.
            self.proof('proof-' + name, entry, 'VerifiedHkdf.', ('VerifiedHkdf.Extract',),
                       symbol='VerifiedHkdf.Extract')
            code, text = self.call('NI-' + name, [self.dafny, 'verify', entry.parent / 'HkdfTrace.dfy',
                                   *self.flags()], timeout=600)
            self.result['proofs'].append({'name': name + '-NI',
                **self.legacy.require_assertion_failure(code, text, name)})
        # Complete-parser audit injection cannot hide behind Dafny's root-only audit.
        injected = self.out / 'audit-control'
        injected.mkdir()
        (injected / 'Hkdf.dfy').write_text(base)
        (injected / 'Assumption.dfy').write_text('module Injected { lemma {:axiom} TrustMe() ensures true }\n')
        (injected / 'Root.dfy').write_text('\ufeff// BOM and inline-comment parser control\ninclude "Assumption.dfy" // included axiom\n')
        self.ordinary('ordinary-audit-injection', injected / 'Root.dfy')
        closure = self.delivery.source_closure(injected, injected / 'Root.dfy', self.dafny,
            call=lambda label, argv: self.call('audit-control-parser-' + label, argv, injected))
        if set(closure) != {'Root.dfy', 'Assumption.dfy'}:
            raise ValueError('BOM/comment include escaped the official parser census')
        self.audit('audit-control-root', injected / 'Root.dfy', 0)
        code, text = self.call('audit-included-assumption', [self.dafny, 'audit', injected / 'Assumption.dfy', '--allow-external-contracts'])
        if code != 0 or 'TrustMe: Declaration has explicit `{:axiom}` attribute.' not in text or \
                'Dafny auditor completed with 1 findings' not in text:
            raise ValueError('included assumption control did not expose exact unexpected assumption')
        self.result['included_assumption_control'] = 'unexpected included axiom found; rejected by the canonical 1/0/0 allowlist'

    def run(self):
        try:
            self.closure()
            self.materialize()
            self.build()
            self.coverage()
            self.java()
            if self.args.phase == 'full':
                self.proofs()
            self.result['status'] = 'complete bounded ' + self.args.phase
        except BaseException as error:
            self.result['status'] = 'failed/incomplete'
            self.result['error'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            self.result['inputs_after'] = {n: self.sha(self.repo / n) for n in self.inputs}
            self.result['frozen_inputs_after'] = {n: self.sha(self.frozen / n) for n in self.inputs}
            tools_after = self.tool_map()
            self.owner.durable_json(self.out / 'TOOLS-AFTER.json', tools_after)
            self.result['tools_after'] = {'path': 'TOOLS-AFTER.json', 'sha256': self.sha(self.out / 'TOOLS-AFTER.json')}
            self.result['tools_after_equal'] = tools_after == self.tools_before
            self.result['manifest_after_sha256'] = self.sha(self.args.manifest)
            self.result['jar_input_after'] = self.sha(self.args.jar) if self.args.jar is not None else None
            self.result['materialized_controls_after'] = self.shared.file_map(self.out / 'controls')
            self.result['build_authority'] = self.authority.record()
            if self.result['inputs_after'] != self.inputs or self.result['frozen_inputs_after'] != self.inputs or \
                    not self.result['tools_after_equal'] or self.result['manifest_after_sha256'] != self.args.expected_manifest or \
                    self.result['jar_input_before'] != self.result['jar_input_after'] or \
                    self.result.get('materialized_controls') != self.result['materialized_controls_after']:
                self.result['status'] = 'failed input/tool drift'
            self.save()
        if not self.result['status'].startswith('complete bounded'):
            raise ValueError(self.result['status'])
        if self.args.phase == 'full':
            # A new output receipt, never a rewrite of a historical receipt or
            # repository input authority. The full raw report stays unchanged.
            try:
                projected = self.evidence.project(self.out)
                self.owner.durable_json(self.out / 'SOURCE-EVIDENCE-v2.json', projected)
            except BaseException as error:
                self.result['status'] = 'failed receipt export; execution facts retained'
                self.result['error'] = type(error).__name__ + ': ' + str(error)
                self.save()
                raise


def main(argv, repo, admitted, admission):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-manifest', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', required=True)
    for name in ('dafny', 'dotnet', 'targeting-packs', 'runtime', 'jdk21', 'jdk25'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--phase', choices=('preflight', 'full'), default='full')
    parser.add_argument('--jar', type=Path, help='read-only exact HKDF12-entry comparison in an already-built JAR')
    args = parser.parse_args(argv)
    for name in ('manifest', 'output', 'dafny', 'dotnet', 'targeting_packs', 'runtime', 'jdk21', 'jdk25'):
        if not getattr(args, name).is_absolute():
            parser.error('--' + name.replace('_', '-') + ' must be absolute')
    data = admission.authenticate(repo, args.manifest, args.expected_manifest)
    if args.jar is not None and not args.jar.is_absolute():
        parser.error('--jar must be absolute')
    if data != admitted:
        raise ValueError('manifest changed after bootstrap')
    Replay(args, repo, data, admission).run()
    return 0

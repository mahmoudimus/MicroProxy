#!/usr/bin/env python3
"""Focused current-epoch Select consumer; never an epoch qualification claim."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import types

HERE = Path(__file__).resolve().parent
EPOCH_SHA = '294e28dbd13219477a285c0774c4d91928c4f536130011db024533efad683dec'
CONSTRUCTOR_SHA = '65eb424c4c0b5ce44498ded72cb8600c02252e18122b8d1f28fcfb0b00eaa3eb'
EXPECTATIONS_SHA = 'ca8c5015bdc1733f196e7dcfc114109386651657799bb4201918882afdf6beee'
EVALUATION_SHA = '4e249bc51c57f4cd9c5c6bc7b5f08fdc106a758b70ea8684526aa4d3e77c66e4'
PROFILE_SHA = {'macos-sdk10.0.400': '9ec9f05ce8dd1083071e6fc0aecea69d9972abe7d94ca8e7be0266c032e99f84',
               'linux-sdk10.0.400': '89c444a9e5c4d473912fd57db16e53b71d06733f1751fe648bf9995c0a4deab1'}
BAD = re.compile(r'timed?\s*out|out of resource|out of memory|internal error|unhandled exception|'
                 r'parse[rd]? errors?|Error: unresolved identifier|Error: incorrect argument type|'
                 r'Error: wrong number of arguments|Error: this expression has type|CLI: Error', re.I)
SUMMARY_LINE = re.compile(r'^Dafny program verifier finished with .*$', re.M)
SUMMARY = re.compile(r'^Dafny program verifier finished with (\d+) verified, (\d+) errors?$', re.M)
FILTER = 'NativeMlKem.Select'
MATCHED = ('NativeMlKem.SelectDiffPrefix', 'NativeMlKem.SelectOutPrefix',
           'NativeMlKem.SelectDiffStep', 'NativeMlKem.SelectOutStep', 'NativeMlKem.Select')


class SelectError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SelectError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def map_sha(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()


def captured_module(name, path, expected):
    path = Path(path)
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink module input: ' + str(part))
    require(path.is_file() and path.stat().st_nlink == 1, 'missing/aliased module input')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, 'module identity changed: ' + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def constructor():
    return captured_module('approved_epoch_views', HERE / 'views.py', CONSTRUCTOR_SHA)


def output_admission(output, protected):
    try:
        return constructor().output_admission(output, protected)
    except (ValueError, OSError) as error:
        raise SelectError(str(error)) from error


def current_sources(manifest):
    return manifest['current']['sources']


def admit_views(manifest_path, expected_manifest_sha256, views_root, expected_receipt_sha256):
    require(expected_manifest_sha256 == EPOCH_SHA, 'unreviewed epoch manifest authority')
    c = constructor()
    try:
        manifest_path, views_root = c.absolute(manifest_path), c.absolute(views_root)
        raw, _ = c.file_bytes(manifest_path)
        require(hashlib.sha256(raw).hexdigest() == EPOCH_SHA, 'epoch manifest changed')
        manifest = c.load_bytes(raw, 'epoch manifest')
        old, new, support, tooling = c.validate_manifest(manifest)
        raw_receipt, _ = c.file_bytes(views_root / 'receipt.json')
        require(re.fullmatch('[0-9a-f]{64}', expected_receipt_sha256 or '')
                and hashlib.sha256(raw_receipt).hexdigest() == expected_receipt_sha256,
                'view receipt differs from external expected digest')
        receipt = c.load_bytes(raw_receipt, 'source view receipt')
        require(receipt.get('schema') == c.RECEIPT_SCHEMA and receipt.get('status') == 'complete'
                and receipt.get('qualification') is False and receipt.get('scope') == 'source-views-only',
                'view receipt scope/status changed')
        require(receipt.get('manifest_sha256') == EPOCH_SHA and receipt.get('constructor_sha256') == CONSTRUCTOR_SHA,
                'source view authority changed')
        require(receipt.get('changed_sources') == c.CHANGES and receipt.get('support_inputs') == support
                and receipt.get('current_tooling') == tooling and receipt.get('paired_harness') == manifest['paired_harness']
                and receipt.get('inputs_before_after_match') is True, 'source view binding changed')
        require(set(receipt.get('views', {})) == {'current', 'historical'}, 'source view inventory changed')
        identities = set()
        for name, sources in [('current', new), ('historical', old)]:
            expected = {**sources, **support, **tooling, c.HARNESS_TEMPLATE: c.HARNESS_SHA}
            root = views_root / name
            files = c.file_tree(root)
            require(set(files) == set(expected), 'view file inventory changed: ' + name)
            for relative, wanted in expected.items():
                content, _ = c.file_bytes(files[relative], identities)
                require(hashlib.sha256(content).hexdigest() == wanted, 'view source/support changed: ' + relative)
            row = receipt['views'][name]
            require(row.get('sources') == sources and row.get('source_map_sha256') == c.map_sha(sources)
                    and row.get('files') == expected and row.get('file_map_sha256') == c.map_sha(expected),
                    'view receipt maps disagree with independently authenticated manifest: ' + name)
            require(set(c.production_paths(root)) == set(sources), 'production85 inventory changed')
            require(not (root / c.HARNESS_TARGET).exists(), 'paired template silently materialized')
        guard_rel = manifest['legacy_select']['validator']
        guard = captured_module('unchanged_historical_select_guard', views_root / 'historical' / guard_rel,
                                support[guard_rel])
        facts = guard.validate_current_inputs(views_root / 'historical')
        require((facts['dafny_files'], facts['package_files'], facts['used_inputs']) == (85, 311, 8),
                'historical Select input admission changed')
        return {'manifest': manifest, 'view_receipt': receipt, 'views_root': views_root,
                'view_receipt_sha256': expected_receipt_sha256, 'current_sources': new,
                'current': views_root / 'current', 'historical': views_root / 'historical',
                'legacy_facts': {k: facts[k] for k in ('dafny_files', 'package_files', 'used_inputs')}}
    except (ValueError, OSError) as error:
        if isinstance(error, SelectError):
            raise
        raise SelectError('source view admission failed: ' + str(error)) from error


def classify_proof(text, exit_code, expected, anchors=()):
    matches = SUMMARY.findall(text)
    require(not BAD.search(text) and len(SUMMARY_LINE.findall(text)) == 1 and len(matches) == 1,
            'inconclusive or malformed proof output')
    found = list(map(int, matches[0]))
    require(expected[0] > 0 and found == list(expected), 'focused proof count mismatch/zero filter')
    require(exit_code == (4 if expected[1] else 0), 'unexpected proof exit')
    require(all(anchor in text for anchor in anchors), 'named semantic diagnostic missing')
    return {'verified': found[0], 'errors': found[1], 'exit': exit_code}


def minimal_env(authority):
    env = authority.environment()
    forbidden = {'JDK_JAVAC_OPTIONS', 'JDK_JAVA_OPTIONS', 'JDK_ALTERNATE_VM',
                 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'PYTHONPATH', 'PYTHONHOME',
                 'PYTHONSTARTUP', 'DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS',
                 'DOTNET_SHARED_STORE', 'CORECLR_PROFILER', 'COR_PROFILER'}
    require(not (set(env) & forbidden) and not any(k.startswith(('DYLD_', 'LD_')) for k in env),
            'controlled child environment contains an injection selector')
    return env


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run_tool(argv, cwd, env, out, label, timeout=300):
    logs = out / 'logs'
    logs.mkdir(exist_ok=True)
    stdout, stderr = logs / (label + '.stdout.log'), logs / (label + '.stderr.log')
    with stdout.open('w') as first, stderr.open('w') as second:
        process = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, stdout=first,
                                 stderr=second, timeout=timeout)
    row = {'label': label, 'argv': list(map(str, argv)), 'cwd': str(cwd),
           'exit': process.returncode, 'stdout': str(stdout.relative_to(out)),
           'stderr': str(stderr.relative_to(out)), 'stdout_sha256': sha(stdout),
           'stderr_sha256': sha(stderr)}
    return row, stdout.read_text(errors='replace') + stderr.read_text(errors='replace')


def freeze_program(admission, destination):
    manifest = admission['manifest']
    expected = {**manifest['current']['sources'], **manifest['support_inputs'],
                **manifest['current_tooling'], manifest['paired_harness']['template']: manifest['paired_harness']['sha256']}
    destination.mkdir()
    c = constructor()
    for relative, wanted in expected.items():
        raw, _ = c.file_bytes(admission['current'] / relative)
        require(hashlib.sha256(raw).hexdigest() == wanted, 'source changed during freeze: ' + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    require({n: sha(p) for n, p in c.file_tree(destination).items()} == expected,
            'frozen current source files differ')
    return expected


def hermetic_build(admission, out, dafny, dotnet, targeting_packs, profile_id):
    require(profile_id in PROFILE_SHA, 'unknown reviewed tool profile')
    program = out / 'current-program'
    frozen = freeze_program(admission, program)
    manifest = admission['manifest']
    pkg = program / 'formal/source/select'
    helper = captured_module('frozen_legacy_select_helpers', pkg / 'replay.py',
                             manifest['support_inputs']['formal/source/select/replay.py'])
    package = helper.verify_package(pkg, manifest['support_inputs']['formal/source/select/package.json'])
    profile, profile_identity = helper.load_profile(pkg, profile_id, PROFILE_SHA[profile_id])
    coverage = captured_module('frozen_current_coverage_tools', program / 'formal/source/keccak/coverage_replay.py',
                               manifest['current_tooling']['formal/source/keccak/coverage_replay.py'])
    authority_module = captured_module('frozen_build_authority', program / 'formal/source/keccak/encoder/build_authority.py',
                                      manifest['current_tooling']['formal/source/keccak/encoder/build_authority.py'])
    dafny, dotnet, profile_pins = coverage.check_tool_pins(profile, Path(dafny), Path(dotnet))
    tools_before = coverage.tool_map(dafny.parent, dotnet.parent)
    catalog = (program / 'formal/source/keccak/encoder/net6-targeting-packs.json').read_bytes()
    _, archives, payloads = authority_module.admit_archives(targeting_packs, catalog)
    authority = authority_module.BuildAuthority(out / 'build-authority', catalog, archives, payloads, dotnet.parent)
    build = out / 'checker-build'
    project = build / 'checker'
    project.mkdir(parents=True)
    files = ('SourceCoverage.cs', 'SourceCoverage.csproj', 'NativeCanonicalEncoderPolicy.cs')
    build_inputs = {}
    for name in files:
        raw = (pkg / 'checker' / name).read_bytes()
        wanted = manifest['support_inputs']['formal/source/select/checker/' + name]
        require(hashlib.sha256(raw).hexdigest() == wanted, 'old checker build input changed')
        (project / name).write_bytes(raw)
        build_inputs[name] = wanted
    global_json = {'sdk': {'version': profile['dotnet_sdk'], 'rollForward': 'disable'}}
    write_json(build / 'global.json', global_json)
    commands = []
    for label, argv, expected in [('dafny-version', [dafny, '--version'], profile['dafny_version']),
                                  ('dotnet-version', [dotnet, '--version'], profile['dotnet_sdk'])]:
        row, text = run_tool(argv, build, minimal_env(authority), out, label)
        commands.append(row)
        require(row['exit'] == 0 and text.strip() == expected, 'actual tool version changed: ' + label)
    common = [dotnet, 'msbuild', Path('checker/SourceCoverage.csproj'), *authority.arguments(dafny.parent)]
    row, text = run_tool([*common, '-t:Restore', '-v:minimal'], build, minimal_env(authority), out, 'checker-restore')
    commands.append(row)
    require(row['exit'] == 0, 'isolated old checker restore failed: ' + text[-1500:])
    assets = authority.validate_assets(project / 'obj/project.assets.json')
    row, text = run_tool([*common, '-t:Build', '-v:minimal',
        '-getProperty:' + ','.join([*authority.properties(), 'MSBuildAllProjects']),
        '-getItem:ReferencePath,ReferencePathWithRefAssemblies,Compile,Analyzer,EditorConfigFiles,GlobalAnalyzerConfigFiles,AnalyzerConfigFiles'],
        build, minimal_env(authority), out, 'checker-build')
    commands.append(row)
    require(row['exit'] == 0, 'isolated old checker build failed: ' + text[-1500:])
    start = text.find('{\n')
    require(start >= 0, 'actual MSBuild evaluation JSON missing')
    evaluated, _ = json.JSONDecoder().raw_decode(text[start:])
    policy_path = HERE / 'select-current/evaluation.py'
    evaluation_module = captured_module('select_same_directory_evaluation', policy_path, EVALUATION_SHA)
    evaluation = evaluation_module.validate_evaluation(authority, json.dumps(evaluated), build,
                                                       project, 'SourceCoverage', tools_before)
    dll = project / 'bin/Debug/net6.0/SourceCoverage.dll'
    require(dll.is_file() and sha(dll) == profile['checker_dll_expected_sha256'],
            'fresh hermetic checker differs from reviewed2785 DLL')
    require({name: sha(project / name) for name in files} == build_inputs, 'frozen checker source changed during build')
    authority.verify()
    require(coverage.tool_map(dafny.parent, dotnet.parent) == tools_before, 'installed tool closure changed during build')
    record = {'mode': 'fresh-hermetic-build', 'qualification': False,
              'scope': 'build evidence pending independent consumer review',
              'dll': str(dll), 'dll_sha256': sha(dll), 'expected_dll_sha256': profile['checker_dll_expected_sha256'],
              'inputs': build_inputs, 'global_json_sha256': sha(build / 'global.json'),
              'commands': commands, 'assets': assets, 'evaluation': evaluation,
              'actual_evaluation_json': evaluated, 'evaluation_policy_sha256': sha(policy_path),
              'profile': profile_identity, 'profile_pins': profile_pins,
              'installed_tool_files': tools_before, 'build_authority': authority.record(),
              'unused_profile_scope': ['JDK21', 'JDK25', 'Maven runtime; no Java/codegen/delivery stage'],
              'frozen_current_program': str(program), 'frozen_current_files': frozen}
    write_json(out / 'checker-build.json', record)
    return dll, record, authority, helper, package, program


def load_expectations(path, expected):
    require(expected == EXPECTATIONS_SHA and sha(path) == EXPECTATIONS_SHA,
            'focused expectation policy differs from external selection')
    policy = constructor().load_bytes(Path(path).read_bytes(), 'focused expectations')
    require(policy.get('schema') == 'microproxy.current-select-expectations/1'
            and policy.get('qualification') is False and policy.get('scope') == 'current-select-consumer'
            and policy.get('filter') == FILTER and set(policy.get('matched_symbols', [])) == set(MATCHED),
            'focused policy scope changed')
    return policy


def verify_csv(path, expected, matched=None):
    with Path(path).open() as stream:
        rows = list(csv.DictReader(stream))
    require(len(rows) == sum(expected), 'verification CSV count changed')
    require(sum(r['TestResult.Outcome'] == 'Passed' for r in rows) == expected[0]
            and sum(r['TestResult.Outcome'] == 'Failed' for r in rows) == expected[1], 'CSV outcomes changed')
    symbols = sorted({r['TestResult.DisplayName'].split(' (')[0] for r in rows})
    if matched is not None:
        require(symbols == sorted(matched), 'actual verified symbol set changed')
    return {'sha256': sha(path), 'rows': len(rows), 'symbols': symbols}


def semantic_worker(request_path, request_sha):
    require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'worker requires Python -I -B')
    require(sha(request_path) == request_sha, 'worker request changed')
    request = constructor().load_bytes(Path(request_path).read_bytes(), 'worker request')
    out = Path(request_path).parent.parent
    program = out / 'current-program'
    dll = out / 'checker-build/checker/bin/Debug/net6.0/SourceCoverage.dll'
    require(request['schema'] == 'microproxy.current-select-worker/1', 'worker request schema')
    require(sha(HERE / 'manifest.json') == EPOCH_SHA, 'worker epoch source authority changed')
    manifest = constructor().load_bytes((HERE / 'manifest.json').read_bytes(), 'worker epoch')
    constructor().validate_manifest(manifest)
    policy = load_expectations(HERE / 'select-current/expectations.json', request['policy_sha256'])
    require(sha(dll) == policy['fresh_checker_expected_sha256'], 'worker checker identity changed')
    expected_files = {**manifest['current']['sources'], **manifest['support_inputs'],
                      **manifest['current_tooling'], manifest['paired_harness']['template']: manifest['paired_harness']['sha256']}
    require({n: sha(p) for n, p in constructor().file_tree(program).items()} == expected_files,
            'worker frozen program changed')
    pkg = program / 'formal/source/select'
    helper = captured_module('worker_frozen_select_helpers', pkg / 'replay.py',
                             manifest['support_inputs']['formal/source/select/replay.py'])
    delivery = captured_module('worker_frozen_dependency_helpers', program / 'formal/crypto/delivery.py',
                               manifest['support_inputs']['formal/crypto/delivery.py'])
    package = helper.verify_package(pkg, manifest['support_inputs']['formal/source/select/package.json'])
    dafny = Path(request['dafny'])
    profile, _ = helper.load_profile(pkg, request['profile'], PROFILE_SHA[request['profile']])
    require(sha(dafny) == profile['dafny_sha256'], 'worker Dafny changed')
    for name, pin in profile['boogie'].items():
        require(sha(dafny.parent / name) == pin, 'worker Boogie changed')
    require(not any(k in os.environ for k in ('JDK_JAVAC_OPTIONS', 'JDK_ALTERNATE_VM', 'PYTHONPATH', 'DOTNET_STARTUP_HOOKS'))
            and not any(k.startswith(('DYLD_', 'LD_')) for k in os.environ), 'worker inherited loader selectors')
    result = {'schema': 'microproxy.current-select-semantics/1', 'scope': 'current-select-consumer',
              'qualification': False, 'status': 'running', 'controls': {}, 'proofs': {}, 'parser_records': []}
    (out / 'csv').mkdir()
    def save():
        write_json(out / 'semantics.json', result)
    def formal_map(formal, operand_pin):
        expected = dict(manifest['current']['sources'])
        expected['formal/crypto/NativeMlKem.dfy'] = operand_pin
        actual = {n: sha(p) for n, p in constructor().production_paths(formal.parent).items()}
        require(actual == expected, 'case current85/fixture source substitution')
        return actual
    def plain(entry, formal, label, operand_pin, extra_sources=None):
        source_map = formal_map(formal, operand_pin)
        cmd = [dafny, 'resolve', entry, '--allow-external-contracts']
        prefix, context = helper.case_context(label, entry, cmd, Path(entry).parent)
        rc, text, log = helper.run(cmd, out / 'logs/plain' / (label + '.log'),
                                   cwd=Path(entry).parent, timeout=180, prefix=prefix)
        context = helper.finish_context(context, entry)
        require(rc == 0 and not helper.BAD_DIAG.search(text), 'plain resolution failed: ' + label)
        def dependencies(dep_label, command):
            line, ctx = helper.case_context(label + '-' + dep_label, entry, command, formal.parent)
            status, body, raw_log = helper.run(command, out / 'logs/dependencies' / (label + '-' + dep_label + '.log'),
                                              cwd=formal.parent, timeout=180, prefix=line)
            ctx = helper.finish_context(ctx, entry)
            result['parser_records'].append({'exit': status, 'command': list(map(str, command)),
                'case_context': ctx, 'log': str(raw_log.relative_to(out)), 'log_sha256': sha(raw_log)})
            require(body.startswith(line), 'raw dependency context prefix changed')
            return status, body[len(line):]
        closure = delivery.source_closure(formal.parent, entry, dafny, timeout=180, call=dependencies)
        allowed = dict(source_map, **(extra_sources or {}))
        require(all(allowed.get(n) == pin for n, pin in closure.items()), 'parsed closure outside current case authority')
        row = {'exit': rc, 'command': list(map(str, cmd)), 'case_context': context,
               'log': str(log.relative_to(out)), 'log_sha256': sha(log), 'source_map': source_map,
               'source_map_sha256': map_sha(source_map), 'parser_closure': closure}
        formal_map(formal, operand_pin)
        return row
    def focused(entry, formal, kind, operand_pin):
        expected = policy['focused'][kind]
        csv_path = out / 'csv' / (kind + '.csv')
        row = helper.proof(out, dafny, entry, policy['case_split'][kind], expected[0],
            'focused-' + kind, allow_errors=expected[1], expect_exit=4 if expected[1] else 0,
            timeout=900, extra=['--filter-symbol', FILTER, '--progress', 'Symbol',
                                '--log-format', 'csv;LogFileName=' + str(csv_path)])
        anchors = policy['f2_anchors'] if kind == 'f2' else ()
        classify_proof((out / row['log']).read_text(), row['exit'], expected, anchors)
        row.update(source_map=formal_map(formal, operand_pin), csv=str(csv_path.relative_to(out)),
                   csv_record=verify_csv(csv_path, expected, policy['matched_symbols']))
        result['proofs'][kind] = row
        save()
    try:
        for name in sorted(helper.EXPECTED_CONTROLS):
            formal = helper.prepare_tree(program, out, name)
            operand = formal / 'crypto/NativeMlKem.dfy'
            fixture_pin = package['candidate_overlay_sha256']
            if name != 'positive-actual':
                source = pkg / 'controls' / name / 'NativeMlKem.dfy'
                shutil.copy2(source, operand)
                fixture_pin = sha(source)
            pre = plain(operand, formal, 'plain-' + name, fixture_pin)
            checker = helper.checker_case(program, pkg, out, dafny, dll, name, package)
            source_map = formal_map(formal, fixture_pin)
            result['controls'][name] = {'plain': pre, 'checker': checker,
                                        'source_map': source_map, 'fixture_sha256': fixture_pin}
            save()
        focused(program / 'formal/crypto/NativeMlKem.dfy', program / 'formal', 'positive', package['candidate_overlay_sha256'])
        harness = pkg / 'harness/SelectTraceHarness.dfy'
        result['harness_plain'] = plain(harness, program / 'formal', 'plain-select-harness',
            package['candidate_overlay_sha256'], {'formal/source/select/harness/SelectTraceHarness.dfy': sha(harness)})
        csv_path = out / 'csv/select-harness.csv'
        row = helper.proof(out, dafny, harness, 0, policy['select_harness'][0], 'select-harness',
                           timeout=900, extra=['--log-format', 'csv;LogFileName=' + str(csv_path)])
        classify_proof((out / row['log']).read_text(), row['exit'], policy['select_harness'])
        row.update(csv=str(csv_path.relative_to(out)), csv_record=verify_csv(csv_path, policy['select_harness']))
        result['proofs']['select_harness'] = row
        formal = helper.prepare_tree(program, out, 'observed')
        operand = formal / 'crypto/NativeMlKem.dfy'
        original = pkg / 'controls/observed/NativeMlKem.dfy'
        shutil.copy2(original, operand)
        obs = formal / 'source/select/observed/SelectObservedHarness.dfy'
        obs.parent.mkdir()
        shutil.copy2(pkg / 'controls/observed/SelectObservedHarness.dfy', obs)
        pin = sha(original)
        result['observed_plain'] = plain(operand, formal, 'plain-observed', pin)
        result['observed_harness_plain'] = plain(obs, formal, 'plain-observed-harness', pin,
            {'formal/source/select/observed/SelectObservedHarness.dfy': sha(obs)})
        cmd = [dafny, 'resolve', operand, '--allow-external-contracts', '--plugin', dll]
        prefix, context = helper.case_context('observed', operand, cmd, operand.parent,
                                              plugin=sha(dll), expected=pin)
        rc, text, log = helper.run(cmd, out / 'logs/controls/observed-checker.log', cwd=operand.parent,
                                    env=helper.clean_env(), timeout=180, prefix=prefix)
        context = helper.finish_context(context, operand)
        require(rc == 0 and helper.scope_ok(text) and not helper.BAD_DIAG.search(text), 'observed coverage acceptance failed')
        result['observed_checker'] = {'exit': rc, 'command': list(map(str, cmd)), 'case_context': context,
            'log': str(log.relative_to(out)), 'log_sha256': sha(log), 'fixture_sha256': pin}
        focused(operand, formal, 'observed', pin)
        csv_path = out / 'csv/observed-harness.csv'
        row = helper.proof(out, dafny, obs, 0, policy['observed_harness'][0], 'observed-harness',
            allow_errors=1, expect_exit=4, timeout=600,
            extra=['--log-format', 'csv;LogFileName=' + str(csv_path)])
        classify_proof((out / row['log']).read_text(), row['exit'], policy['observed_harness'], policy['observed_harness_anchors'])
        row.update(csv=str(csv_path.relative_to(out)), csv_record=verify_csv(csv_path, policy['observed_harness']))
        result['proofs']['observed_harness'] = row
        f2formal = out / 'trees/coverage-private-loop-bound/formal'
        focused(f2formal / 'crypto/NativeMlKem.dfy', f2formal, 'f2',
                result['controls']['coverage-private-loop-bound']['fixture_sha256'])
        require(len(result['controls']) == policy['controls'], 'control matrix incomplete')
        result['status'] = 'complete'
        save()
        return 0
    except Exception as error:
        result.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        save()
        raise


# Exact parser closure independently discovered and selected with expectations.json.
NATIVE_CLOSURE = frozenset('formal/crypto/Codec.dfy formal/crypto/JdkHash.dfy formal/crypto/KemSpec.dfy formal/crypto/NativeCodec.dfy formal/crypto/NativeField.dfy formal/crypto/NativeJdkHash.dfy formal/crypto/NativeKeccak.dfy formal/crypto/NativeMlKem.dfy formal/crypto/NativePolynomial.dfy formal/crypto/NativeSampling.dfy formal/crypto/NativeShake.dfy formal/crypto/NativeTypes.dfy formal/crypto/Polynomial.dfy formal/crypto/Sampling.dfy formal/crypto/Shake.dfy formal/crypto/SpongeSpec.dfy formal/primitives/Field.dfy formal/primitives/Keccak.dfy formal/source/SourceTrace.dfy formal/source/vocabulary/ObservationVocabulary.dfy'.split())


def check_semantic_evidence(fragment, out, policy, helper, package, manifest):
    """Check frozen raw evidence without opening any producer absolute path."""
    require(fragment.get('status') == 'complete' and fragment.get('qualification') is False
            and fragment.get('scope') == 'current-select-consumer', 'semantic evidence incomplete')
    require(set(fragment['controls']) == set(helper.EXPECTED_CONTROLS), 'typed control inventory changed')
    native = 'formal/crypto/NativeMlKem.dfy'
    positive_command = fragment['controls']['positive-actual']['plain']['command']
    operand = Path(positive_command[2])
    producer = operand.parents[4]
    dafny = positive_command[0]
    require(producer.is_absolute() and '..' not in producer.parts and Path(dafny).is_absolute(),
            'invalid recorded producer/tool path')
    plugin = str(producer / 'checker-build/checker/bin/Debug/net6.0/SourceCoverage.dll')
    logs = 0
    def sources(row, pin, harness=None):
        wanted = dict(manifest['current']['sources'])
        wanted[native] = pin
        require(row['source_map'] == wanted, 'case source map substituted outside current epoch')
        if 'source_map_sha256' in row:
            require(row['source_map_sha256'] == map_sha(wanted), 'case source-map digest changed')
        if 'parser_closure' in row:
            closure = {n: wanted[n] for n in NATIVE_CLOSURE}
            if harness:
                closure[harness] = manifest['support_inputs'][harness.replace('/observed/', '/controls/observed/')]
            require(row['parser_closure'] == closure, 'exact current parser closure changed')
        return wanted
    def raw(row, command, label, cwd, pin, checker=False):
        nonlocal logs
        relative = Path(row['log'])
        require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe evidence log path')
        path = out / relative
        for part in [path, *path.parents]:
            require(not part.is_symlink(), 'symlink evidence log')
        require(path.is_file() and path.stat().st_nlink == 1 and sha(path) == row['log_sha256'],
                'raw command log digest/identity changed')
        context = {'case': label, 'operand_sha256_before': pin, 'argv': list(map(str, command)),
                   'cwd': str(cwd), 'operand_sha256_after': pin}
        fields = ['case=' + label, 'operand_sha256=' + pin]
        if checker:
            context.update(expected_fixture_sha256=pin, plugin_sha256=policy['fresh_checker_expected_sha256'])
            fields.append('expected_fixture_sha256=' + pin)
        fields += ['argv=' + json.dumps(context['argv'], separators=(',', ':')), 'cwd=' + str(cwd)]
        if checker:
            fields.append('plugin_sha256=' + policy['fresh_checker_expected_sha256'])
        require(row['command'] == context['argv'] and row['case_context'] == context,
                'actual command/context differs from fixed current case')
        if 'cwd' in row:
            require(row['cwd'] == str(cwd), 'recorded working directory changed')
        text = path.read_text()
        require(text.startswith('CASE-CONTEXT ' + ' '.join(fields) + '\n'), 'raw case context changed')
        logs += 1
        return text
    parser_rows = {r['case_context']['case']: r for r in fragment['parser_records']}
    require(len(parser_rows) == len(fragment['parser_records']), 'duplicate parser command context')
    used_parser = set()
    def plain(row, label, root, entry, pin, native_pin, harness=None):
        sources(row, native_pin, harness)
        command = [dafny, 'resolve', str(root / entry), '--allow-external-contracts']
        require(row['exit'] == 0 and not helper.BAD_DIAG.search(raw(row, command, label,
                (root / entry).parent, pin)), 'negative variant was not well typed')
        pending, seen, round_number = {entry}, set(), 0
        while pending:
            name = label + '-dependencies-' + str(round_number)
            require(name in parser_rows, 'missing actual parser command')
            dep = parser_rows[name]
            command = [dafny, '/printIncludes:Immediate', '/noResolve', *[str(root / n) for n in sorted(pending)]]
            text = raw(dep, command, name, root, pin)
            require(dep['exit'] == 0, 'dependency parser failed')
            lines = text.splitlines()[1:]
            require(lines and lines.pop(0) == "Warning: this way of using the CLI is deprecated. Use 'dafny --help' to see help for the new Dafny CLI format",
                    'dependency parser banner changed')
            require(not helper.BAD_DIAG.search('\n'.join(lines)), 'dependency parser diagnostics')
            discovered = set()
            for line in lines:
                require(line and line.strip() == line, 'malformed dependency parser output')
                for value in line.split(';'):
                    path = Path(value)
                    require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(root),
                            'dependency outside recorded current case')
                    relative = path.relative_to(root).as_posix()
                    require(relative in row['parser_closure'], 'unadmitted parser dependency')
                    discovered.add(relative)
            seen.update(pending)
            pending = discovered - seen
            used_parser.add(name)
            round_number += 1
        require(seen == set(row['parser_closure']), 'raw parser commands do not establish exact current closure')
    for name, row in fragment['controls'].items():
        pin = package['candidate_overlay_sha256'] if name == 'positive-actual' else manifest['support_inputs'][
            'formal/source/select/controls/' + name + '/NativeMlKem.dfy']
        require(row['fixture_sha256'] == pin, 'control fixture origin changed')
        sources(row, pin)
        root = producer / 'trees' / name
        plain(row['plain'], 'plain-' + name, root, native, pin, pin)
        checker = row['checker']
        command = [dafny, 'resolve', str(root / native), '--allow-external-contracts', '--plugin', plugin]
        text = raw(checker, command, name, (root / native).parent, pin, True)
        expected = helper.EXPECTED_CONTROLS[name]
        require(not helper.BAD_DIAG.search(text), 'checker output inconclusive')
        if expected['status'] == 'accepted':
            require(checker['exit'] == 0 and helper.scope_ok(text), 'expected current Select coverage acceptance missing')
        else:
            require(checker['exit'] == 2 and expected['needle'] in text, 'named typed rejection missing')
        require(checker['status'] == expected['status'], 'checker verdict changed')
    base = producer / 'current-program'
    observed_root = producer / 'trees/observed'
    obs_pin = manifest['support_inputs']['formal/source/select/controls/observed/NativeMlKem.dfy']
    harness = 'formal/source/select/harness/SelectTraceHarness.dfy'
    obs_harness = 'formal/source/select/observed/SelectObservedHarness.dfy'
    harness_pin = manifest['support_inputs'][harness]
    obs_harness_pin = manifest['support_inputs']['formal/source/select/controls/observed/SelectObservedHarness.dfy']
    plain(fragment['harness_plain'], 'plain-select-harness', base, harness, harness_pin,
          package['candidate_overlay_sha256'], harness)
    plain(fragment['observed_plain'], 'plain-observed', observed_root, native, obs_pin, obs_pin)
    plain(fragment['observed_harness_plain'], 'plain-observed-harness', observed_root, obs_harness,
          obs_harness_pin, obs_pin, obs_harness)
    require(set(parser_rows) == used_parser, 'extra/unbound parser command evidence')
    observed = fragment['observed_checker']
    cmd = [dafny, 'resolve', str(observed_root / native), '--allow-external-contracts', '--plugin', plugin]
    require(observed['fixture_sha256'] == obs_pin and observed['exit'] == 0 and
            helper.scope_ok(raw(observed, cmd, 'observed', (observed_root / native).parent, obs_pin, True)),
            'observed counterexample not coverage-admitted')
    require(set(fragment['proofs']) == {'positive', 'observed', 'f2', 'select_harness', 'observed_harness'},
            'focused proof inventory changed')
    for kind, row in fragment['proofs'].items():
        focused = kind in policy['focused']
        if focused:
            pin = package['candidate_overlay_sha256'] if kind == 'positive' else obs_pin if kind == 'observed' else fragment['controls']['coverage-private-loop-bound']['fixture_sha256']
            sources(row, pin)
            root = base if kind == 'positive' else observed_root if kind == 'observed' else producer / 'trees/coverage-private-loop-bound'
            entry, label, csv_name = root / native, 'focused-' + kind, kind + '.csv'
        else:
            entry = base / harness if kind == 'select_harness' else observed_root / obs_harness
            pin = harness_pin if kind == 'select_harness' else obs_harness_pin
            label, csv_name = kind.replace('_', '-'), kind.replace('_', '-') + '.csv'
        expected = policy['focused'][kind] if focused else policy[kind]
        csv_relative = 'csv/' + csv_name
        require(row['csv'] == csv_relative, 'verifier CSV path changed')
        extra = ['--filter-symbol', FILTER, '--progress', 'Symbol'] if focused else []
        command = [dafny, 'verify', str(entry), *helper.FLAGS, *extra,
                   '--log-format', 'csv;LogFileName=' + str(producer / csv_relative),
                   '--solver-option', 'O:smt.case_split=' + str(policy['case_split'][kind])]
        anchors = policy['f2_anchors'] if kind == 'f2' else policy['observed_harness_anchors'] if kind == 'observed_harness' else ()
        classify_proof(raw(row, command, label, entry.parent, pin), row['exit'], expected, anchors)
        require(verify_csv(out / row['csv'], expected,
            policy['matched_symbols'] if focused else None) == row['csv_record'], 'actual verifier CSV changed')
    return {'raw_logs_rehashed': logs, 'typed_controls': len(fragment['controls']),
            'parser_closure': len(NATIVE_CLOSURE), 'parser_commands': len(used_parser),
            'focused': policy['focused'], 'paired_harness': policy['select_harness'],
            'observed_counterexample': policy['observed_harness']}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['_worker']:
        parser = argparse.ArgumentParser()
        parser.add_argument('_worker')
        parser.add_argument('--request', type=Path, required=True)
        parser.add_argument('--expected-request-sha256', required=True)
        args = parser.parse_args(argv)
        return semantic_worker(args.request, args.expected_request_sha256)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--views-root', type=Path, required=True)
    parser.add_argument('--expected-views-receipt-sha256', required=True)
    parser.add_argument('--expectations', type=Path, default=HERE / 'select-current/expectations.json')
    parser.add_argument('--expected-expectations-sha256', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--dafny', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--targeting-packs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'consumer requires Python -I -B')
    admission = admit_views(args.manifest, args.expected_manifest_sha256, args.views_root,
                            args.expected_views_receipt_sha256)
    policy = load_expectations(args.expectations, args.expected_expectations_sha256)
    out = output_admission(args.output, [args.views_root, args.manifest.parent, HERE,
        args.dafny.resolve().parent, args.dotnet.resolve().parent, args.targeting_packs])
    out.mkdir(mode=0o700)
    result = {'schema': 'microproxy.current-select-consumer/1', 'qualification': False,
              'scope': 'current-select-consumer', 'status': 'running', 'epoch_manifest_sha256': EPOCH_SHA,
              'source_view_receipt_sha256': args.expected_views_receipt_sha256,
              'source_view_root': str(args.views_root), 'expectations_sha256': EXPECTATIONS_SHA,
              'current85': admission['current_sources'], 'historical_input_admission': admission['legacy_facts'],
              'limits': 'Focused Select consumer only. No full NativeMlKem/kernel/functional/Java/delivery/epoch qualification or physical timing claim.'}
    write_json(out / 'report.json', result)
    try:
        dll, build, authority, helper, package, program = hermetic_build(admission, out, args.dafny,
            args.dotnet, args.targeting_packs, args.profile)
        result['checker'] = build
        result['child_environment'] = minimal_env(authority)
        runner = out / 'runner'
        runner.mkdir()
        runner_inputs = {}
        for relative in ['select_replay.py', 'select-current/evaluation.py', 'views.py']:
            raw = (HERE / relative).read_bytes()
            target = runner / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            runner_inputs[relative] = hashlib.sha256(raw).hexdigest()
        (runner / 'manifest.json').write_bytes(args.manifest.read_bytes())
        (runner / 'select-current/expectations.json').write_bytes(args.expectations.read_bytes())
        runner_inputs['manifest.json'] = sha(runner / 'manifest.json')
        runner_inputs['select-current/expectations.json'] = sha(runner / 'select-current/expectations.json')
        requests = out / 'requests'
        requests.mkdir()
        request = {'schema': 'microproxy.current-select-worker/1', 'dafny': str(args.dafny.resolve()),
                   'profile': args.profile, 'policy_sha256': EXPECTATIONS_SHA}
        request_path = requests / 'semantics.json'
        write_json(request_path, request)
        command = [sys.executable, '-I', '-B', runner / 'select_replay.py', '_worker', '--request', request_path,
                   '--expected-request-sha256', sha(request_path)]
        row, text = run_tool(command, out, minimal_env(authority), out, 'semantic-worker', timeout=2400)
        result['semantic_worker'] = row
        require(row['exit'] == 0, 'current Select semantic worker failed: ' + text[-1800:])
        fragment = json.loads((out / 'semantics.json').read_text())
        result['evidence'] = check_semantic_evidence(fragment, out, policy, helper, package, admission['manifest'])
        coverage = captured_module('final_tool_stability', program / 'formal/source/keccak/coverage_replay.py',
                                   admission['manifest']['current_tooling']['formal/source/keccak/coverage_replay.py'])
        require(coverage.tool_map(args.dafny.resolve().parent, args.dotnet.resolve().parent)
                == build['installed_tool_files'], 'installed tool closure changed during replay')
        require({n: sha(p) for n, p in constructor().file_tree(program).items()} == build['frozen_current_files'],
                'frozen current program changed during replay')
        for relative, pin in runner_inputs.items():
            require(sha(runner / relative) == pin, 'captured worker code/input changed')
        admit_views(args.manifest, args.expected_manifest_sha256, args.views_root,
                    args.expected_views_receipt_sha256)
        authority.verify()
        result.update(status='complete', source_inputs_before_after_match=True,
                      tooling_before_after_match=True, captured_runner_inputs=runner_inputs,
                      semantics_sha256=sha(out / 'semantics.json'), build_authority=authority.record())
        write_json(out / 'report.json', result)
        print(json.dumps({'status': 'complete', 'qualification': False, 'scope': result['scope'],
                          'report': str(out / 'report.json')}))
        return 0
    except Exception as error:
        result.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        write_json(out / 'report.json', result)
        raise


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (SelectError, ValueError, OSError) as error:
        print('CURRENT-SELECT FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Bounded actual-capsule controls and cold replay preflight; launches no provers."""
import argparse
import copy
import hashlib
import types
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).absolute().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['policy', 'capsule', 'views', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['policy', 'capsule', 'views', 'runner']:
        parser.add_argument('--expected-' + name + '-sha256', required=True)
    args = parser.parse_args()
    raw = (HERE / 'parent.py').read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.expected_runner_sha256:
        raise ValueError('runner authority changed before capture')
    p = types.ModuleType('selected_parent')
    p.__file__ = str(HERE / 'parent.py')
    exec(compile(raw, p.__file__, 'exec', dont_inherit=True), p.__dict__)
    p.require(sys.flags.isolated and sys.flags.dont_write_bytecode, 'requires -I -B')
    p.require(p.digest(p.file_bytes(HERE / 'parent.py')) == args.expected_runner_sha256, 'runner authority changed')
    policy = p.read_json(p.absolute(args.policy), args.expected_policy_sha256)
    p.validate_policy(policy)
    p.admit_capsule(args.capsule, args.expected_capsule_sha256, policy)
    p.admit_constructed(policy, args.views, args.expected_views_sha256)
    output = p.output_admission(args.output, [HERE, args.policy.parent, args.capsule, args.views])
    output.mkdir(mode=0o700)
    relocated = output / 'relocated-capsule'
    forged = output / 'forged-views'
    shutil.copytree(args.capsule, relocated)
    shutil.copytree(args.views, forged)
    controls = {}
    def rejects(name, fn, needle=None):
        try:
            fn()
        except p.ParentError as error:
            if needle:
                p.require(needle in str(error), 'wrong control rejection: ' + name + ': ' + str(error))
            controls[name] = str(error)
        else:
            raise p.ParentError('negative control accepted: ' + name)
    roots = p.admit_capsule(relocated, args.expected_capsule_sha256, policy)
    rejects('missing-current-prerequisite', lambda: p.explicit_roots(list(roots.items())[:-1], policy))
    bad = copy.deepcopy(policy)
    bad['replacements']['V5/V6'] = 'historical-supported'
    rejects('false-supported-current-dispatch', lambda: p.validate_policy(bad))
    bad = copy.deepcopy(policy)
    bad['reuse'].append('whole-polynomial-package')
    rejects('old-whole-poly-fallback', lambda: p.validate_policy(bad))
    path = relocated / 'project-inputs/formal/crypto/NativeShake.dfy'
    raw = path.read_bytes()
    try:
        path.write_bytes(raw + b'\n// unselected current source\n')
        rejects('current-source-mismatch', lambda: p.check_pins(relocated / 'project-inputs', policy['overlays']))
    finally:
        path.write_bytes(raw)
    name = next(r['log'] for r in policy['evidence']['shake']['checks'] if r['rule']['kind'] == 'proof')
    path = roots['shake'] / name
    raw = path.read_bytes()
    try:
        path.write_bytes(raw + b'\nforged raw proof\n')
        rejects('wrong-raw-log', lambda: p.admit_capsule(relocated, args.expected_capsule_sha256, policy))
    finally:
        path.write_bytes(raw)
    extra = roots['select'] / 'UNSELECTED.log'
    try:
        extra.write_text('supported\n')
        rejects('extra-capsule-inventory', lambda: p.admit_capsule(relocated, args.expected_capsule_sha256, policy))
    finally:
        extra.unlink()
    path = roots['native'] / 'receipt.json'
    raw = path.read_bytes()
    try:
        path.unlink()
        rejects('missing-full-native-receipt', lambda: p.admit_capsule(relocated, args.expected_capsule_sha256, policy))
    finally:
        path.write_bytes(raw)
    poly = p.read_json(roots['poly'] / 'report.json', policy['evidence']['poly']['receipt_sha256'])
    row = poly['closures']['field']
    pins = dict(row['sources'])
    del pins['formal/crypto/NativeTypes.dfy']
    commands = [r for r in poly['commands'] if r['proof'] == 'field' and r['view'] == 'current']
    rejects('actual-parser-omitted-dependency', lambda: p.replay_parser(commands,
            [p.frozen_text(roots['poly'], r) for r in commands], pins, row['target']), 'omitted/unadmitted')
    receipt_path = forged / 'receipt.json'
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    adapter = 'quic/src/main/java/io/github/mahmoudimus/quic/tls/Shake.java'
    path = forged / 'epoch-project' / adapter
    raw = path.read_bytes()
    try:
        path.write_bytes(raw + b'\n// changed adapter behind a coherent receipt\n')
        receipt['epoch_files'][adapter] = p.digest(path.read_bytes())
        receipt_path.write_text(json.dumps(receipt) + '\n')
        rejects('coherent-receipt-changed-epoch-adapter', lambda: p.admit_constructed(policy, forged,
                p.digest(receipt_path.read_bytes())), 'epoch map must equal')
    finally:
        path.write_bytes(raw)
        receipt_path.write_bytes(receipt_raw)
    receipt = json.loads(receipt_raw)
    original = forged / 'baf-project/README.md'
    renamed = original.with_name('README-moved.md')
    try:
        original.rename(renamed)
        for key in ('git_inventory', 'baf_files'):
            receipt[key]['README-moved.md'] = receipt[key].pop('README.md')
        receipt_path.write_text(json.dumps(receipt) + '\n')
        rejects('coherent-receipt-full-baf-extra-missing-file', lambda: p.admit_constructed(policy, forged,
                p.digest(receipt_path.read_bytes())), 'Git tree authentication failed')
    finally:
        renamed.rename(original)
        receipt_path.write_bytes(receipt_raw)
    normal = 'Dafny program verifier finished with 11 verified, 0 errors\n'
    assertions = 'Dafny program verifier finished with 11 assertions verified, 0 errors\n'
    p.classify_log({'kind': 'proof', 'counts': [11, 0]}, 0, normal)
    p.classify_log({'kind': 'proof', 'counts': [11, 0], 'unit': 'assertions '}, 0, assertions)
    rejects('mixed-summary-units', lambda: p.classify_log({'kind': 'proof', 'counts': [11, 0]}, 0, normal + assertions))
    p.admit_capsule(relocated, args.expected_capsule_sha256, policy)
    p.admit_constructed(policy, args.views, args.expected_views_sha256)
    # From this point onward only relocated data, authenticated constructed views
    # and trusted Python may be opened. Original producer/cache paths are denied.
    _, opened = p.restrict_worker_opens([args.views, output])
    old = Path(policy['evidence']['native']['producer_root']) / 'receipt.json'
    rejects('old-private-producer-file-open-denied', lambda: p.file_bytes(old), 'undeclared file open denied')
    views = args.views
    view_receipt = p.read_json(views / 'receipt.json', args.expected_views_sha256)
    baf = views / 'baf-project'
    for module, filename in [('check_select_source', 'check_select_source.py'), ('historical_ledger', 'check_crypto_obligations.py')]:
        legacy = p.captured_module(module, baf / 'scripts/security' / filename,
                                  view_receipt['baf_files']['scripts/security/' + filename])
    historical = legacy.validate_ledger(baf, baf / 'formal/crypto-obligations.json')
    current = p.current_components(policy, views / 'epoch-project', views / 'source-views', roots)
    p.admit_constructed(policy, views, args.expected_views_sha256)
    p.admit_capsule(relocated, args.expected_capsule_sha256, policy)
    report = {'schema': 'microproxy.keccak004-parent-boundary-preflight/1', 'qualification': False,
              'scope': 'actual retained data relocation/negative controls and composed cold preflight; not parent acceptance',
              'status': 'passed', 'artifact_API_called': False, 'controls': controls,
              'policy_sha256': args.expected_policy_sha256, 'runner_sha256': args.expected_runner_sha256,
              'capsule_sha256': args.expected_capsule_sha256, 'views_sha256': args.expected_views_sha256,
              'historical_status': 'HISTORICAL', 'historical': historical, 'current': current,
              'opened_paths': sorted(opened), 'outstanding': p.OUTSTANDING}
    p.write_json(output / 'report.json', report)
    print(json.dumps({'status': 'passed', 'qualification': False, 'controls': len(controls),
                      'report_sha256': p.digest(p.file_bytes(output / 'report.json'))}))


if __name__ == '__main__':
    main()

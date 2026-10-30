#!/usr/bin/env python3
"""Assemble full CI evidence and inspect the delivered native runtime paths.

This does not approve or publish anything. The ordinary delivery validator checks
the full receipt before this envelope is written; stage repeats those checks and
verifies the frozen graph independently. After exact class/JAR acceptance, the
runtime mode applies the same pinned component guard to namespaced class bytes.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil

import delivery


def assemble(dafny, output):
    output = Path(output).resolve(strict=True)
    receipts = sorted((output/'kem').glob('native-kem-*/receipt.json'))
    if len(receipts) != 1:
        raise RuntimeError('Require exactly one fresh complete native KEM receipt')
    manifest = json.loads((delivery.HERE/'delivery.json').read_text())
    sources = delivery.source_closure(delivery.ROOT, delivery.ROOT/manifest['entry'], Path(dafny))
    receipt = receipts[0]
    envelope = {'schema':'microproxy.crypto-input-evidence/v1', 'status':'complete', 'scope':'full',
                'inputs_before':sources, 'inputs_after':sources,
                'receipts':[{'path':receipt.relative_to(output).as_posix(),
                             'sha256':hashlib.sha256(receipt.read_bytes()).hexdigest()}]}
    expected = delivery.native_input_pins(delivery.ROOT, sources, manifest['native_evidence'], Path(dafny))
    delivery.validate_input_evidence(envelope, output, sources, manifest['runtime']['sha256'],
                                    expected_inputs=expected, contract=manifest['native_evidence'])
    destination = output/'inputs.json'
    with destination.open('x') as stream:
        stream.write(json.dumps(envelope, indent=2)+'\n')
    return destination


def check_delivered_runtime(classes, runtime, java_home, output):
    """Apply the pinned component guard after exact class/JAR acceptance."""
    classes, runtime, java_home = (Path(p).resolve(strict=True) for p in (classes, runtime, java_home))
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = output/'receipt.json'
    report = {'schema':'microproxy.crypto-delivered-runtime/v1', 'status':'incomplete',
              'scope':'Existing native runtime discipline guard on delivered namespaced classes; not a JVM timing theorem',
              'classes':str(classes), 'runtime':str(runtime), 'java_home':str(java_home), 'commands':[]}
    receipt.write_text(json.dumps(report, indent=2)+'\n')
    try:
        manifest_path = delivery.HERE/'delivery.json'
        manifest_bytes = manifest_path.read_bytes()
        manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
        manifest = json.loads(manifest_bytes)
        runner = manifest['native_evidence']['runner']
        runner_path = delivery.safe_path(delivery.ROOT, runner['path'])
        code = runner_path.read_bytes()
        if hashlib.sha256(code).hexdigest() != runner['sha256']:
            raise RuntimeError('Native runtime guard runner pin changed')
        # Read the existing package inventory from the pinned runner; do not
        # silently inspect only part of its native execution classes.
        inventories = [ast.literal_eval(node.value) for node in ast.walk(ast.parse(code))
                       if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                       and target.id == 'native_packages' for target in node.targets)]
        if len(inventories) != 1 or not isinstance(inventories[0], set) or len(inventories[0]) != 7:
            raise RuntimeError('Native runtime package inventory changed; review required')
        packages = inventories[0]
        namespace = manifest['namespace'].replace('.', '/')+'/'
        report['classes_before'] = delivery.class_map(classes, [namespace])
        selected = {name:sha for name,sha in report['classes_before'].items()
                    if name[len(namespace):].split('/')[0] in packages}
        if {name[len(namespace):].split('/')[0] for name in selected} != packages:
            raise RuntimeError('Missing delivered native module classes')
        report['native_classes'] = sorted(selected)
        report['runtime_classes_before'] = delivery.check_runtime(runtime, manifest)
        report['jdk_before'] = delivery.tool_tree(java_home)
        report['inputs_before'] = {'manifest':manifest_sha, 'runner':runner['sha256'],
                                   'runtime':delivery.digest(runtime), 'helper':delivery.digest(__file__)}
        frozen_classes = output/'classes'
        delivery.freeze_inputs(classes, report['classes_before'], frozen_classes)
        frozen_runtime = output/'DafnyRuntime.jar'
        shutil.copy2(runtime, frozen_runtime)
        delivery.check_runtime(frozen_runtime, manifest)
        report['class_snapshot'] = str(frozen_classes)
        report['runtime_snapshot'] = str(frozen_runtime)
        checker = {'__file__':str(runner_path), '__name__':'ci_native_runtime_guard'}
        exec(compile(code, str(runner_path), 'exec'), checker)

        def inspect(label, arguments):
            command = [java_home/'bin/javap', '-c', '-p', '-s', *arguments]
            status, text = delivery.run_command(command, output/(label+'.log'), delivery.ROOT, timeout=120)
            report['commands'].append({'label':label, 'command':list(map(str,command)), 'exit':status})
            if status:
                raise RuntimeError('Delivered runtime inspection failed: '+label)
            return text

        owners = [name[:-6].replace('/', '.') for name in sorted(selected)]
        bytecode = inspect('native-bytecode', ['-cp', frozen_classes, *owners])
        helpers = inspect('runtime-helpers', ['-cp', frozen_runtime, 'dafny.Helpers'])
        byte_helpers = inspect('jdk-byte-conversions', ['--module', 'java.base', 'java.lang.Byte'])
        report['native_runtime_guard'] = checker['native_runtime_guards'](bytecode, helpers, byte_helpers)
        report['classes_after'] = delivery.class_map(classes, [namespace])
        report['runtime_classes_after'] = delivery.check_runtime(runtime, manifest)
        report['jdk_after'] = delivery.tool_tree(java_home)
        report['inputs_after'] = {'manifest':delivery.digest(manifest_path), 'runner':delivery.digest(runner_path),
                                  'runtime':delivery.digest(runtime), 'helper':delivery.digest(__file__)}
        delivery.check_tree(frozen_classes, report['classes_before'])
        delivery.check_runtime(frozen_runtime, manifest)
        if any(report[name+'_before'] != report[name+'_after'] for name in ('classes','runtime_classes','jdk','inputs')):
            raise RuntimeError('Delivered class, runner, runtime, JDK or configuration drift')
        report['status'] = 'complete'
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        receipt.write_text(json.dumps(report, indent=2)+'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', nargs='?', choices=('assemble','check-runtime'), default='assemble')
    parser.add_argument('--dafny', type=Path)
    parser.add_argument('--output', type=Path, required=True,
                        help='Replay root for assemble, or a new report directory for check-runtime')
    parser.add_argument('--classes', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--java-home', type=Path)
    args = parser.parse_args()
    if args.mode == 'assemble':
        if args.dafny is None:
            parser.error('assemble requires --dafny')
        print(assemble(args.dafny, args.output))
    else:
        if any(value is None for value in (args.classes,args.runtime,args.java_home)):
            parser.error('check-runtime requires --classes, --runtime and --java-home')
        print(check_delivered_runtime(args.classes,args.runtime,args.java_home,args.output))


if __name__ == '__main__':
    main()

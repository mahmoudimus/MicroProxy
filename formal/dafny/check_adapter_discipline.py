#!/usr/bin/env python3
"""Structural gate for the reviewed production HKDF byte-conversion adapters.

The gate parses the actual compiled method bodies emitted by `javap -p -c`. It rejects any
`DafnySequence.select`/`selectUnsigned` or `Byte.valueOf`/`byteValue` instruction in
`JdkHmac`/`HkdfBridge`, and it requires the `JdkHmac.bytes` method itself to contain:

  * a `DafnySequence.toRawArray()` invocation,
  * a real `instanceof` of the primitive `[B` class,
  * a conditional branch whose fail target lies after the fall-through `checkcast [B` and
    `areturn` (the guarded primitive-return shape), and
  * no dependency on a decoy method elsewhere in the class for those requirements.

`HkdfBridge.bytes` must delegate to `JdkHmac.bytes`. `--self-test` compiles deliberate
old-select-loop, bare-cast and dead-method-decoy mutants and requires rejection. This is a
structural regression guard for the owned conversion path and the reviewed pinned runtime ABI;
it is not a call-graph, Java-refinement, whole-JVM constant-time or memory-noninterference proof.
Generated `LabelInfo` still selects public 16-bit label units; that generated code is outside
this gate and labels are public.
"""
import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TARGETS = (
    ('io.github.mahmoudimus.verifiedcrypto.JdkHmac',
     ROOT / 'quic/src/main/java/io/github/mahmoudimus/verifiedcrypto/JdkHmac.java'),
    ('io.github.mahmoudimus.quic.internal.verifiedhkdf.HkdfBridge',
     ROOT / 'quic/src/main/java/io/github/mahmoudimus/quic/internal/verifiedhkdf/HkdfBridge.java'),
)
SELECT = re.compile(r'Method dafny/DafnySequence\.select(?:Unsigned)?:')
BYTE_VALUE = re.compile(r'Method java/lang/Byte\.(?:valueOf|byteValue):')
TO_RAW = 'Method dafny/DafnySequence.toRawArray:()Ljava/lang/Object;'
BYTE_ARRAY = 'class "[B"'
DELEGATE = 'Method io/github/mahmoudimus/verifiedcrypto/JdkHmac.bytes:'
INSTRUCTION = re.compile(r'^\s*(\d+):\s+(\S+)(.*)$')
CONDITIONAL = {'ifeq', 'ifne', 'iflt', 'ifge', 'ifgt', 'ifle', 'ifnull', 'ifnonnull',
               'if_icmpeq', 'if_icmpne', 'if_icmplt', 'if_icmpge', 'if_icmpgt', 'if_icmple',
               'if_acmpeq', 'if_acmpne'}
OLD_LOOP = '''    {modifier} byte[] bytes(DafnySequence<? extends Byte> sequence) {{
        byte[] result = new byte[sequence.length()];
        for (int i = 0; i < result.length; i++) {{
            result[i] = sequence.select(i);
        }}
        return result;
    }}'''
BARE_CAST = '''    public static byte[] bytes(DafnySequence<? extends Byte> sequence) {{
        Objects.requireNonNull(sequence, "sequence");
        return (byte[]) sequence.toRawArray();
    }}'''
DEAD_DECOY = BARE_CAST + '''

    @SuppressWarnings("unused")
    private static byte[] decoy(DafnySequence<? extends Byte> sequence) {{
        Object raw = sequence.toRawArray();
        if (raw instanceof byte[]) {{
            return (byte[]) raw;
        }}
        return new byte[0];
    }}'''


@dataclass(frozen=True)
class Instruction:
    offset: int
    opcode: str
    operand: str
    comment: str


class AdapterDisciplineError(RuntimeError):
    pass


def instruction(line):
    match = INSTRUCTION.match(line)
    if not match:
        return None
    offset = int(match.group(1))
    opcode = match.group(2)
    rest = match.group(3)
    before, _, after = rest.partition('//')
    operand = before.strip().split()[0] if before.strip() else ''
    return Instruction(offset, opcode, operand, after.strip())


def all_instructions(text):
    result = []
    for line in text.splitlines():
        parsed = instruction(line)
        if parsed is not None:
            result.append(parsed)
    return result


def method_instructions(text, signature):
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith('  ') and signature in line and line.rstrip().endswith(';'):
            start = index
            break
    if start is None:
        raise AdapterDisciplineError('missing compiled method: ' + signature)
    result = []
    for line in lines[start + 1:]:
        parsed = instruction(line)
        if parsed is not None:
            result.append(parsed)
            continue
        if (line.startswith('  ') and '(' in line and line.rstrip().endswith(';')
                and 'Code:' not in line):
            break
    return result


def find(instructions, opcode=None, comment=None, start=0):
    for index in range(start, len(instructions)):
        item = instructions[index]
        if opcode is not None and item.opcode != opcode:
            continue
        if comment is not None and comment not in item.comment:
            continue
        return index
    return None


def byte_shape(instructions):
    failures = []
    raw = find(instructions, 'invokevirtual', TO_RAW)
    instance = find(instructions, 'instanceof', BYTE_ARRAY)
    if raw is None:
        failures.append('JdkHmac.bytes does not call DafnySequence.toRawArray')
    if instance is None:
        failures.append('JdkHmac.bytes has no byte[] instanceof representation check')
    if raw is None or instance is None:
        return failures
    if raw > instance:
        failures.append('JdkHmac.bytes checks representation before toRawArray')
    branch = None
    for index in range(instance + 1, len(instructions)):
        item = instructions[index]
        if item.opcode in CONDITIONAL and item.operand.isdigit():
            branch = index
            break
    cast = find(instructions, 'checkcast', BYTE_ARRAY, instance + 1)
    ret = find(instructions, 'areturn', start=instance + 1)
    if branch is None:
        failures.append('JdkHmac.bytes has no conditional guard after instanceof')
    if cast is None:
        failures.append('JdkHmac.bytes has no primitive byte[] checkcast')
    if ret is None:
        failures.append('JdkHmac.bytes has no primitive byte[] return')
    if branch is None or cast is None or ret is None:
        return failures
    if not (instance < branch < cast < ret):
        failures.append('JdkHmac.bytes guard/cast/return order is not the reviewed shape')
    elif int(instructions[branch].operand) <= instructions[ret].offset:
        failures.append('JdkHmac.bytes conditional branch does not guard the primitive return')
    return failures


def violations(text, fqcn):
    found = []
    for item in all_instructions(text):
        if SELECT.search(item.comment) and 'DafnySequence.select is used on a payload path' not in found:
            found.append('DafnySequence.select is used on a payload path')
        if BYTE_VALUE.search(item.comment) and 'Byte boxing/unboxing is used on a payload path' not in found:
            found.append('Byte boxing/unboxing is used on a payload path')
    try:
        instructions = method_instructions(text, 'byte[] bytes(dafny.DafnySequence')
    except AdapterDisciplineError as error:
        found.append(str(error))
        return found
    if fqcn.endswith('.JdkHmac'):
        for message in byte_shape(instructions):
            if message not in found:
                found.append(message)
    elif fqcn.endswith('.HkdfBridge'):
        delegate = find(instructions, 'invokestatic', DELEGATE)
        ret = find(instructions, 'areturn', start=delegate + 1) if delegate is not None else None
        if delegate is None:
            found.append('HkdfBridge.bytes does not delegate to JdkHmac.bytes')
        elif ret is None:
            found.append('HkdfBridge.bytes delegation is not returned')
    else:
        found.append('unknown target class')
    return found


def javap(java_home, classpath, fqcn):
    command = [str(java_home / 'bin/javap'), '-p', '-c', '-classpath', classpath, fqcn]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AdapterDisciplineError('javap failed for ' + fqcn + ': ' + (result.stdout + result.stderr)[-4000:])
    return result.stdout + result.stderr


def check_classes(java_home, classes, runtime, support=None):
    entries = [str(classes)]
    if support is not None:
        entries.append(str(support))
    entries.append(str(runtime))
    classpath = os.pathsep.join(entries)
    failures = []
    for fqcn, _ in TARGETS:
        found = violations(javap(java_home, classpath, fqcn), fqcn)
        if found:
            failures.append(fqcn + ': ' + '; '.join(found))
    if failures:
        raise AdapterDisciplineError('Payload conversion discipline failed: ' + ' | '.join(failures))


def replace_method(source, signature, replacement):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return source[:start] + replacement + source[index + 1:]
    raise AdapterDisciplineError('Unbalanced method in adapter source: ' + signature)


def compile_mutant(java_home, classes, runtime, source_path, signature, replacement, workspace, name):
    mutated = replace_method(source_path.read_text(), signature, replacement)
    source = workspace / name / source_path.name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(mutated)
    output = workspace / (name + '-classes')
    output.mkdir()
    command = [str(java_home / 'bin/javac'), '--release', '21', '-g:lines,vars,source',
               '-encoding', 'UTF-8', '-Xpkginfo:always', '-Xlint:all,-serial,-cast,-rawtypes',
               '-cp', os.pathsep.join((str(classes), str(runtime))), '-d', str(output), str(source)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode or (result.stdout + result.stderr).strip():
        raise AdapterDisciplineError('Mutant compilation failed or warned: '
                                     + (result.stdout + result.stderr)[-4000:])
    return output


def self_test(java_home, classes, runtime):
    mutants = []
    for fqcn, source in TARGETS:
        modifier = 'public static' if fqcn.endswith('.JdkHmac') else 'private static'
        signature = f'{modifier} byte[] bytes(DafnySequence<? extends Byte> sequence)'
        name = fqcn.rsplit('.', 1)[-1]
        mutants.append((name + '-select-loop', fqcn, source, signature,
                        OLD_LOOP.format(modifier=modifier), 'select'))
    jdk = 'io.github.mahmoudimus.verifiedcrypto.JdkHmac'
    jdk_source = dict(TARGETS)[jdk]
    jdk_signature = 'public static byte[] bytes(DafnySequence<? extends Byte> sequence)'
    mutants.append(('JdkHmac-bare-cast', jdk, jdk_source, jdk_signature, BARE_CAST, 'instanceof'))
    mutants.append(('JdkHmac-dead-decoy', jdk, jdk_source, jdk_signature, DEAD_DECOY, 'instanceof'))
    with tempfile.TemporaryDirectory(prefix='hkdf-adapter-control-') as name:
        workspace = Path(name)
        for label, fqcn, source, signature, replacement, expected in mutants:
            mutant = compile_mutant(java_home, classes, runtime, source, signature, replacement,
                                    workspace, label)
            try:
                check_classes(java_home, mutant, runtime, support=classes)
            except AdapterDisciplineError as error:
                if expected not in str(error):
                    raise AdapterDisciplineError(
                        f'{label} was rejected for the wrong reason: {error}')
                continue
            raise AdapterDisciplineError('Mutant was accepted: ' + label)
    print('adapter control: select-loop, bare-cast and dead-decoy mutants rejected')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, default=Path(os.environ.get('JAVA_HOME', '')))
    parser.add_argument('--classes', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    java_home = args.java_home.expanduser().resolve()
    if not (java_home / 'bin/javap').is_file():
        parser.error('Set JAVA_HOME (or pass --java-home) to a JDK 21+ installation')
    try:
        check_classes(java_home, args.classes.resolve(), args.runtime.resolve())
        print('adapter discipline: JdkHmac.bytes has the guarded primitive byte[] shape; '
              'HkdfBridge delegates')
        if args.self_test:
            self_test(java_home, args.classes.resolve(), args.runtime.resolve())
    except AdapterDisciplineError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

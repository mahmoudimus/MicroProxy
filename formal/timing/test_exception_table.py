"""Fail-closed regression for `javap` exception tables in the extractor.

RED against the reviewed extractor (`bytecode_trace.py` at HEAD `debedb4`):
`javap` prints a non-numeric header row (`from    to  target type`) before the
numeric exception-table rows. The parser treated that header as an unknown line
and left table state before reading a single row, so `Method.handlers` stayed
empty, `Method.exception_table` did not exist, and real `try`/`catch`,
`catch (Throwable)` and `try`/`finally` methods translated into certificates
whose handler blocks were silently dropped — and which then verified.

GREEN against the patched extractor: presence is recorded from the actual
`javap` header in every parser state, the header row is skipped instead of
ending parsing, well-formed rows are preserved verbatim as
`(start, end, handler, type)` tuples, a row-shaped but unparseable line is a hard
parse error, and the translator rejects **any** method with a declared table
(`exception table is outside the accepted language`) regardless of whether a row
was readable.

The controls compile real JDK 21 sources with `javac -g --release 21` and read
real `javap -c -p -s` output. Expected rows are extracted from the raw javap text
by this module's own reader (`raw_rows`), not from the parser under test, so an
implementation that drops, reorders or invents rows cannot pass. Sources live
here rather than in the reviewed `fixtures/` inventory on purpose: that inventory
is asserted exactly by `test_trace.py::test_fixture_inventory_is_explicit`, and
this module tests the gate, not a traceable fixture.

The second half of the module covers the adjacent method-*boundary* defect
(reviewer F1): the reviewed header rule only recognised declarations ending in
`);`, so a real `javap` declaration ending in `throws ...;` was missed, its
`Code:` array was appended to the preceding method with duplicate offsets, and a
table-free example was still accepted with the sibling's body silently dropped.
The extractor now recognises `throws` declarations, rejects duplicate or
non-increasing bytecode offsets before building a control-flow graph, and rejects
orphan/repeated `Code:` arrays and descriptors that are not bound to a recognised
member.

What the RED evidence here can and cannot show (reviewer F5): against the
originally reviewed extractor (HEAD `debedb4`, no `exception_table` field) the
exception-table subtests fail with `AttributeError`, so this module alone does
not exhibit the old *acceptance*; that acceptance is demonstrated independently
by a scratch probe that imports the old module and verifies the emitted
certificate. Against the intermediate extractor (`ab9c1ea9`, table guard only)
the boundary tests below are the real RED: they fail on behaviour, not attributes.

Scope: finite parse/rejection control only (two independent artifacts: raw javap
text and the extractor's verdict). Ordinary implicit exceptions of unhandled
methods remain outside the observer as before; semantic exception handling is
still not modelled, and this is not a JVM-semantics or timing theorem.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bytecode_trace as bt  # noqa: E402

JDK = Path(os.environ.get(
    'JAVA_HOME', '/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home'))
JAVAC = JDK / 'bin/javac'
JAVAP = JDK / 'bin/javap'

#: Reviewed call/static classification. The exception-table gate fires before any
#: parameter or call classification is consulted, but the positive control (a
#: method with no table) must translate under the real policy to be meaningful.
POLICY = json.loads((HERE / 'policy.json').read_text())

SOURCES = {
    'CatchTable': '''package probes;
import java.util.Objects;
/** One protected range with a typed catch. */
public final class CatchTable {
    public static int run(byte[] value) {
        Objects.requireNonNull(value, "value");
        try {
            return value[0];
        } catch (RuntimeException error) {
            return -1;
        }
    }
}
''',
    'CatchAllTable': '''package probes;
import java.util.Objects;
/** Catch-all handler: javap writes `Class java/lang/Throwable`. */
public final class CatchAllTable {
    public static int run(byte[] value) {
        Objects.requireNonNull(value, "value");
        try {
            return value[0] + value[value.length - 1];
        } catch (Throwable error) {
            return value.length;
        }
    }
}
''',
    'FinallySingle': '''package probes;
import java.util.Objects;
/** try/finally only: javap writes one `any` handler for the finally path. */
public final class FinallySingle {
    public static int run(byte[] value) {
        Objects.requireNonNull(value, "value");
        try {
            return value[0];
        } finally {
            value[0] = 0;
        }
    }
}
''',
    'CatchFinally': '''package probes;
import java.util.Objects;
/** catch plus finally: three rows, one typed and two `any`. */
public final class CatchFinally {
    public static int run(byte[] value) {
        Objects.requireNonNull(value, "value");
        try {
            return value[0];
        } catch (RuntimeException error) {
            return -1;
        } finally {
            value[0] = 0;
        }
    }
}
''',
    'NoTable': '''package probes;
import java.util.Objects;
/** Control: a method with no protected range must still translate. */
public final class NoTable {
    public static int run(byte[] value) {
        Objects.requireNonNull(value, "value");
        return value.length;
    }
}
''',
    'ThrowsNoTable': '''package probes;
/** javap ends these declarations with `throws`, not `);`. No protected ranges. */
public final class ThrowsNoTable {
    public static int before(byte[] value) { return value.length; }
    public static int helper(byte[] value) throws java.io.IOException { return value[0] + 1; }
    public static int after(byte[] value) throws java.io.IOException, RuntimeException {
        return value.length + 2;
    }
}
''',
    'ThrowsWithTable': '''package probes;
/** Table-free method first, then a `throws` sibling that owns a table. */
public final class ThrowsWithTable {
    public static int run(byte[] value) { return value.length; }
    public static int helper(byte[] value) throws java.io.IOException {
        try {
            return value[0];
        } catch (RuntimeException error) {
            return -1;
        }
    }
}
''',
    'AbstractAndFields': '''package probes;
/** Valid members without a `Code:` array, plus a field, must still parse. */
public abstract class AbstractAndFields {
    static final byte[] EMPTY = new byte[0];
    public abstract int abstractRun(byte[] value);
    public native int nativeRun(byte[] value);
}
''',
}

RUN = 'run:([B)I'
TABLES = ('CatchTable', 'CatchAllTable', 'FinallySingle', 'CatchFinally')

_CLASSES = None


def setUpModule():
    global _CLASSES
    _CLASSES = tempfile.TemporaryDirectory()
    root = Path(_CLASSES.name)
    for name, text in SOURCES.items():
        (root / (name + '.java')).write_text(text)
    completed = subprocess.run(
        [str(JAVAC), '-g', '--release', '21', '-d', str(root)]
        + [str(root / (name + '.java')) for name in SOURCES],
        capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError('Could not compile exception-table probes: '
                           + completed.stderr[-2000:])


def tearDownModule():
    if _CLASSES is not None:
        _CLASSES.cleanup()


def classes_dir() -> Path:
    return Path(_CLASSES.name)


def raw_javap(name: str) -> str:
    completed = subprocess.run(
        [str(JAVAP), '-c', '-p', '-s', '-classpath', str(classes_dir()), 'probes.' + name],
        capture_output=True, text=True, timeout=120)
    if completed.returncode:
        raise RuntimeError('javap failed: ' + completed.stderr.strip())
    return completed.stdout


HEADER = re.compile(r'from\s+to\s+target\s+type')
ROW = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S.*)$')


def raw_rows(text: str) -> list[tuple[int, int, int, str]]:
    """Independent javap-format reader for the declared protected ranges.

    Deliberately written from the javap format (header row included) rather than
    from the parser under test.
    """
    rows, in_table = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('Exception table:'):
            in_table = True
            continue
        if not in_table:
            continue
        if HEADER.fullmatch(stripped):
            continue
        match = ROW.match(line)
        if match:
            rows.append((int(match[1]), int(match[2]), int(match[3]), match[4].strip()))
            continue
        if stripped in ('', '}'):
            in_table = False
    return rows


def raw_header_before_rows(text: str) -> bool:
    """True when javap prints the non-numeric header row before the first row."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith('Exception table:'):
            tail = [l.strip() for l in lines[index + 1:index + 4]]
            if not any(HEADER.fullmatch(l) for l in tail):
                return False
            return any(ROW.match(l) for l in tail[1:])
    return False


def methods(name: str):
    return bt.disassemble(JAVAP, classes_dir(), 'probes.' + name)


def params_for(descriptor: str) -> list[str]:
    """Conservative fixture parameters: arrays and Dafny sequences are secret."""
    arguments, _ = bt.descriptor_types(descriptor)
    out = []
    for argument in arguments:
        if argument.startswith('['):
            out.append('array_sec')
        elif 'DafnySequence' in argument:
            out.append('seq_sec')
        else:
            out.append('pub')
    return out


def translate(method: bt.Method):
    owner = method.owner
    spec = {'methods': {f'{method.name}:{method.descriptor}':
                        {'params': params_for(method.descriptor)}},
            'fields': {}}
    policy = {'calls': POLICY['calls'], 'statics': POLICY['statics'],
              'classes': {owner: spec}}
    return bt.translate(method, policy, spec)


class ExceptionTableRegressionTests(unittest.TestCase):
    def assert_rejected(self, method: bt.Method):
        with self.assertRaises(bt.PolicyError) as caught:
            translate(method)
        self.assertIn('exception table is outside the accepted language',
                      str(caught.exception))
        return str(caught.exception)

    def test_real_javap_header_precedes_numeric_rows(self):
        # Ground truth for the regression: the header row really exists and really
        # precedes the rows. The reviewed parser stopped on this line.
        for name in TABLES:
            with self.subTest(name=name):
                text = raw_javap(name)
                self.assertTrue(raw_header_before_rows(text), name)
                self.assertTrue(raw_rows(text), name)

    def test_catch_table_is_recorded_with_exact_rows_and_rejected(self):
        expected = raw_rows(raw_javap('CatchTable'))
        self.assertEqual([(7, 10, 11, 'Class java/lang/RuntimeException')], expected)
        method = methods('CatchTable')[RUN]
        self.assertTrue(method.exception_table)
        self.assertEqual(expected, method.handlers)
        self.assert_rejected(method)

    def test_catch_all_finally_and_mixed_forms_are_recorded_and_rejected(self):
        text = raw_javap('CatchAllTable')
        expected = raw_rows(text)
        self.assertEqual(['Class java/lang/Throwable'], [row[3] for row in expected])

        finally_rows = raw_rows(raw_javap('FinallySingle'))
        self.assertEqual(['any'], [row[3] for row in finally_rows])

        mixed = raw_rows(raw_javap('CatchFinally'))
        self.assertEqual(3, len(mixed), mixed)
        self.assertEqual(['Class java/lang/RuntimeException', 'any', 'any'],
                         [row[3] for row in mixed])

        for name in ('CatchAllTable', 'FinallySingle', 'CatchFinally'):
            with self.subTest(name=name):
                expected_rows = raw_rows(raw_javap(name))
                method = methods(name)[RUN]
                self.assertTrue(method.exception_table)
                # Order and values are preserved verbatim; no synthesized tuples.
                self.assertEqual(expected_rows, method.handlers)
                self.assert_rejected(method)

    def test_handler_targets_are_real_code_offsets(self):
        # The protected handler blocks that the reviewed parser dropped are real
        # instructions, so their loss was a real loss of control flow.
        text = raw_javap('CatchFinally')
        offsets = {int(m[1]) for m in
                   (re.match(r'^\s*(\d+):', line) for line in text.splitlines()) if m}
        for _, _, handler, _ in raw_rows(text):
            self.assertIn(handler, offsets)
        self.assertTrue({'astore_1', 'astore_3'} & set(text.split()))

    def test_unhandled_method_still_translates(self):
        # Control against over-rejection: no table, no rejection, clean audit.
        text = raw_javap('NoTable')
        self.assertNotIn('Exception table:', text)
        method = methods('NoTable')[RUN]
        self.assertFalse(method.exception_table)
        self.assertEqual([], method.handlers)
        result = translate(method)
        self.assertEqual([], bt.audit_certificate(result))

    def test_table_presence_is_counted_from_raw_text(self):
        # Property control: the number of methods flagged as carrying a table must
        # equal the number of tables javap actually printed in that class file.
        for name in (*TABLES, 'NoTable'):
            with self.subTest(name=name):
                text = raw_javap(name)
                flagged = [m for m in methods(name).values() if m.exception_table]
                self.assertEqual(text.count('Exception table:'), len(flagged), name)
                for method in flagged:
                    self.assertEqual(raw_rows(text), method.handlers)

    def test_declared_table_without_readable_rows_fails_closed(self):
        # Presence is the load-bearing fact, not a successfully parsed row: a
        # declared table with no rows must never be accepted. The synthetic text
        # mirrors the javap shape; the verdict is produced by the extractor.
        synthetic = '''public final class Synthetic {
  public static int run(byte[]);
    descriptor: ([B)I
    flags: (0x0009) ACC_PUBLIC, ACC_STATIC
    Code:
       0: iconst_0
       1: ireturn
    Exception table:

}
'''
        parsed = bt.parse(synthetic, 'probes/Synthetic')
        method = parsed[RUN]
        self.assertTrue(method.exception_table)
        self.assertEqual([], method.handlers)
        self.assert_rejected(method)

    def test_malformed_row_is_a_hard_parse_error(self):
        # A row-shaped but unparseable line must not be skipped: its protected
        # range would otherwise vanish from the recorded metadata.
        synthetic = '''public final class Broken {
  public static int run(byte[]);
    descriptor: ([B)I
    Code:
       0: iconst_0
       1: ireturn
    Exception table:
       from    to  target type
           7    10   eleven   Class java/lang/RuntimeException
}
'''
        with self.assertRaises(bt.PolicyError) as caught:
            bt.parse(synthetic, 'probes/Broken')
        self.assertIn('malformed exception table row', str(caught.exception))


MEMBER_DECL = re.compile(r'^  \S')


def raw_members(text: str) -> list[dict]:
    """Independent javap member-block reader.

    `javap -c -p -s` prints a member declaration at exactly two spaces of
    indentation and its attributes/instructions deeper. Everything from one
    declaration up to the next belongs to that member; this reader never
    consults the parser under test, so it can detect merged or dropped bodies.
    """
    blocks: list[dict] = []
    current = None
    for line in text.splitlines():
        if MEMBER_DECL.match(line) and line.rstrip().endswith(';'):
            current = {'decl': line.strip(), 'lines': []}
            blocks.append(current)
        if current is not None:
            current['lines'].append(line)
    for block in blocks:
        block['offsets'] = [int(m.group(1)) for line in block['lines']
                            for m in [re.match(r'^\s+(\d+):', line)] if m]
        block['has_code'] = any(line.strip() == 'Code:' for line in block['lines'])
        block['has_table'] = any(line.strip().startswith('Exception table:')
                                 for line in block['lines'])
        block['has_descriptor'] = any(line.strip().startswith('descriptor:')
                                      for line in block['lines'])
    return blocks


def raw_method_keys(blocks: list[dict]) -> set[str]:
    """Independent `name:descriptor` keys for every raw javap *method* member.

    Derived from the raw declaration text and the raw `descriptor:` line, so it
    can prove that every member javap printed is addressable and that no field
    or merged body became a method.
    """
    keys = set()
    for block in blocks:
        descriptor = next((line.split('descriptor:', 1)[1].strip()
                           for line in block['lines']
                           if line.strip().startswith('descriptor:')), None)
        if descriptor is None:
            continue
        declaration = block['decl']
        if declaration.replace(' ', '') in ('static{};', 'static{}'):
            keys.add('<clinit>:' + descriptor)
            continue
        if '(' not in declaration:
            continue
        keys.add(declaration.split('(')[0].split()[-1] + ':' + descriptor)
    return keys


def is_strictly_increasing(values: list[int]) -> bool:
    return all(b > a for a, b in zip(values, values[1:]))


def step_kinds(result: dict) -> list[tuple]:
    return [inst['kind'] for inst in result['code'] if inst['type'] == 'step']


class MethodBoundaryRegressionTests(unittest.TestCase):
    """Reviewer F1: `throws` declarations and merged/duplicated member bodies."""

    def block_for(self, name: str, method_name: str) -> dict:
        matches = [b for b in raw_members(raw_javap(name))
                   if re.search(r'(?<![\w$])' + re.escape(method_name) + r'\(', b['decl'])]
        self.assertEqual(1, len(matches), 'ambiguous raw javap block for ' + method_name)
        return matches[0]

    def test_throws_declarations_are_distinct_methods(self):
        # Raw javap: three method declarations end in `throws ...;`. Each must own
        # its own Method object with exactly its own instructions, in order.
        parsed = methods('ThrowsNoTable')
        for name in ('before', 'helper', 'after'):
            key = name + ':([B)I'
            self.assertIn(key, parsed)
            block = self.block_for('ThrowsNoTable', name)
            self.assertTrue(block['has_code'], name)
            offsets = [insn.offset for insn in parsed[key].insns]
            self.assertEqual(block['offsets'], offsets)
            self.assertTrue(is_strictly_increasing(offsets), offsets)
            self.assertFalse(parsed[key].exception_table)
        # Every member javap printed is addressable, and nothing else is.
        self.assertEqual(raw_method_keys(raw_members(raw_javap('ThrowsNoTable'))),
                         set(parsed))

    def test_throws_methods_translate_with_their_own_code(self):
        parsed = methods('ThrowsNoTable')
        expectations = {'before': False, 'helper': True, 'after': True}
        for name, has_add in expectations.items():
            block = self.block_for('ThrowsNoTable', name)
            result = translate(parsed[name + ':([B)I'])
            sites = {site['offset'] for site in result['sites']}
            self.assertTrue(sites, name)
            self.assertTrue(sites <= set(block['offsets']),
                            (name, sorted(sites - set(block['offsets']))))
            self.assertTrue(result['code'])
            self.assertEqual(has_add,
                             any(kind[:2] == ('op', 'add') for kind in step_kinds(result)),
                             name)

    def test_throws_sibling_with_table_keeps_identity(self):
        # Table-free `run` precedes a `throws` sibling that owns a table.
        parsed = methods('ThrowsWithTable')
        self.assertEqual(raw_method_keys(raw_members(raw_javap('ThrowsWithTable'))),
                         set(parsed))
        run, helper = parsed['run:([B)I'], parsed['helper:([B)I']
        run_block = self.block_for('ThrowsWithTable', 'run')
        helper_block = self.block_for('ThrowsWithTable', 'helper')
        self.assertTrue(helper_block['has_table'])
        self.assertFalse(run_block['has_table'])
        self.assertFalse(run.exception_table)
        self.assertEqual([], run.handlers)
        self.assertEqual(run_block['offsets'], [insn.offset for insn in run.insns])
        self.assertTrue(helper.exception_table)
        self.assertTrue(helper.handlers)
        self.assertEqual(helper_block['offsets'], [insn.offset for insn in helper.insns])
        # The table-free sibling still certifies with its own instructions.
        result = translate(run)
        self.assertTrue({site['offset'] for site in result['sites']}
                        <= set(run_block['offsets']))
        # The table-bearing sibling is rejected by the table gate, not by merge.
        with self.assertRaises(bt.PolicyError) as caught:
            translate(helper)
        self.assertIn('exception table is outside the accepted language',
                      str(caught.exception))

    def test_abstract_native_members_and_fields_still_parse(self):
        parsed = methods('AbstractAndFields')
        self.assertIn('<clinit>:()V', parsed)
        for key in ('abstractRun:([B)I', 'nativeRun:([B)I'):
            self.assertIn(key, parsed)
            self.assertEqual([], parsed[key].insns)
            self.assertFalse(parsed[key].exception_table)
        # Every method member is addressable (including `<clinit>` and the
        # constructor) and the field is not a method.
        self.assertEqual(raw_method_keys(raw_members(raw_javap('AbstractAndFields'))),
                         set(parsed))
        self.assertFalse([key for key in parsed if key.startswith('EMPTY')])

    def test_duplicate_offsets_fail_closed_before_cfg(self):
        # (a) a real javap-shaped member body whose offsets repeat
        duplicate = '''public final class Dup {
  public static int run(byte[]);
    descriptor: ([B)I
    Code:
       0: aload_0
       1: arraylength
       1: ireturn
}
'''
        with self.assertRaises(bt.PolicyError) as caught:
            bt.parse(duplicate, 'probes/Dup')
        self.assertIn('offset', str(caught.exception))
        # (b) a hand-built Method with duplicate offsets is refused by the
        # translator before any control-flow graph is built
        insns = [bt.Insn(0, 'aload_0', '', '0: aload_0'),
                 bt.Insn(1, 'arraylength', '', '1: arraylength'),
                 bt.Insn(1, 'ireturn', '', '1: ireturn')]
        method = bt.Method('probes/Dup', 'run', '([B)I', True, {'ACC_STATIC'}, insns)
        class_policy = {'methods': {'run:([B)I': {'params': ['array_sec']}}, 'fields': {}}
        with self.assertRaises(bt.PolicyError) as caught:
            bt.translate(method, {'calls': POLICY['calls'], 'statics': POLICY['statics'],
                                  'classes': {'probes/Dup': class_policy}}, class_policy)
        self.assertIn('offset', str(caught.exception))

    def test_orphan_and_repeated_code_arrays_fail_closed(self):
        orphan = '''public final class Orphan {
  public static final int X;
    descriptor: I
    Code:
       0: iconst_0
       1: ireturn
}
'''
        with self.assertRaises(bt.PolicyError) as caught:
            bt.parse(orphan, 'probes/Orphan')
        self.assertIn('Code', str(caught.exception))
        repeated = '''public final class Repeat {
  public static int run(byte[]);
    descriptor: ([B)I
    Code:
       0: iconst_0
       1: ireturn
    Code:
       0: iconst_1
       1: ireturn
}
'''
        with self.assertRaises(bt.PolicyError) as caught:
            bt.parse(repeated, 'probes/Repeat')
        self.assertIn('Code', str(caught.exception))

    def test_unbound_descriptor_and_misshapen_member_fail_closed(self):
        # A descriptor with no recognised member before it
        unbound = '''public final class Unbound {
    descriptor: I
  public static int run(byte[]);
    descriptor: ([B)I
    Code:
       0: iconst_0
       1: ireturn
}
'''
        with self.assertRaises(bt.PolicyError) as caught:
            bt.parse(unbound, 'probes/Unbound')
        self.assertIn('descriptor', str(caught.exception))
        # A member declaration the parser cannot recognise must not hand its
        # body to the preceding method.
        misshapen = '''public final class Misshapen {
  public static int run(byte[] v) throws;
    descriptor: ([B)I
    Code:
       0: iconst_0
       1: ireturn
}
'''
        with self.assertRaises(bt.PolicyError):
            bt.parse(misshapen, 'probes/Misshapen')


if __name__ == '__main__':
    unittest.main()

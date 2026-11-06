"""Finite actual-CSV/error-family admission for this selected HKDF proof plan."""
import collections, csv, io, re
HEADER = ['TestResult.DisplayName', 'TestResult.Outcome', 'TestResult.Duration', 'TestResult.ResourceCount', 'RandomSeed']
DISPLAY = re.compile('^([^()]+) \\((correctness|well-formedness)\\)(?: \\(assertion batch ([1-9][0-9]*)\\))?$')
BAD = re.compile('timed?\\s*out|timeout|out of resource|out of memory|inconclusive|internal error|unhandled exception|parse errors?|resolution/type errors|CLI: Error', re.I)
SUMMARY = re.compile('Dafny program verifier finished with ([0-9]+) verified, ([0-9]+) errors?')
LOCATION = re.compile('^([^\\r\\n|]+)\\(([0-9]+),([0-9]+)\\): (Error|Related location): ([^\\r\\n]+)$', re.M)

def rows(raw):
    reader = csv.DictReader(io.StringIO(raw))
    if not reader.fieldnames == HEADER:
        raise ValueError('unexpected/empty CSV header')
    result = list(reader)
    if not result:
        raise ValueError('empty actual VC CSV')
    names = [r['TestResult.DisplayName'] for r in result]
    if not len(names) == len(set(names)):
        raise ValueError('duplicate actual VC')
    families = collections.defaultdict(list)
    for row in result:
        name = DISPLAY.fullmatch(row['TestResult.DisplayName'])
        if not name:
            raise ValueError('unknown VC name form')
        if not row['RandomSeed'] == '0':
            raise ValueError('seed differs')
        if not row['TestResult.Outcome'] in ('Passed', 'Failed'):
            raise ValueError('resource/timeout/skipped VC is not semantic credit')
        if not int(row['TestResult.ResourceCount']) >= 0:
            raise ValueError('proof admission check failed')
        families[name[1], name[2]].append(int(name[3]) if name[3] else None)
    for family, numbers in families.items():
        if None in numbers:
            if not numbers == [None]:
                raise ValueError(('mixed/duplicate unnumbered family', family))
        elif not sorted(numbers) == list(range(1, len(numbers) + 1)):
            raise ValueError(('gapped assertion family', family))
    return (result, families)

def positive(code, log, csv_raw, prefix, required_methods=(), required_function=None):
    if not (code == 0 and (not BAD.search(log)) and ('warning' not in log.lower())):
        raise ValueError('nonpassing positive execution')
    data, families = rows(csv_raw)
    if not all((r['TestResult.Outcome'] == 'Passed' for r in data)):
        raise ValueError('proof admission check failed')
    summary = SUMMARY.findall(log)
    if not (len(summary) == 1 and tuple(map(int, summary[0])) == (len(data), 0)):
        raise ValueError('incomplete positive summary')
    if not all((symbol.startswith(prefix) for symbol, kind in families)):
        raise ValueError('unexpected own-file proof scope')
    for method in required_methods:
        if not (method, 'correctness') in families:
            raise ValueError(('required body absent', method))
    if required_function:
        if not (required_function, 'well-formedness') in families:
            raise ValueError(('required function contracts/WF absent', required_function))
    return {'rows': len(data), 'families': {symbol + ' (' + kind + ')': len(ns) for (symbol, kind), ns in families.items()}, 'outcome': 'all actual VCs passed', 'row_credit': 'actual VC rows; not distinct method/body counts'}

def negative(code, log, csv_raw, symbol, kind, required_line, optional_post_line=None):
    if not (code == 4 and (not BAD.search(log))):
        raise ValueError('not a normal assertion/postcondition counterexample')
    data, families = rows(csv_raw)
    if not set(families) == {(symbol, 'correctness'), (symbol, 'well-formedness')}:
        raise ValueError('wrong/missing target/family')
    if not (all((ns == [None] for ns in families.values())) and len(data) == 2):
        raise ValueError('these five unchanged nonisolated targets require exact two-row form')
    if not next((r for r in data if '(correctness)' in r['TestResult.DisplayName']))['TestResult.Outcome'] == 'Failed':
        raise ValueError('proof admission check failed')
    if not next((r for r in data if '(well-formedness)' in r['TestResult.DisplayName']))['TestResult.Outcome'] == 'Passed':
        raise ValueError('WF failure cannot substitute for intended correctness failure')
    summary = SUMMARY.findall(log)
    if not (len(summary) == 1 and int(summary[0][0]) == 1 and (int(summary[0][1]) > 0)):
        raise ValueError('proof admission check failed')
    groups = []
    for path, line, column, category, message in LOCATION.findall(log):
        location = {'path': path, 'line': int(line), 'column': int(column), 'message': message}
        if category == 'Error':
            groups.append({'error': location, 'related': []})
        else:
            if not groups:
                raise ValueError('proof admission check failed')
            groups[-1]['related'].append(location)
    if not (groups and int(summary[0][1]) == len(groups)):
        raise ValueError('missing/extra actual error groups')
    if kind == 'assertion':
        if not (len(groups) == 1 and groups[0]['error']['line'] == required_line and (groups[0]['error']['message'] == 'assertion might not hold')):
            raise ValueError('proof admission check failed')
    else:
        if not all((g['error']['message'] == 'a postcondition could not be proved on this return path' for g in groups)):
            raise ValueError('proof admission check failed')
        clauses = [p['line'] for g in groups for p in g['related'] if p['message'] == 'this is the postcondition that could not be proved']
        if not (len(clauses) == len(groups) and clauses.count(required_line) == 1):
            raise ValueError('required value/model/frame post missing or duplicated')
        allowed = {required_line} | ({optional_post_line} if optional_post_line is not None else set())
        if not set(clauses) <= allowed:
            raise ValueError('unrelated postcondition is not the intended control')
    return {'actual_target': symbol, 'rows': 2, 'passed_WF': 1, 'failed_correctness': 1, 'error_groups': groups, 'required_failure_line': required_line, 'outcome': 'normal intended correctness failure'}

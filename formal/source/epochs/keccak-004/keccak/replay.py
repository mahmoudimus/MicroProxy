#!/usr/bin/env python3
"""Externally selected Keccak source proofs/audits/semantic controls. qualification:false."""
import argparse
import hashlib
import _hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
SHA = re.compile(r'[0-9a-f]{64}\Z')
METHOD_ROOTS = ['NativeKeccak.' + n for n in ('NewOffsets','NewSources','SetLane','Iota','Theta','RhoPi','Chi','Round','PermuteScratch','Permute','Wipe')]
FUNCTION_ROOTS = ['NativeKeccak.' + n for n in ('Rotate','Constant','Offset','Source')]
HARNESS = 'formal/source/NativeKeccakTraceHarness.dfy'
NATIVE = 'formal/crypto/NativeKeccak.dfy'
SCOPE = 'Keccak source body proofs, direct audits and semantic controls; coverage receipt consumption only; no parent epoch, Java, delivery or timing qualification'

def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def map_sha(mapping):
    return digest((json.dumps(mapping, sort_keys=True, separators=(',', ':')) + '\n').encode())


def absolute(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute path without parent traversal required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        require(not cursor.is_symlink(), 'symlink path component: ' + str(cursor))
    return path


def file_bytes(path):
    path = absolute(path)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular unaliased input required: ' + str(path))
    data = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    require((before.st_dev, before.st_ino, before.st_size, before.st_nlink) ==
            (after.st_dev, after.st_ino, len(data), 1), 'input identity changed: ' + str(path))
    return data


def sha(path):
    return digest(file_bytes(path))


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def authenticated_json(path, expected):
    require(isinstance(expected, str) and SHA.fullmatch(expected), 'invalid external expected digest')
    raw = file_bytes(path)
    require(digest(raw) == expected, 'input differs from external expected digest: ' + str(path))
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    require(type(value) is dict, 'expected JSON object')
    return value


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name
            and all(ord(c) >= 32 for c in name), 'unsafe relative input')
    p = PurePosixPath(name)
    require(not p.is_absolute() and str(p) == name and all(x not in ('', '.', '..') for x in name.split('/')),
            'unsafe relative input: ' + name)
    return name


def mapped_files(root):
    root = absolute(root)
    result = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            require(not (Path(parent) / name).is_symlink(), 'symlink in input tree')
        for name in files:
            p = Path(parent) / name
            result[p.relative_to(root).as_posix()] = sha(p)
    return result


def check_map(root, pins):
    for name, expected in pins.items():
        require(SHA.fullmatch(expected) and sha(root / relative(name)) == expected, 'input hash changed: ' + name)


def include_closure(root, pins, entry):
    root = absolute(root)
    found = set()

    def visit(path):
        # Resolve lexical '..' in legitimate local includes, then require a mapped root-local file.
        require(not path.is_symlink(), 'symlink include')
        path = path.resolve()
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('unmapped include outside source root') from error
        require(name in pins, 'unmapped include: ' + name)
        require(sha(path) == pins[name], 'include source hash changed: ' + name)
        if name in found:
            return
        found.add(name)
        source = file_bytes(path).decode()
        includes = re.findall(r'^\s*include\s+"([^"\n]+)"\s*$', source, re.M)
        require(len(includes) == len(re.findall(r'^\s*include\b', source, re.M)), 'unsupported include syntax: ' + name)
        for child in includes:
            require(not Path(child).is_absolute() and '\\' not in child and ':' not in child, 'unsafe include syntax')
            visit(path.parent / child)

    visit(root / relative(entry))
    return sorted(found)


def error_locations(output):
    return [{'file': m[1], 'line': int(m[2]), 'column': int(m[3]), 'message': m[4]}
            for m in re.finditer(r'^(formal/[^()\n]+)\((\d+),(\d+)\): Error: (.+)$', output, re.M)]


def require_errors(output, expected):
    actual = error_locations(output)
    require(actual == expected, 'intended semantic error locations changed: ' + repr(actual))
    return actual


def output_admission(output, protected):
    output = absolute(output)
    require(output.parent.is_dir(), 'output parent must exist')
    parent_ids = {(p.stat().st_dev, p.stat().st_ino) for p in (output.parent, *output.parent.parents)}
    existing_id = (output.stat().st_dev, output.stat().st_ino) if output.exists() else None
    for root in protected:
        root = absolute(root)
        ancestors = (root, *root.parents)
        root_ids = {(p.stat().st_dev, p.stat().st_ino) for p in ancestors}
        require((root.stat().st_dev, root.stat().st_ino) not in parent_ids and existing_id not in root_ids,
                'output overlaps a protected input: ' + str(root))
    require(not os.path.lexists(output), 'output already exists')


def load(name, path, expected):
    data = file_bytes(path)
    require(isinstance(expected, str) and SHA.fullmatch(expected) and digest(data) == expected,
            'executable bytes differ from selected digest: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute the authenticated source bytes, never a timestamp-valid but unpinned .pyc.
    # Registration preserves ordinary module context for annotations and imports.
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(data, str(path), 'exec'), module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return module


def exact_map(root, pins):
    require(mapped_files(root) == pins, 'input inventory/hash differs: ' + str(root))


def child_environment(parent, home, temporary):
    home, temporary = absolute(home), absolute(temporary)
    require(home.is_dir() and temporary.is_dir() and not any(home.iterdir()) and not any(temporary.iterdir()),
            'fresh private child home and temporary directories required')
    config = home / 'config'
    config.mkdir(mode=0o700)
    env = {key: parent[key] for key in ('LANG','LC_ALL','LC_CTYPE','TZ') if key in parent}
    env.update({'HOME':str(home), 'TMPDIR':str(temporary), 'TMP':str(temporary), 'TEMP':str(temporary),
                'XDG_CONFIG_HOME':str(config), 'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
    return env


def classify(rule, code, output):
    require(type(code) is int, 'command did not complete with an integer exit status')
    require(not re.search(r'timed out|out of resource|resource limit|inconclusive|parse errors detected|internal error|Unhandled exception',
                          output, re.I), 'parser/resource/crash substitute is not evidence')
    kind = rule['kind']
    result = {'kind':kind}
    errors = error_locations(output)
    require(len(errors) == output.count('Error:'), 'unclassified Error diagnostic')
    if kind == 'proof':
        unit = rule.get('summary_unit','declarations')
        require(unit in ('declarations','assertions'), 'unknown proof summary unit')
        noun = 'assertions ' if unit=='assertions' else ''
        require(len(re.findall(r'^Dafny program verifier finished with .*$',output,re.M))==1,
                'exactly one verifier summary required')
        counts = re.findall(r'^Dafny program verifier finished with (\d+) '+noun+r'verified, (\d+) errors?$', output,re.M)
        expected = rule['counts']
        require(type(expected) is list and len(expected)==2 and expected[0]>0 and expected[1] in (0,1), 'invalid proof count authority')
        require(counts == [tuple(map(str,expected))], 'exact proof counts changed: ' + repr(counts))
        require(code == (4 if expected[1] else 0), 'proof exit status changed')
        require(errors == rule.get('errors',[]) and len(errors)==expected[1], 'intended semantic error locations changed: '+repr(errors))
        result['counts'] = expected
    elif kind == 'audit':
        require(code==0 and not errors, 'audit resolution failed')
        findings = re.findall(r'Dafny auditor completed with (\d+) findings?\b', output)
        require(findings == [str(rule['findings'])], 'exact audit finding count changed')
        warnings = re.findall(r'^(.+): Warning: (.+)$',output,re.M)
        require(len(warnings)==rule['findings'], 'unclassified audit warning')
        if rule['findings']:
            require(rule['findings']==1 and rule['warning'] in warnings[0][1]
                    and warnings[0][0]=='formal/crypto/NativeKeccak.dfy(1125,4)', 'included owned assumption finding changed')
        result['findings'] = rule['findings']
    elif kind == 'reject':
        require(code==2 and len(errors)==1 and errors[0]['message']==rule['diagnostic'], 'intended plugin rejection changed')
        require(not re.search(r'KECCAK-(?:METHOD-COVERAGE|FUNCTION-OBSERVATIONS) OK',output), 'rejected program also reports coverage success')
        result['errors'] = errors
    elif kind in ('resolve','method','function','combined'):
        require(code==0 and not errors and not re.search(r'\b[1-9][0-9]* (?:resolution/type|parse) errors?',output), 'resolve failed')
        if kind in ('method','combined'):
            roots = re.findall(r'^KECCAK-METHOD-COVERAGE ROOT OK: (\S+)$',output,re.M)
            require(len(roots)==11 and sorted(roots)==sorted(METHOD_ROOTS)
                    and output.count('KECCAK-METHOD-COVERAGE OK:')==1, 'exact 11 method roots missing/duplicated')
            result['method_roots'] = sorted(roots)
        if kind in ('function','combined'):
            summaries = re.findall(r'^KECCAK-FUNCTION-OBSERVATIONS OK: exact functions \[(.*?)\]; FUNCTION-ONLY DEVELOPMENT SCOPE$',output,re.M)
            roots = summaries[0].split(',') if len(summaries)==1 else []
            require(roots==FUNCTION_ROOTS and output.count('KECCAK-FUNCTION-OBSERVATIONS OK:')==1, 'exact 4 function roots missing/duplicated')
            result['function_roots'] = sorted(roots)
    else:
        raise ValueError('unknown result classification')
    return result


def validate_inputs(value):
    require(value['schema']=='microproxy.keccak004-public-proof-inputs/1' and value['qualification'] is False
            and value['scope']==SCOPE, 'input schema/scope changed')
    require(value['source_count']==85 and value['stage_source_count']==86 and value['task_count']==44
            and len(value['tasks'])==44, 'fixed inventory changed')
    labels = [r['label'] for r in value['tasks']]
    require(len(labels)==len(set(labels)), 'duplicate task label')
    counts = [r['rule']['counts'][0] for r in value['tasks'] if r['label'].startswith('body-')]
    require(len(counts)==9 and sum(counts)==value['proof_total_overlapping']==1877, 'nine-root body authority changed')
    require(sum(r['label'].startswith('audit-') for r in value['tasks'])==9
            and sum(r['label'].startswith('address-') for r in value['tasks'])==15
            and sum(r['label'].startswith('branch-') for r in value['tasks'])==6
            and sum(r['label'].startswith('stale-') for r in value['tasks'])==3, 'control inventory changed')
    for task in value['tasks']:
        relative(task['label'])
        require(task['action'] in ('verify','resolve','audit') and task['entries'], 'unknown command action')
        for name in task['entries']: relative(name)
        require(set(task['plugins']) <= {'method','function'} and len(task['plugins'])==len(set(task['plugins'])), 'invalid plugins')
        require(task['action']=='resolve' or not task['plugins'], 'plugins are for coverage resolve only')
        require('--allow-external-contracts' not in task['extra'] or task['action']=='resolve', 'body proof cannot use external contracts')
    return value


def source_authority(source, epoch, receipt, authority):
    require(epoch['schema']=='microproxy.keccak-source-epoch/1' and epoch['epoch']=='keccak-004', 'source epoch changed')
    sources = epoch['current']['sources']
    require(len(sources)==85 and map_sha(sources)==epoch['current']['map_sha256']==authority['source_map_sha256'], 'production85 source map changed')
    files = {**sources,**epoch['support_inputs'],**epoch['current_tooling'],
             epoch['paired_harness']['template']:epoch['paired_harness']['sha256']}
    require(receipt['schema']=='microproxy.keccak-source-views/1' and receipt['status']=='complete'
            and receipt['qualification'] is False and receipt['inputs_before_after_match'] is True
            and receipt['manifest_sha256']==authority['source_epoch_manifest_sha256']
            and receipt['constructor_sha256']==authority['source_view_constructor_sha256'], 'source-view receipt scope/status changed')
    require(receipt['views']['current']['files']==files, 'source-view receipt inventory changed')
    exact_map(source, files)
    require(HARNESS not in sources and epoch['paired_harness']['stage_target']==HARNESS, 'live paired harness cannot be production85')
    return sources, files


def tool_authority(dafny_root, archive, tools):
    require(tools['schema']=='microproxy.keccak004-shake-tools/1', 'unsupported tool authority')
    identities = tools['identities']
    distribution = mapped_files(dafny_root)
    require(len(distribution)==285 and distribution==identities['dafny_distribution'], 'complete official Dafny distribution changed')
    require(sha(archive)==identities['dafny_archive_sha256'], 'official Dafny archive changed')
    oracle = {str(Path(p).resolve()):sha(Path(p).resolve()) for p in (sys.executable,hashlib.__file__,_hashlib.__file__)}
    require(oracle==identities['python_oracle'] and sys.version==identities['python']
            and platform.platform()==identities['platform'], 'selected Python/platform identity changed')
    return {'dafny_distribution':distribution,'dafny_archive_sha256':sha(archive),'python_oracle':oracle,
            'python':sys.version,'platform':platform.platform()}


def bound_logs(value, root):
    logs = {}
    def visit(node):
        if isinstance(node,dict):
            if {'argv','cwd','exit','stdout','stderr','stdout_sha256','stderr_sha256'} <= set(node):
                for stream in ('stdout','stderr'):
                    p=absolute(Path(node[stream]))
                    require(p.is_relative_to(root), 'coverage raw log escapes receipt directory')
                    pin=node[stream+'_sha256']
                    require(SHA.fullmatch(pin) and sha(p)==pin, 'coverage raw log binding changed: '+str(p))
                    name=p.relative_to(root).as_posix()
                    require(name not in logs or logs[name]==pin, 'inconsistent raw log binding')
                    logs[name]=pin
            for item in node.values():visit(item)
        elif isinstance(node,list):
            for item in node:visit(item)
    visit(value)
    require(len(logs)==354, 'complete coverage raw log inventory changed')
    return logs


def coverage_authority(path, expected, package_root, stage_sources, authority, method, function):
    report=authenticated_json(path,expected)
    require(expected==authority['coverage_receipt_sha256'] and report['schema']=='microproxy.keccak-coverage/1'
            and report['status']=='passed' and report['qualification'] is False
            and report['scope']=='Keccak resolved-AST method and pure-function observation coverage only; no value/body-proof, NI, Java, delivery, or physical timing qualification'
            and report['inputs_unchanged'] is True and report['dlls_unchanged'] is True, 'coverage receipt status/scope changed')
    require(report['package_map']==authority['coverage_package_map']==report['build']['inputs'], 'coverage tool source map changed')
    exact_map(package_root,report['package_map'])
    root=absolute(path.parent)
    exact_map(root/'frozen-package',report['package_map'])
    closure=sorted(set(n for entry in authority['combined_entries'] for n in include_closure(
        root/'frozen-source',report['source_map'],entry)))
    expected_sources={name:stage_sources[name] for name in closure}
    require(report['source_map']==expected_sources and len(expected_sources)==22
            and report['combined_entries']==authority['combined_entries']
            and report['combined']['inputs']==expected_sources and report['combined']['passed'] is True
            and report['combined']['inputs_unchanged'] is True, 'coverage source graph differs from current stage')
    exact_map(root/'frozen-source',expected_sources)
    require(report['combined']['method_roots']==sorted(METHOD_ROOTS)
            and sorted(report['combined']['function_roots'])==sorted(FUNCTION_ROOTS), 'coverage combined roots changed')
    dlls={}
    for gate,p in [('method',method),('function',function)]:
        selected=report['build']['dlls'][gate]
        require(sha(p)==selected['sha256']==report['dlls_after'][gate]==authority['dlls'][gate], 'coverage DLL identity changed')
        require(sha(Path(selected['path']))==selected['sha256'], 'coverage retained DLL changed')
        dlls[gate]={'path':str(p),'sha256':sha(p)}
    logs=bound_logs(report,root)
    case_maps={}
    for gate,total,positive,negative in [('method',61,4,57),('function',18,2,16)]:
        rows=report['cases'][gate]
        require(report['counts'][gate]=={'total':total,'positive':positive,'negative':negative,'passed':total}
                and len(rows)==total and len({r['name'] for r in rows})==total, 'coverage control inventory changed')
        require(set(authority['coverage_case_diagnostics'][gate])=={r['name'] for r in rows}, 'coverage diagnostic inventory changed')
        for row in rows:
            require(row['passed'] is True and row['typed_without_plugin'] is True and row['inputs_unchanged'] is True
                    and row['gate']==gate and len(row['commands'])==2, 'coverage case incomplete')
            plain,plugin=row['commands']; require(plain['exit']==0, 'coverage negative did not resolve first')
            require('--plugin' not in plain['argv'] and plugin['argv'].count('--plugin')==1, 'coverage case command binding changed')
            for record in (plain,plugin):
                require(record['argv'][1:3]==['resolve',NATIVE], 'coverage case resolves a different entry')
            classify({'kind':'resolve'},plain['exit'],file_bytes(Path(plain['stdout'])).decode()+file_bytes(Path(plain['stderr'])).decode())
            output=file_bytes(Path(plugin['stdout'])).decode()+file_bytes(Path(plugin['stderr'])).decode()
            require(not re.search(r'timed out|out of resource|resource limit|inconclusive|parse errors detected|internal error|Unhandled exception', output, re.I), 'coverage case has parser/resource/crash substitute')
            diagnostics=re.findall(r'^.*: Error: .+$',output,re.M)
            require(diagnostics==authority['coverage_case_diagnostics'][gate][row['name']], 'exact coverage diagnostics changed')
            if row['expected_error'] is None:
                classify({'kind':gate},plugin['exit'],output)
            else:
                require(plugin['exit']==2 and diagnostics and output.count('Error:')==len(diagnostics)
                        and all(row['expected_error'] in line for line in diagnostics)
                        and (row['expected_message'] is None or row['expected_message'] in output), 'coverage negative diagnostic changed')
            for record in (plain,plugin):
                case_root=absolute(Path(record['cwd']))
                require(case_root==root/'cases'/gate/row['name'], 'coverage case path changed')
                exact_map(case_root,row['inputs'])
            case_maps[gate+'/'+row['name']]=row['inputs']
    for name,pin in report['tool_pins'].items():require(sha(Path(name))==pin, 'coverage selected tool map changed')
    command=report['combined']['command']
    classify({'kind':'combined'},command['exit'],file_bytes(Path(command['stdout'])).decode()+file_bytes(Path(command['stderr'])).decode())
    return {'receipt_sha256':sha(path),'source_map':expected_sources,'package_map':report['package_map'],
            'tool_pins':report['tool_pins'],'dlls':dlls,'raw_logs':logs,'case_maps':case_maps,
            'counts':report['counts'],'scope':report['scope']}


def capture_file(origin, target, expected):
    data=file_bytes(origin)
    require(isinstance(expected,str) and SHA.fullmatch(expected) and digest(data)==expected,
            'input changed during capture: '+str(origin))
    target=absolute(target)
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('xb') as stream:stream.write(data)
    target.chmod(0o555 if origin.stat().st_mode & 0o111 else 0o444)
    require(target.stat().st_ino!=origin.stat().st_ino or target.stat().st_dev!=origin.stat().st_dev,
            'frozen copy aliases input')
    return expected


def freeze_files(root, mapping, destination):
    for name,pin in mapping.items():capture_file(root/relative(name),destination/name,pin)
    exact_map(destination,mapping)


def variants(base, sources, package, mutations, output):
    require(set(mutations)=={'address-faithful','address-forged','address-omitted','branch-private','included-assumption','stale-mutant'}, 'mutation inventory changed')
    data={'base':{n:file_bytes(base/n) for n in sources}}
    native=data['base'][NATIVE]
    for name,row in mutations.items():
        require(row['parent'] in data and row['file']==NATIVE, 'unknown mutation parent/target')
        value=data[row['parent']][NATIVE]
        require(digest(value)==row['before_sha256'] and row['search'] and value.decode().count(row['search'])==1,
                'mutation anchor/prestate differs: '+name)
        changed=value.decode().replace(row['search'],row['replacement'],1).encode()
        require(digest(changed)==row['after_sha256'] and changed!=native, 'mutation witness changed: '+name)
        data[name]={**data['base'],NATIVE:changed}
    for name,values in data.items():
        for probe in ('AddressPairProbe','FunctionPairProbe'):
            values['formal/source/'+probe+'.dfy']=file_bytes(package/(probe+'.dfy.in'))
        target=output/name
        for rel,content in values.items():
            path=target/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);path.chmod(0o444)
    maps={name:{n:digest(v) for n,v in values.items()} for name,values in data.items()}
    return maps


def command(label, argv, cwd, output, timeout):
    workspace=output/'children'/label;workspace.mkdir(parents=True,mode=0o700)
    home=workspace/'home';temporary=workspace/'tmp';home.mkdir(mode=0o700);temporary.mkdir(mode=0o700)
    env=child_environment(os.environ,home,temporary)
    logdir=output/'logs';logdir.mkdir(exist_ok=True)
    stdout=logdir/(label+'.stdout.log');stderr=logdir/(label+'.stderr.log')
    start=time.monotonic();process=None;code='not-started';failure=None
    try:
        with stdout.open('wb') as out,stderr.open('wb') as err:
            process=subprocess.Popen(list(map(str,argv)),cwd=cwd,stdout=out,stderr=err,env=env,start_new_session=True)
            try:code=process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:code='timeout'
            except BaseException as error:
                code='interrupted';failure=type(error).__name__+': '+str(error)
            finally:
                # Each child owns a new session/process group; never kill by executable name.
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:pass
                finally:
                    # A reaped parent can leave an owned descendant that ignores TERM.
                    # Always finish this same group, regardless of the parent's poll status.
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    process.wait()
    finally:
        if process is not None and process.poll() is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait()
    record={'label':label,'argv':list(map(str,argv)),'cwd':str(cwd),'exit':code,'seconds':time.monotonic()-start,
            'stdout':str(stdout),'stderr':str(stderr),'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr),
            'environment':env,'child_generated_files':mapped_files(workspace),'command_exception':failure}
    return record,file_bytes(stdout).decode()+file_bytes(stderr).decode()


def save(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('inputs','source-root','source-manifest','view-receipt','helper-root','tools-manifest','dafny-root',
                 'dafny-archive','coverage-receipt','coverage-package-root','method-dll','function-dll','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-inputs-sha256','expected-source-manifest-sha256','expected-view-receipt-sha256',
                 'expected-tools-sha256','expected-coverage-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--admission-only',action='store_true',help='authenticate all inputs and output boundary; create nothing and run no proof')
    args=parser.parse_args()
    require(sys.flags.isolated and sys.dont_write_bytecode, 'invoke Python with -I -B')
    for name,value in vars(args).items():
        if isinstance(value,Path):setattr(args,name,absolute(value))
    authority=validate_inputs(authenticated_json(args.inputs,args.expected_inputs_sha256))
    for option,key in [('expected_source_manifest_sha256','source_epoch_manifest_sha256'),
                       ('expected_view_receipt_sha256','source_view_receipt_sha256'),
                       ('expected_tools_sha256','tools_manifest_sha256'),('expected_coverage_sha256','coverage_receipt_sha256')]:
        require(getattr(args,option)==authority[key], 'external authority selection differs: '+key)
    package=absolute(Path(__file__).absolute().parent)
    exact_map(package,{**authority['package_files'],'inputs.json':args.expected_inputs_sha256})
    require(args.inputs==package/'inputs.json', 'input authority must be the selected package manifest')
    epoch=authenticated_json(args.source_manifest,args.expected_source_manifest_sha256)
    view=authenticated_json(args.view_receipt,args.expected_view_receipt_sha256)
    tools=authenticated_json(args.tools_manifest,args.expected_tools_sha256)
    constructor=args.helper_root/'formal/source/epochs/keccak-004/views.py'
    require(sha(constructor)==authority['source_view_constructor_sha256'], 'constructor authority changed')
    # Constructor is authenticated as provenance data; this runner executes no external Python helper.
    source_map,view_map=source_authority(args.source_root,epoch,view,authority)
    stage_sources={**source_map,HARNESS:epoch['paired_harness']['sha256']}
    require(len(stage_sources)==86,'new paired stage inventory changed')
    tools_before=tool_authority(args.dafny_root,args.dafny_archive,tools)
    coverage_before=coverage_authority(args.coverage_receipt,args.expected_coverage_sha256,args.coverage_package_root,
                                       stage_sources,authority,args.method_dll,args.function_dll)
    protected=[args.source_root,args.helper_root,package,args.inputs,args.source_manifest,args.view_receipt,
               args.tools_manifest,args.dafny_root,args.dafny_archive,args.coverage_receipt.parent,args.coverage_package_root,args.method_dll,args.function_dll]
    output_admission(args.output,protected)
    if args.admission_only:
        print(json.dumps({'status':'admitted','qualification':False,'source_count':85,'stage_source_count':86,
                          'coverage_controls':{'method':61,'function':18},'commands_planned':44},sort_keys=True))
        return 0
    input_before={'source_view':view_map,'package':{**authority['package_files'],'inputs.json':sha(args.inputs)},
                  'epoch_manifest':sha(args.source_manifest),'view_receipt':sha(args.view_receipt),
                  'tools_manifest':sha(args.tools_manifest),'constructor':sha(constructor)}
    out=args.output;out.mkdir(mode=0o700)
    frozen=out/'frozen-view';freeze_files(args.source_root,view_map,frozen)
    stage=frozen/HARNESS;stage.parent.mkdir(parents=True,exist_ok=True)
    stage.write_bytes(file_bytes(frozen/epoch['paired_harness']['template']))
    expected_stage={**view_map,HARNESS:epoch['paired_harness']['sha256']};exact_map(frozen,expected_stage)
    frozen_package=out/'frozen-package';freeze_files(package,input_before['package'],frozen_package)
    frozen_tools=out/'frozen-tools';freeze_files(args.dafny_root,tools_before['dafny_distribution'],frozen_tools)
    authority_copies={}
    authority_pins={'source-manifest.json':args.expected_source_manifest_sha256,
                    'view-receipt.json':args.expected_view_receipt_sha256,'tools-manifest.json':args.expected_tools_sha256,
                    'coverage-receipt.json':args.expected_coverage_sha256,
                    'source-view-constructor.py':authority['source_view_constructor_sha256']}
    for name,origin in [('source-manifest.json',args.source_manifest),('view-receipt.json',args.view_receipt),
                        ('tools-manifest.json',args.tools_manifest),('coverage-receipt.json',args.coverage_receipt),
                        ('source-view-constructor.py',constructor)]:
        authority_copies[name]=capture_file(origin,out/name,authority_pins[name])
    plugins=out/'plugins';plugins.mkdir()
    selected={}
    for gate,origin in [('method',args.method_dll),('function',args.function_dll)]:
        target=plugins/(gate+'.dll')
        capture_file(origin,target,authority['dlls'][gate]);selected[gate]=target
    frozen_plugins=mapped_files(plugins)
    mutations=authenticated_json(frozen_package/'mutations.json',authority['package_files']['mutations.json'])
    maps=variants(frozen,stage_sources,frozen_package,mutations,out/'variants')
    closures={name:{entry:include_closure(out/'variants'/name,mapping,entry)
                    for entry in sorted(set(e for t in authority['tasks'] if t['variant']==name for e in t['entries']))}
              for name,mapping in maps.items()}
    for path in list(frozen.rglob('*'))+list(frozen_package.rglob('*'))+list(plugins.rglob('*')):
        if path.is_file():path.chmod(0o444)
    receipt={'schema':'microproxy.keccak004-public-proof/1','qualification':False,'scope':SCOPE,'status':'running',
             'source_count_production':85,'source_count_paired_stage':86,'source_map':source_map,'stage_source_map':stage_sources,
             'inputs_before':input_before,'tools_before':tools_before,'coverage_before':coverage_before,
             'frozen_stage':expected_stage,'frozen_package':input_before['package'],'frozen_plugins':frozen_plugins,
             'frozen_authorities_before':authority_copies,'frozen_tools':tools_before['dafny_distribution'],
             'variants_before':maps,'include_closures':closures,'commands':[],
             'authority_selection':{k:str(v) for k,v in vars(args).items()},
             'limits':'1877 overlapping body checks, not unique theorems. Source component evidence only; no Java, parent-epoch, physical timing or production-adoption qualification.'}
    save(out/'result.json',receipt)
    dafny=frozen_tools/'dafny/dafny';solver=frozen_tools/'dafny/z3/bin/z3-4.12.1'
    try:
        for task in authority['tasks']:
            argv=[dafny,task['action'],*task['entries'],*task['extra']]
            if task['action']=='verify':argv+=['--solver-path',solver]
            for gate in task['plugins']:argv+=['--plugin',selected[gate]]
            record,text=command(task['label'],argv,out/'variants'/task['variant'],out,authority['command_timeout_seconds'])
            record.update({'variant':task['variant'],'rule':task['rule'],'passed':False})
            receipt['commands'].append(record);save(out/'result.json',receipt)
            record['classification']=classify(task['rule'],record['exit'],text);record['passed']=True
            print(task['label']+' PASS '+str(record['classification']),flush=True)
            save(out/'result.json',receipt)
        exact_map(frozen,expected_stage);exact_map(frozen_package,input_before['package']);exact_map(plugins,frozen_plugins)
        exact_map(frozen_tools,tools_before['dafny_distribution'])
        authority_copies_after={name:sha(out/name) for name in authority_copies}
        require(authority_copies_after==authority_copies, 'frozen authority copies changed')
        receipt['frozen_authorities_after']=authority_copies_after
        variants_after={name:mapped_files(out/'variants'/name) for name in maps}
        require(variants_after==maps,'frozen variant inputs changed')
        receipt['variants_after']=variants_after
        _,source_after=source_authority(args.source_root,epoch,view,authority)
        tools_after=tool_authority(args.dafny_root,args.dafny_archive,tools)
        coverage_after=coverage_authority(args.coverage_receipt,args.expected_coverage_sha256,args.coverage_package_root,
                                         stage_sources,authority,args.method_dll,args.function_dll)
        exact_map(package,input_before['package'])
        input_after={'source_view':source_after,'package':mapped_files(package),'epoch_manifest':sha(args.source_manifest),
                     'view_receipt':sha(args.view_receipt),'tools_manifest':sha(args.tools_manifest),'constructor':sha(constructor)}
        receipt.update({'inputs_after':input_after,'tools_after':tools_after,'coverage_after':coverage_after,
                        'inputs_unchanged':input_after==input_before,'tools_unchanged':tools_after==tools_before,
                        'coverage_unchanged':coverage_after==coverage_before})
        require(input_after==input_before and tools_after==tools_before and coverage_after==coverage_before,
                'source/input/tool/coverage authority changed during replay')
        receipt.update({'status':'passed','counts':{'body_roots':9,'body_overlapping_checks':1877,'clean_audits':9,
                        'private_address_tasks':15,'private_branch_tasks':6,'included_assumption_tasks':1,
                        'stale_capture_tasks':3,'combined_plugin_tasks':1,'commands':44,
                        'consumed_method_coverage_cases':61,'consumed_function_coverage_cases':18}})
    except BaseException as error:
        receipt.update({'status':'failed','failure':type(error).__name__+': '+str(error),
                        'partial_log_map':mapped_files(out/'logs') if (out/'logs').is_dir() else {}})
        raise
    finally:
        save(out/'result.json',receipt)
    print('KECCAK PUBLIC SOURCE REPLAY PASSED; qualification=false',flush=True)
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError,TypeError) as error:
        print('KECCAK REPLAY REJECTED: '+str(error),file=sys.stderr)
        raise SystemExit(1)

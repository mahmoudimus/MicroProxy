"""Select layout adapter for the approved strict build evaluation policy.

Copied from BuildAuthority.validate_evaluation in build_authority.py SHA256
 d1f3d75180cec03cdd88fe56afa9c505755ed3b6a5b514f6befa8600e9bd06e5.
The receiver is explicit. ONLY the authenticated encoder-source expectation moves
from sibling encoder/ to the exact old Select project directory. All isolation,
reference, import, analyzer and generated-source checks are unchanged.
"""
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_evaluation(authority, evaluation, build, project, assembly, tools):
        data = json.loads(evaluation)
        props, items = data['Properties'], data['Items']
        for name, value in authority.properties().items():
            if name not in props or props[name].rstrip('/\\') != value.rstrip('/\\'):
                raise ValueError('evaluated isolation property mismatch: ' + name)
        def path(item):
            p = Path(item.get('FullPath', item['Identity']))
            return (p if p.is_absolute() else build / p).resolve()
        pack_files = {str((authority.root / 'packs' / rel).resolve()): value
                      for rel, value in authority.immutable_before['packs'].items()}
        references = {}
        for kind in ('ReferencePath', 'ReferencePathWithRefAssemblies', 'Analyzer'):
            for item in items.get(kind, []):
                p = path(item); expected = pack_files.get(str(p), tools.get(str(p)))
                if expected is None or not p.is_file() or sha(p) != expected:
                    raise ValueError('unmapped actual compiler reference/analyzer: ' + str(p))
                references[str(p)] = expected
        if not items.get('ReferencePath'): raise ValueError('empty actual compiler reference closure')
        configs = {}
        for kind in ('EditorConfigFiles', 'GlobalAnalyzerConfigFiles', 'AnalyzerConfigFiles'):
            for item in items.get(kind, []):
                p = path(item)
                if str(p) not in tools and not p.is_relative_to(build):
                    raise ValueError('unmapped compiler analyzer config: ' + str(p))
                configs[str(p)] = sha(p)
        authored = {(project / (assembly + '.cs')).resolve(),
                    (project / 'NativeCanonicalEncoderPolicy.cs').resolve()}
        generated_names = {assembly + '.AssemblyInfo.cs', assembly + '.GlobalUsings.g.cs',
                           '.NETCoreApp,Version=v6.0.AssemblyAttributes.cs'}
        compile_inputs = {}
        for item in items.get('Compile', []):
            p = path(item)
            if p not in authored and not (p.is_relative_to(project / 'obj') and p.name in generated_names):
                raise ValueError('unexpected actual compiler source: ' + str(p))
            compile_inputs[str(p)] = sha(p)
        if not authored <= {Path(p) for p in compile_inputs}: raise ValueError('authored C# compile closure missing')
        imports = {}
        for name in props.get('MSBuildAllProjects', '').split(';'):
            if not name: continue
            p = Path(name).resolve()
            if str(p) in tools:
                if sha(p) != tools[str(p)]: raise ValueError('SDK import changed')
            elif not p.is_relative_to(build):
                raise ValueError('unmapped actual MSBuild import: ' + str(p))
            imports[str(p)] = sha(p)
        return {'properties': props, 'references': references, 'compile_inputs': compile_inputs,
                'imports': imports, 'analyzer_configs': configs, 'items': items}

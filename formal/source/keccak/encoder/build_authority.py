"""Explicit offline MSBuild authority for the coverage-only Keccak component."""
import base64
import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from xml.sax.saxutils import escape

MANIFEST_SHA = '4a93358067580cb907bfa2d54202deee28d8887fda3a5734052e7cc7707de549'
USER_HOOKS = tuple('ImportUserLocationsByWildcard' + side + target
                   for target in ('MicrosoftCommonProps', 'MicrosoftCommonTargets', 'MicrosoftCSharpTargets')
                   for side in ('Before', 'After'))
ENV_ALLOWLIST = ('PATH', 'LANG', 'LANGUAGE', 'LC_ALL', 'LC_CTYPE', 'LC_MESSAGES', 'TZ')


def digest(data): return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def file_map(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def safe_members(raw):
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('targeting-pack archive is too large')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names, members, total = set(), {}, 0
        for info in archive.infolist():
            name = info.filename
            parts = name.rstrip('/').split('/')
            if (not name or '\\' in name or ':' in name or name.startswith('/') or
                    any(p in ('..', '.') for p in parts) or '//' in name):
                raise ValueError('unsafe targeting-pack ZIP member path')
            key = name.rstrip('/').casefold()
            if key in names: raise ValueError('duplicate targeting-pack ZIP entry')
            names.add(key)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError('symlink/special targeting-pack ZIP member')
            if info.is_dir(): continue
            total += info.file_size
            if total > 64 * 1024 * 1024 or len(members) >= 1024:
                raise ValueError('targeting-pack expanded inventory exceeds bounds')
            members[name] = archive.read(info)
        return members


def admit_archives(directory, manifest_raw):
    if digest(manifest_raw) != MANIFEST_SHA:
        raise ValueError('unreviewed targeting-pack authority manifest')
    manifest = json.loads(manifest_raw)
    directory = Path(directory)
    if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink():
        raise ValueError('targeting-pack source must be an absolute nonsymlink directory')
    cursor = Path(directory.anchor)
    for part in directory.parts[1:]:
        cursor /= part
        if cursor.is_symlink(): raise ValueError('symlink targeting-pack source ancestor')
    expected = {row['filename'] for row in manifest['packages']}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError('targeting-pack source has missing/extra names')
    archives, payloads = {}, {}
    for row in manifest['packages']:
        path = directory / row['filename']
        if path.is_symlink() or not path.is_file(): raise ValueError('symlink/nonfile targeting-pack archive')
        raw = path.read_bytes()
        members = safe_members(raw)
        if (len(raw) != row['size'] or digest(raw) != row['sha256'] or
                base64.b64encode(hashlib.sha512(raw).digest()).decode() != row['sha512_base64']):
            raise ValueError('targeting-pack archive authority hash/size mismatch')
        if len(members) != row['file_count'] or sum(map(len, members.values())) != row['expanded_size']:
            raise ValueError('targeting-pack archive member inventory mismatch')
        archives[row['filename']] = raw
        prefix = row['installed_name'] + '/' + row['version'] + '/'
        payloads.update({prefix + name: content for name, content in members.items()})
    return manifest, archives, payloads


class BuildAuthority:
    def __init__(self, root, manifest_raw, archives, payloads, dotnet_root):
        self.root, self.dotnet_root = Path(root), Path(dotnet_root)
        self.root.mkdir(parents=True, exist_ok=False)
        self.manifest_raw, self.archives, self.payloads = manifest_raw, archives, payloads
        for label in ('archives', 'packs', 'home', 'config', 'cache', 'tmp', 'dotnet-home',
                      'packages', 'http-cache', 'plugins-cache', 'msbuild-user'):
            (self.root / label).mkdir()
        for name, raw in archives.items(): (self.root / 'archives' / name).write_bytes(raw)
        for name, raw in payloads.items():
            path = self.root / 'packs' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.config = self.root / 'NuGet.Config'
        self.config.write_bytes(self.config_bytes())
        self.immutable_before = self.immutable_map()

    def config_bytes(self):
        folder = escape(str(self.root / 'packages'), {'"': '&quot;'})
        return ('<?xml version="1.0" encoding="utf-8"?>\n<configuration>\n'
                '  <packageSources><clear /></packageSources>\n'
                '  <fallbackPackageFolders><clear /></fallbackPackageFolders>\n'
                '  <disabledPackageSources><clear /></disabledPackageSources>\n'
                '  <packageSourceMapping><clear /></packageSourceMapping>\n'
                '  <config><add key="globalPackagesFolder" value="' + folder + '" /></config>\n'
                '</configuration>\n').encode()

    def environment(self):
        env = {name: os.environ[name] for name in ENV_ALLOWLIST if name in os.environ}
        env.update({
            'HOME': str(self.root / 'home'), 'USERPROFILE': str(self.root / 'home'),
            'APPDATA': str(self.root / 'config'), 'LOCALAPPDATA': str(self.root / 'cache'),
            'XDG_CONFIG_HOME': str(self.root / 'config'), 'XDG_CACHE_HOME': str(self.root / 'cache'),
            'TMPDIR': str(self.root / 'tmp'), 'TMP': str(self.root / 'tmp'), 'TEMP': str(self.root / 'tmp'),
            'DOTNET_CLI_HOME': str(self.root / 'dotnet-home'), 'DOTNET_ROOT': str(self.dotnet_root),
            'DOTNET_NOLOGO': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
            'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_MULTILEVEL_LOOKUP': '0',
            'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE': '1', 'MSBuildEnableWorkloadResolver': 'false',
            'NUGET_PACKAGES': str(self.root / 'packages'),
            'NUGET_HTTP_CACHE_PATH': str(self.root / 'http-cache'),
            'NUGET_PLUGINS_CACHE_PATH': str(self.root / 'plugins-cache'),
        })
        return env

    def properties(self, user_extensions=None, packs=None):
        props = {
            'ImportDirectoryBuildProps': 'false', 'ImportDirectoryBuildTargets': 'false',
            'ImportDirectoryPackagesProps': 'false',
            'MSBuildUserExtensionsPath': str(user_extensions or self.root / 'msbuild-user'),
            'UseSharedCompilation': 'false', 'CompilerResponseFile': '', 'MSBuildEnableWorkloadResolver': 'false',
            'DiscoverEditorConfigFiles': 'false', 'DiscoverGlobalAnalyzerConfigFiles': 'false',
            'RestoreConfigFile': str(self.config), 'RestorePackagesPath': str(self.root / 'packages'),
            'RestoreSources': '', 'RestoreFallbackFolders': '', 'RestoreAdditionalProjectSources': '',
            'RestoreAdditionalProjectFallbackFolders': '', 'RestoreIgnoreFailedSources': 'false',
            'NuGetAudit': 'false', 'NuGetInteractive': 'false',
            'EnableTargetingPackDownload': 'false', 'NetCoreTargetingPackRoot': str(packs or self.root / 'packs'),
        }
        props.update({name: 'false' for name in USER_HOOKS})
        return props

    def arguments(self, dafny_root, **overrides):
        props = self.properties(**overrides)
        props['DafnyHome'] = str(dafny_root)
        return ['-noAutoResponse', '-nodeReuse:false', '-m:1', '-nologo'] + [
            '-p:' + key + '=' + value for key, value in props.items()]

    def immutable_map(self):
        return {'archives': file_map(self.root / 'archives'), 'packs': file_map(self.root / 'packs'),
                'NuGet.Config': sha(self.config)}

    def verify(self):
        if self.immutable_before != self.immutable_map():
            raise ValueError('private pack archives/payloads or isolated NuGet.Config changed')
        if any((self.root / 'packages').iterdir()):
            raise ValueError('unexpected NuGet package cache content; installed packs must suffice')

    def record(self):
        self.verify()
        return {'manifest_sha256': digest(self.manifest_raw), 'manifest': json.loads(self.manifest_raw),
                'root': str(self.root), 'environment': self.environment(), 'properties': self.properties(),
                'immutable_before': self.immutable_before, 'immutable_after': self.immutable_map(),
                'private_generated_state': {name: file_map(self.root / name) for name in (
                    'home', 'config', 'cache', 'tmp', 'dotnet-home', 'packages', 'http-cache',
                    'plugins-cache', 'msbuild-user')}}

    def validate_assets(self, assets):
        data = json.loads(Path(assets).read_text())
        restore = data['project']['restore']
        intended = str((self.root / 'packages').resolve())
        if ({str(Path(name).resolve()) for name in data['packageFolders']} != {intended} or
                Path(restore['packagesPath']).resolve() != Path(intended)):
            raise ValueError('assets escaped the isolated package folder')
        if restore.get('configFilePaths') != [str(self.config)] or restore.get('sources', {}):
            raise ValueError('assets used an ambient NuGet config/source')
        if data.get('libraries') or any(f.get('downloadDependencies') for f in data['project']['frameworks'].values()):
            raise ValueError('unexpected package/download dependency; private installed packs are mandatory')
        if any(f.get('projectReferences') for f in restore.get('frameworks', {}).values()):
            raise ValueError('unexpected project reference')
        return {'path': str(assets), 'sha256': sha(assets), 'restore': restore,
                'package_folders': data['packageFolders'], 'frameworks': data['project']['frameworks']}

    def validate_evaluation(self, evaluation, build, project, assembly, tools):
        data = json.loads(evaluation)
        props, items = data['Properties'], data['Items']
        for name, value in self.properties().items():
            if name not in props or props[name].rstrip('/\\') != value.rstrip('/\\'):
                raise ValueError('evaluated isolation property mismatch: ' + name)
        def path(item):
            p = Path(item.get('FullPath', item['Identity']))
            return (p if p.is_absolute() else build / p).resolve()
        pack_files = {str((self.root / 'packs' / rel).resolve()): value
                      for rel, value in self.immutable_before['packs'].items()}
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
                    (project.parent / 'encoder/NativeCanonicalEncoderPolicy.cs').resolve()}
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

"""Synthetic pure-DATA admission regressions; no proof/build execution."""
import copy
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from contextlib import ExitStack

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('prospective_hkdf_ci', HERE / 'ci.py')
C = importlib.util.module_from_spec(spec)
exec(compile((HERE/'ci.py').read_bytes(),str(HERE/'ci.py'),'exec',dont_inherit=True),C.__dict__)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return sha(raw)


class SYNTHETICCommandFixture:
    """UNIT ONLY: fabricated data never executes or qualifies any program."""
    def __init__(self, root):
        self.root = root / 'SYNTHETIC-UNIT-ONLY'
        self.root.mkdir(parents=True)
        self.pins = {}
        self.roles = {n: n + '.json' for n in C.INDEX_ROLES}
        self.roles.update(report='report.json', api_report='actual-artifacts/report.json',
                          bundle_receipt='actual-artifacts/bundle-check/receipt.json',
                          api_request='api-request.json',qualified_python='qualified-python.json')
        self.index = {'files': self.pins, 'roles': self.roles}
        self.project = '/SYNTHETIC-DARWIN/project'
        self.output = '/SYNTHETIC-DARWIN/output'
        self.source = '/SYNTHETIC-DARWIN/source'
        self.rt = {n: '/SYNTHETIC-DARWIN/' + n for n in
                   ('python', 'runtime', 'jdk21', 'jdk25', 'maven', 'prepared', 'data', 'hkdf', 'cache', 'junit', 'maven_repository')}
        self.inputs = {n: sha(('SYNTHETIC source ' + n).encode()) for n in C.CODE}
        self.inputs['formal/crypto/bundle_checks.py'] = sha(b'SYNTHETIC bundle tool')
        self.inputs['formal/nonce/BundleNonceSmoke.java'] = sha(b'SYNTHETIC nonce source')
        self.inputs['formal/crypto/delivery.json'] = sha(b'SYNTHETIC config')
        self.operands = {n:{'SYNTHETIC-'+n:sha(n.encode())} for n in ('cache','junit','maven_repository')}
        self.tools = {'python_sha256': sha(b'SYNTHETIC Python'), 'runtime_sha256': sha(b'SYNTHETIC runtime'),
                      **{n + '_tree_sha256': C.A.map_sha({'SYNTHETIC tool': n}) for n in ('jdk21', 'jdk25', 'maven')},
                      'maven_repository_tree_sha256':C.A.map_sha(self.operands['maven_repository'])}
        self.policy = {'schema': C.A.SCHEMA, 'candidate': {'inputs': self.inputs}, 'tools': self.tools,
                       'delivery': {'config': {'path': C.BASE+'delivery.json', 'sha256': sha(b'SYNTHETIC config')},
                                    'api': {'path': C.API, 'sha256': self.inputs[C.API]},
                                    'native_evidence': {'path': C.BASE+'native-inputs.json', 'sha256': sha(b'SYNTHETIC native')},
                                    'timeout': 1800}}
        self.policy_sha = self.json('policy.json', self.policy)
        self.library = self.project+'/quic/target/quic-UNIT.jar'
        self.bundle = self.project+'/microproxy-starlark/target/microproxy-starlark-UNIT-all.jar'
        self.opts = {'root': self.source, 'policy': self.source+'/'+C.BASE+'inputs.json',
            'expected-policy-sha256': self.policy_sha, 'project': self.project, 'output': self.output,
            'library': self.library, 'bundle': self.bundle, 'runtime': self.rt['runtime'],
            'jdk21': self.rt['jdk21'], 'jdk25': self.rt['jdk25'],
            **{n.replace('_','-'): self.rt[n] for n in ('prepared','data','hkdf','cache','junit','maven','maven_repository')}}
        self.request = {'schema':'microproxy.hkdf-array-qualification-request/1','qualification':False,
            'root':self.source,'project':self.project,'output':self.output,'platform_scope':'Darwin-arm64',
            'policy':{'path':self.opts['policy'],'sha256':self.policy_sha},
            'python':{'path':self.rt['python'],'sha256':self.tools['python_sha256']},
            'bootstrap':{n:{'path':self.source+'/'+C.BASE+n+'.py','sha256':self.inputs[C.BASE+n+'.py']} for n in ('run','admission')},
            'runtime_locations':self.rt,'argv':['qualify',*[x for n,v in self.opts.items() for x in ('--'+n,v)]],
            'new_initial_stage':self.output+'/stage','new_actual_API_output':self.output+'/actual-artifacts',
            'policy_selection':{'path':'/SYNTHETIC-DARWIN/POLICY-SELECTION.json','sha256':sha(b'SYNTHETIC policy selection')},
            'full_preparation':{'path':'/SYNTHETIC-DARWIN/PREPARED.json','sha256':sha(b'SYNTHETIC preparation')},
            'project_map':{'path':'/SYNTHETIC-DARWIN/PROJECT.json','sha256':sha(b'SYNTHETIC project'),'map_sha256':sha(b'SYNTHETIC map')},
            'operand_maps':{n:{'map_sha256':C.A.map_sha(v)} for n,v in self.operands.items()},
            'execution_contract':['SYNTHETIC UNIT ONLY'],'execution_window':'SYNTHETIC-UNIT-NO-EXECUTION'}
        self.request_sha = self.json(self.roles.get('execution_request','execution_request.json'),self.request)
        self.api_request = {'project':self.project,'api':self.policy['delivery']['api'],
            'delivery_sha256':self.inputs[C.DELIVERY], 'stage':self.output+'/stage',
            'classes':self.project+'/quic/target/classes','library':self.library,'bundle':self.bundle,
            'runtime':self.rt['runtime'],'jdk21':self.rt['jdk21'],'jdk25':self.rt['jdk25'],
            'output':self.output+'/actual-artifacts','timeout':1800}
        self.api_request_sha = self.json(self.roles['api_request'],self.api_request)
        self.log('runner/run.py',b'SYNTHETIC captured runner',pin=self.inputs[C.BASE+'run.py'])
        self.log('runner/admission.py',b'SYNTHETIC captured admission',pin=self.inputs[C.BASE+'admission.py'])
        settings=('<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">\n'
          '  <mirrors><mirror><id>selected-central</id><mirrorOf>*</mirrorOf>\n'
          '    <url>https://repo.maven.apache.org/maven2</url>\n'
          '  </mirror></mirrors>\n</settings>\n').encode()
        self.log('child/home/.m2/settings.xml',settings)
        home=self.output+'/child/home';settings_path=home+'/.m2/settings.xml'
        self.argvs={
          'initial-new-config-stage':[self.rt['python'],'-I','-B',self.project+'/'+C.DELIVERY,'stage',
              '--output',self.output+'/stage','--cache',home+'/.cache/microproxy-formal','--runtime',self.rt['runtime'],
              '--java-home',self.rt['jdk21'],'--evidence',self.project+'/'+self.policy['delivery']['native_evidence']['path']],
          'private-maven-package':[self.rt['maven']+'/bin/mvn','-o','-q','--settings',settings_path,
              '--global-settings',settings_path,'-Dmaven.repo.local='+home+'/.m2/repository',
              '-pl','microproxy-starlark','-am','-DskipTests','package'],
          'whole-artifact-api':[self.rt['python'],'-I','-B',self.output+'/runner/run.py','_api','--request',
              self.output+'/api-request.json','--expected-request-sha256',self.api_request_sha]}
        self.environment={'PATH':self.rt['jdk21']+'/bin:'+self.rt['maven']+'/bin:/usr/bin:/bin',
            'LANG':'C','LC_ALL':'C','TZ':'UTC','HOME':home,'TMPDIR':self.output+'/child/tmp',
            'TMP':self.output+'/child/tmp','TEMP':self.output+'/child/tmp','XDG_CONFIG_HOME':self.output+'/child/config',
            'XDG_CACHE_HOME':self.output+'/child/cache','JAVA_HOME':self.rt['jdk21'],'MAVEN_SKIP_RC':'1',
            'PYTHONDONTWRITEBYTECODE':'1','MAVEN_USER_HOME':home+'/.m2'}
        self.report={'project':self.project,'tool_root':self.project,'runtime_locations':{n:self.rt[n] for n in
            ('prepared','data','hkdf','cache','junit','maven','maven_repository')},'commands':[],'scope':'SYNTHETIC UNIT ONLY'}
        for label,argv in self.argvs.items():
            raw={'argv':argv,'cwd':self.project,'environment':self.environment,'actual_exit_observed':True,
                 'returncode':0,'supervisor_failure':None,'log':self.output+'/logs/'+label+'.log',
                 'log_sha256':self.log('logs/'+label+'.log',b'SYNTHETIC UNIT log')}
            name='logs/'+label+'.raw-execution.json';pin=self.json(name,raw)
            self.report['commands'].append({'label':label,'argv':argv,'exit':0,'process_group_empty_after_exit':True,
                'raw_execution_record':self.output+'/'+name,'raw_execution_sha256':pin})
        self.api={'repository_root':self.project,'tool_root':self.project,
            'java_homes':{'21':self.rt['jdk21'],'25':self.rt['jdk25']},
            'inputs':{n:self.api_request[n] for n in ('stage','classes','library','bundle','runtime')},'commands':[]}
        self.api['inputs']['java_homes']=[self.rt['jdk21'],self.rt['jdk25']]
        self.api['inputs']['delivery_manifest_sha256']=self.policy['delivery']['config']['sha256']
        self.api['tools']={n:self.inputs[n] for n in (C.API,C.DELIVERY,'formal/crypto/bundle_checks.py','formal/nonce/BundleNonceSmoke.java')}
        apiargv={
            'jdk-0-version':[self.rt['jdk21']+'/bin/java','-version'],
            'jdk-1-version':[self.rt['jdk25']+'/bin/java','-version'],
            'delivery-check':[self.rt['python'],self.project+'/'+C.DELIVERY,'check','--stage',self.output+'/stage',
                '--classes',self.api_request['classes'],'--jar',self.library,'--runtime',self.rt['runtime'],'--java-home',self.rt['jdk21']],
            'bundle-check':[self.rt['python'],self.project+'/formal/crypto/bundle_checks.py','--library',self.library,
                '--bundle',self.bundle,'--delivery-receipt',self.output+'/actual-artifacts/delivery-check.json',
                '--stage',self.output+'/stage','--runtime',self.rt['runtime'],'--java-home',self.rt['jdk21'],
                '--java-home',self.rt['jdk25'],'--output',self.output+'/actual-artifacts/bundle-check']}
        for label,argv in apiargv.items():
            row={'label':label,'argv':argv,'exit':0}
            for stream in ('stdout','stderr'):row[stream+'_sha256']=self.log('actual-artifacts/'+label+'.'+stream+'.log',b'SYNTHETIC')
            self.api['commands'].append(row)
        self.bundle_receipt={'commands':[],'runs':{},'nonce_smoke':{'runs':{}}}
        for label in ['version-0','version-1','compile-harness','jdk21-bundle-smoke','jdk25-bundle-smoke',
                      'compile-nonce-smoke','jdk21-nonce-smoke','jdk25-nonce-smoke']:
            self.bundle_receipt['commands'].append({'label':label,'exit':0,'log_sha256':self.log('actual-artifacts/bundle-check/'+label+'.log',b'SYNTHETIC')})
        for major in ('21','25'):
            self.bundle_receipt['runs'][major]={'classload_sha256':self.log('actual-artifacts/bundle-check/jdk'+major+'-classload.log',b'SYNTHETIC')}
            self.bundle_receipt['nonce_smoke']['runs'][major]={'classload_sha256':self.log('actual-artifacts/bundle-check/jdk'+major+'-nonce-classload.log',b'SYNTHETIC')}
        self.rows={'report':self.report,'api_report':self.api,'bundle_receipt':self.bundle_receipt,
                   'policy':self.policy,'execution_request':self.request,'api_request':self.api_request,
                   'tools_before':{'trees':{n:{'SYNTHETIC tool':n} for n in ('jdk21','jdk25','maven')},
                       'python_sha256':self.tools['python_sha256'],'runtime_sha256':self.tools['runtime_sha256'],**self.operands},
                   'stage_receipt':{'jdk_home':self.rt['jdk21'],'manifest_sha256':self.policy['delivery']['config']['sha256']}}
        self.bind_SYNTHETIC_python(self.rt['python'],self.rt['python'],self.rt['python'])

    def bind_SYNTHETIC_python(self,launch,observed,resolved):
        """UNIT ONLY independent qualified observation, never host-side resolution."""
        self.rt['python']=launch
        self.qualified_python={'qualification':False,'path':resolved,'sha256':self.tools['python_sha256'],
            'actual_sys_executable':observed,'actual_qualification_argv':[launch,'-I','-B'],
            'mandatory_flags':['-I','-B'],'implementation':'cpython','version':[3,13,9],
            'framework':'/SYNTHETIC-DARWIN/3.13/Python','framework_sha256':sha(b'SYNTHETIC framework'),
            'actual_sys_flags':{'isolated':1,'dont_write_bytecode':1,'optimize':0,'ignore_environment':1,'no_user_site':1}}
        qsha=self.json(self.roles['qualified_python'],self.qualified_python)
        self.request['python']={'path':launch,'sha256':self.tools['python_sha256'],
            'observed_sys_executable':observed,
            'resolved_executable':{'path':resolved,'sha256':self.tools['python_sha256']},
            'framework':{'path':self.qualified_python['framework'],'sha256':self.qualified_python['framework_sha256']},
            'qualified_python_sha256':qsha}
        self.request_sha=self.json(self.roles['execution_request'] if 'execution_request' in self.roles else 'execution_request.json',self.request)
        self.rows['qualified_python']=self.qualified_python
        for label in ('initial-new-config-stage','whole-artifact-api'):
            argv=list(next(r for r in self.report['commands'] if r['label']==label)['argv']);argv[0]=observed
            self.argvs[label]=argv;self.coherently_replace_epoch_argv(label,argv)
        for label in ('delivery-check','bundle-check'):
            next(r for r in self.api['commands'] if r['label']==label)['argv'][0]=observed

    def log(self,name,raw,pin=None):
        self.pins[name]=write(self.root/name,raw) if pin is None else pin
        return self.pins[name]

    def json(self,name,value):
        return self.log(name,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())

    def coherently_replace_epoch_argv(self,label,argv):
        row=next(r for r in self.report['commands'] if r['label']==label)
        name='logs/'+label+'.raw-execution.json';raw=json.loads((self.root/name).read_bytes())
        row['argv']=argv;raw['argv']=argv;row['raw_execution_sha256']=self.json(name,raw)


class SYNTHETICFullFlowFixture(SYNTHETICCommandFixture):
    """UNIT ONLY. Cold original and HKDF proof admission are explicit mocks.

    Selection, file capture, source/class/test inventories, policy loading,
    receipt chains, pure artifact rules, command checks and check() are REAL.
    No fabricated receipt escapes unittest's temporary directory.
    """
    def __init__(self, root):
        super().__init__(root)
        source_root = Path(os.environ.get('HKDF_CI_UNIT_SOURCE_ROOT', str(HERE.parents[3]))).resolve()
        if not (source_root / C.OLD / 'ci/run.py').is_file():
            raise RuntimeError('SYNTHETIC UNIT needs explicit HKDF_CI_UNIT_SOURCE_ROOT for pinned read-only source fixtures')
        self.repository = root / 'SYNTHETIC-SOURCE-UNIT'
        self.current_project = root / 'SYNTHETIC-CURRENT-PROJECT-UNIT'
        payloads = {}
        for name in C.CODE:
            origin = HERE / Path(name).name if name in (C.BASE+'ci.py',C.BASE+'admission.py') else source_root/name
            payloads[name] = origin.read_bytes()
        for name in ('formal/crypto/bundle_checks.py','formal/nonce/BundleNonceSmoke.java'):
            payloads[name] = (source_root/name).read_bytes()
        self.notice_names = ('META-INF/LICENSE-dafny.txt','META-INF/LICENSE-go-mlkem.txt','META-INF/NOTICE-crypto.txt')
        payloads.update({'pom.xml':b'<project>SYNTHETIC UNIT root</project>',
            'quic/pom.xml':b'<project>SYNTHETIC UNIT quic</project>',
            'formal/crypto/Native.dfy':b'// SYNTHETIC UNIT ONLY; no theorem\n',
            'quic/src/main/java/io/github/mahmoudimus/quic/Native.java':b'// SYNTHETIC UNIT ONLY; never compiled\n',
            'old-note.txt':b'SYNTHETIC new unit note',
            C.BASE+'delivery.json':b'{"output_name":"NativeCrypto"}',
            'formal/crypto/delivery.json':b'{"output_name":"NativeCrypto"}',
            C.BASE+'predecessor.json':b'{"SYNTHETIC_UNIT_ONLY":"old configuration"}',
            C.BASE+'native-inputs.json':b'{"SYNTHETIC_UNIT_ONLY":"native boundary mocked"}',
            'formal/source/hkdf/inputs-v2.json':b'{"SYNTHETIC_UNIT_ONLY":"HKDF admission mocked"}',
            'formal/source/hkdf/SOURCE-EVIDENCE-v2.json':b'{"SYNTHETIC_UNIT_ONLY":"no actual proof receipt"}'})
        self.test_inputs = {}
        for n in range(189):
            name=f'p/Preserved{n}.class';data=f'SYNTHETIC immutable input{n}'.encode()
            payloads['quic/target/test-classes/'+name]=data
            self.test_inputs[name]=sha(data)
        for name in self.notice_names:
            payloads['quic/src/main/resources/'+name]=('SYNTHETIC UNIT notice '+name).encode()
        self.inputs={n:write(self.repository/n,data) for n,data in payloads.items()}
        for n,data in payloads.items():write(self.current_project/n,data)
        self.outputs={'directories':{n:{'path':p,'sha256':self.inputs[p]} for n,p in
                      [('target','pom.xml'),('quic/target','quic/pom.xml')]},'files':{}}
        self.class_payloads={f'io/github/mahmoudimus/quic/SYNTHETIC{n:03}.class':
                             f'SYNTHETIC UNIT class bytes{n}'.encode() for n in range(468)}
        self.classes={n:write(self.current_project/'quic/target/classes'/n,data) for n,data in self.class_payloads.items()}
        self.resources={n:write(self.current_project/'quic/target/classes'/n,payloads['quic/src/main/resources/'+n]) for n in self.notice_names}
        self.tests={**self.test_inputs,C.ARRAY_TEST:write(self.current_project/'quic/target/test-classes'/C.ARRAY_TEST,b'SYNTHETIC added test')}
        other_test=write(self.current_project/'target/test-classes/OtherReactorTest.class',b'SYNTHETIC other reactor output')
        self.test_trees={'quic/target/test-classes':self.tests,'target/test-classes':{'OtherReactorTest.class':other_test}}
        self.library_sha=write(self.current_project/'quic/target/quic-UNIT.jar',b'SYNTHETIC UNIT; not a JAR')
        self.bundle_sha=write(self.current_project/'microproxy-starlark/target/microproxy-starlark-UNIT-all.jar',b'SYNTHETIC UNIT; not a bundle')
        # The bundle output belongs to a third exact POM-owned reactor target.
        extra_pom='microproxy-starlark/pom.xml';extra_raw=b'<project>SYNTHETIC UNIT bundle</project>'
        payloads[extra_pom]=extra_raw;self.inputs[extra_pom]=write(self.repository/extra_pom,extra_raw)
        write(self.current_project/extra_pom,extra_raw)
        self.outputs['directories']['microproxy-starlark/target']={'path':extra_pom,'sha256':self.inputs[extra_pom]}
        self.real_load_module=C.A.load_module
        helper=self.real_load_module('SYNTHETIC_UNIT_TYPED_HELPER',self.repository/C.TOOLING,self.inputs[C.TOOLING])
        self.local_sdk=root/'SYNTHETIC-LOCAL-SDK-UNIT'
        write(self.local_sdk/'bin/compiler',b'SYNTHETIC non-executable tool bytes')
        self.typed_tree=helper.tree_snapshot(self.local_sdk)
        self.tools={'python_sha256':C.A.sha(Path(sys.executable).resolve()),'runtime_sha256':sha(b'SYNTHETIC runtime'),
            **{n+'_tree_sha256':C.A.map_sha(self.typed_tree) for n in ('jdk21','jdk25','maven')},
            'maven_repository_tree_sha256':C.A.map_sha(self.operands['maven_repository'])}
        old_inputs={'formal/crypto/Native.dfy':self.inputs['formal/crypto/Native.dfy'],'old-note.txt':sha(b'SYNTHETIC old unit note')}
        old_classes=dict(self.classes);old_classes[sorted(old_classes)[-1]]=sha(b'SYNTHETIC old class')
        def delta(before,after):
            return {'changed':{n:{'before':before[n],'after':after[n]} for n in before.keys()&after.keys() if before[n]!=after[n]},
                    'added':{n:after[n] for n in after.keys()-before.keys()},'removed':{n:before[n] for n in before.keys()-after.keys()}}
        self.original={'epoch_files':old_inputs}
        prepared_bytes=b'{"SYNTHETIC_UNIT_ONLY":"Darwin preparation boundary mocked"}'
        prepared_sha=write(self.root/self.roles['prepared_receipt'],prepared_bytes)
        ref=lambda n:{'path':n,'sha256':self.inputs[n]}
        self.policy={'schema':C.A.SCHEMA,'epoch':'hkdf-array-001','qualification':False,
            'predecessor':{'inputs':old_inputs,'classes':old_classes},'candidate':{'inputs':self.inputs,'classes':self.classes},
            'allowed':{'inputs':delta(old_inputs,self.inputs),'classes':delta(old_classes,self.classes)},
            'retained':{'ci':ref(C.OLD+'ci/run.py'),'selection':ref(C.OLD+'ci/selection.json'),'prepared_receipt_sha256':prepared_sha},
            'hkdf':{'manifest':ref('formal/source/hkdf/inputs-v2.json'),'receipt':ref('formal/source/hkdf/SOURCE-EVIDENCE-v2.json'),
                'projector':ref('formal/source/hkdf/tooling/source_evidence.py'),
                'raw_files':{'SYNTHETIC.raw':sha(b'SYNTHETIC')},
                'producers':{'formal/source/hkdf/tooling/source_evidence.py':self.inputs['formal/source/hkdf/tooling/source_evidence.py']},
                'tool_map_sha256':sha(b'SYNTHETIC external HKDF tool map')},
            'delivery':{'predecessor':ref(C.BASE+'predecessor.json'),'config':ref(C.BASE+'delivery.json'),
                'native_evidence':ref(C.BASE+'native-inputs.json'),'api':ref(C.API),'timeout':1800,'build_outputs':self.outputs},
            'tools':self.tools}
        self.policy_sha=self.json(self.roles['policy'],self.policy)
        self.policy_path=self.repository/C.BASE/'inputs.json'
        write(self.policy_path,(json.dumps(self.policy,sort_keys=True,indent=2)+'\n').encode())
        self.request['policy']['sha256']=self.policy_sha
        self.opts['expected-policy-sha256']=self.policy_sha
        self.request['argv']=['qualify',*[x for n,v in self.opts.items() for x in ('--'+n,v)]]
        self.request['python']['sha256']=self.tools['python_sha256']
        self.bind_SYNTHETIC_python(self.rt['python'],self.rt['python'],self.rt['python'])
        for name in ('run','admission'):
            self.request['bootstrap'][name]['sha256']=self.inputs[C.BASE+name+'.py']
            self.log('runner/'+name+'.py',payloads[C.BASE+name+'.py'])
        self.request_sha=self.json(self.roles['execution_request'],self.request)
        self.api_request['api']=self.policy['delivery']['api']
        self.api_request['delivery_sha256']=self.inputs[C.DELIVERY]
        self.api_request_sha=self.json(self.roles['api_request'],self.api_request)
        worker=list(self.argvs['whole-artifact-api']);worker[-1]=self.api_request_sha
        self.coherently_replace_epoch_argv('whole-artifact-api',worker)
        native_name='io/github/mahmoudimus/quic/Native.java'
        native_classes=dict(list(self.classes.items())[:66])
        self.stage={'schema':'microproxy.crypto-delivery-stage/v1','status':'complete','component':None,
            'manifest_sha256':self.policy['delivery']['config']['sha256'],'jdk_home':self.rt['jdk21'],
            'inputs':{n:self.inputs[n] for n in ('formal/crypto/Native.dfy','formal/crypto/delivery.json')},
            'sources':{'formal/crypto/Native.dfy':self.inputs['formal/crypto/Native.dfy']},
            'delivered_sources':{native_name:self.inputs['quic/src/main/java/'+native_name]},
            'canonical_classes':native_classes,'generated_files':{'Native.java':sha(payloads['quic/src/main/java/'+native_name])}}
        self.roles['stage_receipt']='stage/receipt.json'
        for n in self.stage['inputs']:self.log('stage/inputs/'+n,payloads[n])
        self.log('stage/sources/'+native_name,payloads['quic/src/main/java/'+native_name])
        self.log('stage/NativeCrypto-java/Native.java',payloads['quic/src/main/java/'+native_name])
        for n in native_classes:self.log('stage/classes/'+n,self.class_payloads[n])
        stage_sha=self.json(self.roles['stage_receipt'],self.stage)
        self.original_stage=copy.deepcopy(self.stage)
        self.delivery={'status':'checked','classes':self.classes,'class_count':468,'generated_class_count':66,
            'jar_sha256':self.library_sha,'stage_receipt_sha256':stage_sha,'handwritten_sources':1,
            'handwritten_lint':[],'comparison':'exact class bytes including all debug attributes'}
        self.roles['delivery_receipt']='actual-artifacts/delivery-check.json'
        delivery_sha=self.json(self.roles['delivery_receipt'],self.delivery)
        self.api['tools']={n:self.inputs[n] for n in (C.API,C.DELIVERY,'formal/crypto/bundle_checks.py','formal/nonce/BundleNonceSmoke.java')}
        b=self.bundle_receipt
        b.update(schema='microproxy.crypto-current-bundle/v2',status='complete',library_jar_sha256=self.library_sha,
            bundle_jar_sha256=self.bundle_sha,stage_receipt_sha256=stage_sha,
            artifact_inputs={'library.jar':self.library_sha,'bundle.jar':self.bundle_sha,
                'delivery.json':delivery_sha,'runtime-reference.jar':self.tools['runtime_sha256']},
            canonical={'classes':self.classes,'stage_receipt_sha256':stage_sha},
            crypto_classes=dict(list(self.classes.items())[:84]),retained_library_classes=self.classes,
            runtime_classes={f'dafny/SYNTHETIC{n}.class':sha(str(n).encode()) for n in range(37)},
            resources=self.resources,source_inputs=self.api['tools'],jdk_inputs={self.rt[n]:{'SYNTHETIC':sha(n.encode())} for n in ('jdk21','jdk25')})
        for run in b['runs'].values():run.update(completed_full_handshakes=9,loaded_classes={'SYNTHETIC':'file:/SYNTHETIC-DARWIN/bundle'})
        nonce=b['nonce_smoke'];nonce.update(schema='microproxy.nonce-bundle-smoke/v1',
            source='formal/nonce/BundleNonceSmoke.java',source_sha256=self.inputs['formal/nonce/BundleNonceSmoke.java'],
            harness_classes={'nonceadoption/BundleNonceSmoke.class':sha(b'SYNTHETIC harness')})
        for run in nonce['runs'].values():
            origin='file:/SYNTHETIC-DARWIN/bundle';harness='file:/SYNTHETIC-DARWIN/harness'
            run.update(cases=9,passed=9,origins={'PacketKey':origin,'VerifiedNonce':origin,'DafnyRuntime':origin,'harness':harness},
                cases_detail=[{'suite':suite,'packet_number':pn,'nonce':'00'*12,'ciphertext_sha256':sha((suite+str(pn)).encode())}
                    for suite in ('TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256') for pn in (0,1,-1)],
                loaded_classes={'io.github.mahmoudimus.quic.crypto.PacketKey':origin,
                    'io.github.mahmoudimus.quic.crypto.internal.verifiednonce.VerifiedNonce.__default':origin,
                    'dafny.Helpers':origin,'nonceadoption.BundleNonceSmoke':harness})
        bundle_sha=self.json(self.roles['bundle_receipt'],b)
        # Reuse the REAL pure artifact receipt validators. No subprocess APIs.
        self.real_load_module('delivery',self.repository/C.DELIVERY,self.inputs[C.DELIVERY])
        rules=self.real_load_module('SYNTHETIC_UNIT_REAL_ARTIFACT_RULES',self.repository/C.API,self.inputs[C.API])
        checked=rules._check_delivery_receipt(self.delivery,stage_receipt=self.stage,library_sha=self.library_sha,stage_sha=stage_sha)
        checked_bundle=rules._check_bundle_receipt(b,delivery_receipt=self.delivery,library_sha=self.library_sha,
            bundle_sha=self.bundle_sha,runtime_sha=self.tools['runtime_sha256'],delivery_receipt_sha=delivery_sha,
            stage_sha=stage_sha,tool_hashes=self.api['tools'],java_homes={'21':Path(self.rt['jdk21']),'25':Path(self.rt['jdk25'])})
        self.api.update(schema='microproxy.crypto-current-release-artifact-validation/v1',status='complete',
            delivery={**{n:checked[n] for n in ('class_count','generated_class_count','handwritten_sources','stage_receipt_sha256','jar_sha256')},'receipt_sha256':delivery_sha},
            bundle={**checked_bundle,'receipt_sha256':bundle_sha})
        self.api['inputs'].update(library_sha256=self.library_sha,bundle_sha256=self.bundle_sha,
            runtime_sha256=self.tools['runtime_sha256'],stage_receipt_sha256=stage_sha,
            delivery_manifest_sha256=self.policy['delivery']['config']['sha256'])
        api_sha=self.json(self.roles['api_report'],self.api)
        self.hkdf_local={n:{'SYNTHETIC_UNIT_ONLY':'external HKDF proof admission mocked'} for n in
            ('producer_pins','class_maps','runtime_suites','proof_counts')}
        self.hkdf_local.update(scope='SYNTHETIC UNIT ONLY',qualification=False,
            manifest_sha256=self.inputs['formal/source/hkdf/inputs-v2.json'],receipt_sha256=self.inputs['formal/source/hkdf/SOURCE-EVIDENCE-v2.json'],
            raw_map_sha256=sha(b'SYNTHETIC raw map'),complete_before_after_maps_match=True,
            shared_component_validation={'project_root':str(self.repository),'full_ledger':False,'globalV7':False,'artifactqualification':False})
        hkdf_retained=copy.deepcopy(self.hkdf_local);hkdf_retained['shared_component_validation']['project_root']=self.project
        self.report.update(schema=C.DELIVERY_SCHEMA,status='complete bounded delivery',qualification=False,
            artifact_API_called=True,policy_sha256=self.policy_sha,complete_input_maps_match=True,
            complete_tool_maps_match=True,artifact_report_sha256=api_sha,whole_artifact=self.api,
            build_output_policy=self.outputs,hkdf=hkdf_retained)
        before_tools={'trees':{n:self.typed_tree for n in ('jdk21','jdk25','maven')},
            'python_sha256':self.tools['python_sha256'],'runtime_sha256':self.tools['runtime_sha256'],**self.operands}
        actual_project=C.A.files(self.current_project)
        build={n:h for n,h in actual_project.items() if n not in self.inputs}
        map_values={'inputs_before':self.inputs,'inputs_after':self.inputs,'tools_before':before_tools,
            'tools_after':before_tools,'project_after':actual_project,'build_outputs_after':build}
        role_names={'inputs_before':'INPUTS-BEFORE.json','inputs_after':'INPUTS-AFTER.json','tools_before':'TOOLS-BEFORE.json',
            'tools_after':'TOOLS-AFTER.json','project_after':'PROJECT-TREE-AFTER.json','build_outputs_after':'BUILD-OUTPUTS-AFTER.json'}
        self.report['maps']={}
        for role,value in map_values.items():
            name=role_names[role];self.roles[role]=name;pin=self.json(name,value)
            self.report['maps'][name]={'path':name,'sha256':pin}
        report_sha=self.json(self.roles['report'],self.report)
        source_trees={}
        for ref in self.outputs['directories'].values():
            for part in ('src/main/java','src/main/resources','src/test/java','src/test/resources'):
                name=str(Path(ref['path']).parent/part);prefix=name+'/'
                source_trees[name]={n[len(prefix):]:h for n,h in self.inputs.items() if n.startswith(prefix)}
        self.checkout={'schema':C.CHECKOUT_SCHEMA,'policy_sha256':self.policy_sha,'report_sha256':report_sha,
            'api_report_sha256':api_sha,'stage_receipt_sha256':stage_sha,'project_inputs':self.inputs,
            'audited_inputs':self.inputs,'class_files':self.classes,'resources':self.resources,
            'test_input_binaries':self.test_inputs,'test_outputs':self.tests,
            'test_output_trees':{**self.test_trees,'microproxy-starlark/target/test-classes':{}},
            'source_trees':source_trees,'build_outputs':self.outputs}
        checkout_sha=self.json(self.roles['checkout'],self.checkout)
        self.pins=C.A.files(self.root)
        self.index={'schema':C.INDEX_SCHEMA,'scope':'retained-Darwin-arm64','roles':self.roles,'files':self.pins}
        index_raw=(json.dumps(self.index,sort_keys=True,indent=2)+'\n').encode()
        self.index_sha=write(self.root/'index.json',index_raw)
        self.selection={'schema':C.SELECTION_SCHEMA,'scope':C.SCOPE,
            'code':{n:self.inputs[n] for n in C.CODE},'original_maps':C.ORIGINAL_MAPS,
            'local_tools':{'SYNTHETIC_compiler':self.typed_tree},'local_python_sha256':C.A.sha(Path(sys.executable).resolve()),
            'retained':{'index_sha256':self.index_sha,'policy_sha256':self.policy_sha,'prepared_receipt_sha256':prepared_sha,
                'checkout_sha256':checkout_sha,'tool_map_sha256':C.A.map_sha(before_tools),'execution_request_sha256':self.request_sha}}
        self.selection['retained']['qualified_python_sha256']=self.pins[self.roles['qualified_python']]
        self.selection_path=root/'SYNTHETIC-SELECTION-UNIT.json'
        selection_sha=write(self.selection_path,(json.dumps(self.selection,sort_keys=True,indent=2)+'\n').encode())
        self.local_tools_path=root/'SYNTHETIC-LOCAL-TOOLS-UNIT.json'
        write(self.local_tools_path,json.dumps({'SYNTHETIC_compiler':str(self.local_sdk)}).encode())
        hkdf_raw=root/'SYNTHETIC-HKDF-RAW-UNIT';write(hkdf_raw/'SYNTHETIC.raw',b'SYNTHETIC')
        self.args=SimpleNamespace(repository=self.repository,project=self.current_project,policy=self.policy_path,
            selection=self.selection_path,expected_selection_sha256=selection_sha,retained_data=self.root,
            original_data=root/'SYNTHETIC-ORIGINAL-DATA',prepared=root/'SYNTHETIC-LOCAL-PREPARED',
            expected_prepared_sha256=sha(b'SYNTHETIC local preparation mock'),classes=self.current_project/'quic/target/classes',
            test_outputs=self.current_project/'quic/target/test-classes',local_tools=self.local_tools_path,hkdf_raw=hkdf_raw)

    def external_boundary_mocks(self):
        stack=ExitStack()
        stack.enter_context(mock.patch.object(C,'cold_original',return_value=(self.original,
            {'qualification':False,'scope':'SYNTHETIC original-admission boundary mocked'},self.original_stage)))
        def load(name,path,expected):
            module=self.real_load_module(name,path,expected)
            if name=='hkdf_ci_epoch_runner':
                module.check_hkdf=lambda project,policy:copy.deepcopy(self.hkdf_local)
                module.managed_hkdf_sources=lambda project,policy:{}
            return module
        stack.enter_context(mock.patch.object(C.A,'load_module',side_effect=load))
        return stack

    def reseal_SYNTHETIC_unit_mutation(self, *, report_changed=False):
        """UNIT ONLY coherent forged index; independent request authority stays fixed."""
        if report_changed:
            self.checkout['report_sha256']=self.json(self.roles['report'],self.report)
        checkout_sha=self.json(self.roles['checkout'],self.checkout)
        self.index['files']={n:h for n,h in C.A.files(self.root).items() if n!='index.json'}
        index_sha=write(self.root/'index.json',(json.dumps(self.index,sort_keys=True,indent=2)+'\n').encode())
        self.selection['retained'].update(index_sha256=index_sha,checkout_sha256=checkout_sha)
        self.args.expected_selection_sha256=write(self.selection_path,(json.dumps(self.selection,sort_keys=True,indent=2)+'\n').encode())


class DataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_path_free_maps_are_fixed_independent_authority(self):
        C.check_original_maps(dict(C.ORIGINAL_MAPS))
        for role in C.ORIGINAL_MAPS:
            with self.subTest(role=role):
                bad = dict(C.ORIGINAL_MAPS)
                bad[role] = sha(b'wrong original content')
                with self.assertRaises(ValueError):
                    C.check_original_maps(bad)

    def test_extra_or_omitted_original_map_rejected(self):
        for bad in ({}, {**C.ORIGINAL_MAPS, 'extra': sha(b'extra')}):
            with self.assertRaises(ValueError):
                C.check_original_maps(bad)

    def test_local_preparation_never_replaces_darwin_pin(self):
        darwin = sha(b'actual fixture Darwin receipt bytes')
        local = sha(b'different actual fixture Linux receipt bytes')
        policy = {'retained': {'prepared_receipt_sha256': darwin}}
        C.check_darwin_preparation(policy, darwin, darwin)
        with self.assertRaises(ValueError):
            C.check_darwin_preparation(policy, darwin, local)
        with self.assertRaises(ValueError):
            C.check_darwin_preparation({'retained': {'prepared_receipt_sha256': local}}, darwin, local)

    def test_local_preparation_paths_preserve_local_own_identity(self):
        p = self.root / 'local-prepared'
        receipt = {n: str(p / rel) for n, rel in C.PREPARED_PATHS.items()}
        C.check_local_paths(p, receipt)
        for n in receipt:
            bad = dict(receipt)
            bad[n] = str(self.root / 'darwin-old-path' / n)
            with self.subTest(role=n), self.assertRaises(ValueError):
                C.check_local_paths(p, bad)

    def test_clone_map_is_original_plus_exact_overlays_and_removals(self):
        original = {'main/A.java': sha(b'old'), 'remove.txt': sha(b'gone')}
        overlay = {'main/A.java': sha(b'current'), 'ci.py': sha(b'actual helper')}
        expected = {'main/A.java': overlay['main/A.java'], 'ci.py': overlay['ci.py']}
        C.check_clone(original, overlay, {'remove.txt': original['remove.txt']}, expected)
        for bad in ({**expected, 'unselected': sha(b'x')}, {'ci.py': overlay['ci.py']}):
            with self.assertRaises(ValueError):
                C.check_clone(original, overlay, {'remove.txt': original['remove.txt']}, bad)
        with self.assertRaises(ValueError):
            C.check_clone(original, overlay, {'absent': sha(b'x')}, expected)

    def project_fixture(self):
        project = self.root / 'project'
        before = {'pom.xml': write(project / 'pom.xml', b'<project/>'),
                  'quic/pom.xml': write(project / 'quic/pom.xml', b'<project>quic</project>'),
                  'quic/src/main/java/A.java': write(project / 'quic/src/main/java/A.java', b'class A{}'),
                  'quic/target/test-classes/Old.class': write(project / 'quic/target/test-classes/Old.class', b'old test input')}
        outputs = {'directories': {'target': {'path': 'pom.xml', 'sha256': before['pom.xml']},
                    'quic/target': {'path': 'quic/pom.xml', 'sha256': before['quic/pom.xml']}}, 'files': {}}
        return project, before, outputs

    def test_complete_project_inputs_and_outputs_have_separate_roles(self):
        project, before, outputs = self.project_fixture()
        write(project / 'quic/target/classes/A.class', b'generated')
        result = C.check_project_inputs(project, before, outputs)
        self.assertEqual(result['inputs'], before)
        self.assertEqual(set(result['outputs']), {'quic/target/classes/A.class'})

    def test_retained_complete_map_partition_rejects_coherent_extra_input(self):
        inputs = {'pom.xml': sha(b'pom')}
        outputs = {'target/X.class': sha(b'class')}
        C.check_partition(inputs, outputs, {**inputs, **outputs})
        with self.assertRaises(ValueError):
            C.check_partition(inputs, outputs, {**inputs, **outputs, '.mvn/extensions.xml': sha(b'extra')})
        with self.assertRaises(ValueError):
            C.check_partition(inputs, {**outputs, 'pom.xml': inputs['pom.xml']}, {**inputs, **outputs})

    def test_exact_retained_stage_tree_rejects_extra_or_changed_class(self):
        wanted = {'Native.class': sha(b'native')}
        pins = {'stage/classes/Native.class': wanted['Native.class'], 'stage/receipt.json': sha(b'receipt')}
        C.check_index_subtree(pins, 'stage/classes', wanted)
        for bad in ({**pins, 'stage/classes/Unselected.class': sha(b'extra')},
                    {**pins, 'stage/classes/Native.class': sha(b'changed')}):
            with self.assertRaises(ValueError):
                C.check_index_subtree(bad, 'stage/classes', wanted)

    def test_extra_source_tool_and_unrelated_target_rejected(self):
        for path in ['microproxy-starlark/src/main/java/Extra.java', '.mvn/extensions.xml', 'other/target/output.class']:
            with self.subTest(path=path):
                project, before, outputs = self.project_fixture()
                target = project / path
                write(target, b'unselected')
                with self.assertRaises(ValueError):
                    C.check_project_inputs(project, before, outputs)
                target.unlink()

    def test_preexisting_target_input_cannot_be_reclassified_as_output(self):
        project, before, outputs = self.project_fixture()
        (project / 'quic/target/test-classes/Old.class').write_bytes(b'mutated')
        with self.assertRaises(ValueError):
            C.check_project_inputs(project, before, outputs)

    def test_missing_current_input_rejected(self):
        project, before, outputs = self.project_fixture()
        (project / 'quic/src/main/java/A.java').unlink()
        with self.assertRaises(ValueError):
            C.check_project_inputs(project, before, outputs)

    def test_classes_resources_and_test_outputs_exact_no_omissions_or_extras(self):
        main, tests = self.root / 'classes', self.root / 'tests'
        cm = {'p/A.class': write(main / 'p/A.class', b'production')}
        resources = {'META-INF/NOTICE.txt': write(main / 'META-INF/NOTICE.txt', b'notice')}
        tm = {'p/T.class': write(tests / 'p/T.class', b'test')}
        C.check_compiled_trees(main, tests, cm, resources, tm)
        for tree, path in [(main, 'p/Extra.class'), (tests, 'p/ExtraTest.class')]:
            extra = tree / path
            write(extra, b'extra')
            with self.assertRaises(ValueError):
                C.check_compiled_trees(main, tests, cm, resources, tm)
            extra.unlink()
        (main / 'p/A.class').unlink()
        with self.assertRaises(ValueError):
            C.check_compiled_trees(main, tests, cm, resources, tm)

    def test_old189_inputs_cannot_be_mislabeled_as_actual190_outputs(self):
        old = {f'p/Test{n}.class': sha(str(n).encode()) for n in range(189)}
        actual = {**old, C.ARRAY_TEST: sha(b'array input test')}
        C.check_test_roles(old, actual)
        with self.assertRaises(ValueError):
            C.check_test_roles(old, old)
        with self.assertRaises(ValueError):
            C.check_test_roles(actual, actual)

    def test_historical189_overlapping_test_bytes_are_strictly_immutable(self):
        old = {f'p/Test{n}.class': sha(str(n).encode()) for n in range(189)}
        actual = {n: sha((n+'fresh compiler bytes').encode()) for n in old}
        actual[C.ARRAY_TEST] = sha(b'array input test')
        with self.assertRaisesRegex(ValueError, 'immutable'):
            C.check_test_roles(old, actual)

    def test_actual_test_count_is_selected_and_not_fixed_to_historical190(self):
        old = {f'p/Test{n}.class': sha(str(n).encode()) for n in range(189)}
        actual = {**old, C.ARRAY_TEST: sha(b'array'), 'p/NewCurrentTest.class': sha(b'new')}
        C.check_test_roles(old, actual)

    def test_current_code_and_API_tool_closure_cannot_be_omitted_or_rehashed(self):
        code = {n: C.FIXED_CODE.get(n, sha(n.encode())) for n in C.CODE}
        code[C.BASE + 'admission.py'] = C.ADMISSION_SHA256
        C.check_code_bindings(code, code, {C.API: code[C.API]})
        for bad in ({n: h for n, h in code.items() if n != C.BASE + 'ci.py'},
                    {**code, C.API: sha(b'unselected API source')}):
            with self.assertRaises(ValueError):
                C.check_code_bindings(code, bad, {C.API: code[C.API]})
        with self.assertRaises(ValueError):
            C.check_code_bindings(code, code, {'unbound/tool.py': sha(b'unbound')})

    def test_all_reactor_test_outputs_reject_unselected_extra_outside_quic(self):
        project, before, outputs = self.project_fixture()
        trees = {'target/test-classes': {}, 'quic/target/test-classes': {'Old.class': before['quic/target/test-classes/Old.class']}}
        C.check_all_test_outputs(project, outputs, trees)
        write(project / 'target/test-classes/Extra.class', b'new unselected output')
        with self.assertRaises(ValueError):
            C.check_all_test_outputs(project, outputs, trees)

    def test_retained_and_local_HKDF_root_roles_are_checked_without_raw_rewrite(self):
        fields = {'scope', 'qualification', 'manifest_sha256', 'receipt_sha256', 'raw_map_sha256',
                  'producer_pins', 'class_maps', 'runtime_suites', 'proof_counts', 'complete_before_after_maps_match'}
        retained = {n: {'fixture': 'only synthetic comparison data'} for n in fields}
        retained['shared_component_validation'] = {'project_root': '/fixture/darwin', 'manifest_sha256': sha(b'manifest')}
        local = copy.deepcopy(retained)
        local['shared_component_validation']['project_root'] = '/fixture/linux'
        unchanged = copy.deepcopy(retained)
        C.check_hkdf_identity(local, retained, '/fixture/linux', '/fixture/darwin')
        self.assertEqual(retained, unchanged)
        for field in ['project_root', 'manifest_sha256']:
            bad = copy.deepcopy(local)
            bad['shared_component_validation'][field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.check_hkdf_identity(bad, retained, '/fixture/linux', '/fixture/darwin')

    def test_code_and_tools_are_independently_bound(self):
        source = self.root / 'source'
        pins = {'ci.py': write(source / 'ci.py', b'captured source')}
        C.check_selected_files(source, pins)
        (source / 'ci.py').write_bytes(b'changed source')
        with self.assertRaises(ValueError):
            C.check_selected_files(source, pins)
        tool = self.root / 'local-tools'
        expected = {'bin/compiler': write(tool / 'bin/compiler', b'actual local compiler')}
        C.check_local_tools({'compiler': tool}, {'compiler': expected})
        write(tool / 'bin/unselected', b'extra tool')
        with self.assertRaises(ValueError):
            C.check_local_tools({'compiler': tool}, {'compiler': expected})
        with self.assertRaises(ValueError):
            C.check_local_tools({}, {'compiler': expected})

    def test_retained_index_missing_rejects_before_any_success(self):
        with self.assertRaises(ValueError):
            C.read_index(self.root / 'missing', sha(b'future actual index'))

    def test_retained_index_cannot_authorize_itself_or_extra_files(self):
        retained = self.root / 'retained'
        retained.mkdir()
        row = {'schema': C.INDEX_SCHEMA, 'scope': 'retained-Darwin-arm64', 'files': {}, 'roles': {}}
        raw = json.dumps(row).encode()
        (retained / 'index.json').write_bytes(raw)
        with self.assertRaises(ValueError):
            C.read_index(retained, sha(raw))

    def test_closed_retained_tree_does_not_ignore_unindexed_files(self):
        retained = self.root / 'retained'
        retained.mkdir()
        pins, roles = {}, {}
        for role in C.INDEX_ROLES:
            name = role + '.json'
            pins[name] = write(retained / name, b'{}')
            roles[role] = name
        raw = json.dumps({'schema': C.INDEX_SCHEMA, 'scope': 'retained-Darwin-arm64',
                          'files': pins, 'roles': roles}).encode()
        (retained / 'index.json').write_bytes(raw)
        C.read_index(retained, sha(raw))
        write(retained / 'unindexed.log', b'extra')
        with self.assertRaises(ValueError):
            C.read_index(retained, sha(raw))

    def test_coherent_index_rehash_cannot_replace_external_authority(self):
        retained = self.root / 'retained'
        retained.mkdir()
        pins, roles = {}, {}
        for role in C.INDEX_ROLES:
            name = role + '.json'
            pins[name] = write(retained / name, b'{}')
            roles[role] = name
        value = {'schema': C.INDEX_SCHEMA, 'scope': 'retained-Darwin-arm64', 'files': pins, 'roles': roles}
        raw = json.dumps(value).encode()
        (retained / 'index.json').write_bytes(raw)
        selected = sha(raw)
        C.read_index(retained, selected)
        pins[roles['report']] = write(retained / roles['report'], b'{"status":"coherently forged"}')
        (retained / 'index.json').write_bytes(json.dumps(value).encode())
        with self.assertRaises(ValueError):
            C.read_index(retained, selected)

    def test_incomplete_or_legacy_report_never_qualifies(self):
        for report in ({'status': 'failed/incomplete'},
                       {'schema': 'microproxy.keccak004-parent/1', 'status': 'complete'},
                       {'schema': C.DELIVERY_SCHEMA, 'status': 'complete bounded delivery', 'artifact_API_called': False}):
            with self.assertRaises(ValueError):
                C.require_completion(report, sha(b'policy'))

    def test_entry_rejects_O_and_OO_before_bootstrap_or_output(self):
        solo = self.root / 'solo'
        solo.mkdir()
        (solo / 'ci.py').write_bytes((HERE / 'ci.py').read_bytes())
        output = self.root / 'must-not-exist'
        for optimize in ['-O', '-OO']:
            r = subprocess.run([sys.executable, '-I', '-B', optimize, str(solo / 'ci.py'),
                                '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('requires unoptimized Python', r.stderr)
            self.assertNotIn('admission.py', r.stderr)
            self.assertFalse(output.exists())

    def test_sys_only_guard_precedes_argparse_and_every_other_import(self):
        source = (HERE / 'ci.py').read_bytes()
        for optimize, isolated, dont_write in [(1, 1, 1), (2, 1, 1), (0, 0, 1), (0, 1, 0)]:
            seen = []
            fake_sys = SimpleNamespace(flags=SimpleNamespace(optimize=optimize, isolated=isolated,
                                                             dont_write_bytecode=dont_write))
            def sentinel(name, *args, **kwargs):
                seen.append(name)
                if name == 'sys':
                    return fake_sys
                raise AssertionError('non-sys import ran before rejection: ' + name)
            env = {'__builtins__': {**vars(builtins), '__import__': sentinel},
                   '__file__': str(HERE / 'ci.py'), '__name__': 'SYNTHETIC_UNIT_ENTRY'}
            with self.subTest(flags=(optimize, isolated, dont_write)), self.assertRaises(RuntimeError):
                exec(compile(source, env['__file__'], 'exec'), env)
            self.assertEqual(seen, ['sys'])

    def test_actual_entry_rejects_missing_I_or_B_before_bootstrap(self):
        solo=self.root/'no-bootstrap'
        solo.mkdir();(solo/'ci.py').write_bytes((HERE/'ci.py').read_bytes())
        for flags in (['-I'],['-B'],[]):
            r=subprocess.run([sys.executable,*flags,str(solo/'ci.py')],capture_output=True,text=True)
            with self.subTest(flags=flags):
                self.assertNotEqual(r.returncode,0)
                self.assertIn('requires Python -I -B',r.stderr)
                self.assertNotIn('admission.py',r.stderr)


class SYNTHETICInvocationTests(unittest.TestCase):
    setUp = DataTests.setUp

    def test_SYNTHETIC_exact_recorded_commands_pass_data_admission(self):
        f=SYNTHETICCommandFixture(self.root)
        C.check_raw_commands(f.root,f.index,f.rows)

    def test_SYNTHETIC_different_selected_observed_and_resolved_python_spellings_pass(self):
        f=SYNTHETICCommandFixture(self.root)
        f.bind_SYNTHETIC_python('/SYNTHETIC-DARWIN/canonical/bin/python3.13',
            '/SYNTHETIC-DARWIN/observed-alias/bin/python3.13','/SYNTHETIC-DARWIN/canonical/bin/python3.13')
        C.check_raw_commands(f.root,f.index,f.rows)
        self.assertNotEqual(f.request['python']['path'],f.request['python']['observed_sys_executable'])
        self.assertEqual(f.report['commands'][0]['argv'][0],f.request['python']['observed_sys_executable'])

    def test_SYNTHETIC_python_role_bindings_reject_coherent_mutations(self):
        for i,role in enumerate(('launch','observed','resolved_path','resolved_hash','launch_hash','framework_path','framework_hash','qualification_hash','policy_binary')):
            f=SYNTHETICCommandFixture(self.root/str(i))
            f.bind_SYNTHETIC_python('/SYNTHETIC-DARWIN/canonical/bin/python3.13',
                '/SYNTHETIC-DARWIN/observed-alias/bin/python3.13','/SYNTHETIC-DARWIN/canonical/bin/python3.13')
            py=f.request['python']
            if role=='launch':py['path']=f.rt['python']='/SYNTHETIC-DARWIN/unqualified-launch'
            elif role=='observed':
                py['observed_sys_executable']='/SYNTHETIC-DARWIN/unqualified-alias'
                for label in ('initial-new-config-stage','whole-artifact-api'):
                    argv=list(next(r for r in f.report['commands'] if r['label']==label)['argv']);argv[0]=py['observed_sys_executable']
                    f.coherently_replace_epoch_argv(label,argv)
                for label in ('delivery-check','bundle-check'):next(r for r in f.api['commands'] if r['label']==label)['argv'][0]=py['observed_sys_executable']
            elif role=='resolved_path':py['resolved_executable']['path']='/SYNTHETIC-DARWIN/wrong-resolved-binary'
            elif role=='resolved_hash':py['resolved_executable']['sha256']=sha(b'wrong resolved binary')
            elif role=='launch_hash':py['sha256']=sha(b'wrong launch binary')
            elif role=='framework_path':py['framework']['path']='/SYNTHETIC-DARWIN/wrong-framework'
            elif role=='framework_hash':py['framework']['sha256']=sha(b'wrong framework')
            elif role=='qualification_hash':py['qualified_python_sha256']=sha(b'unselected qualification')
            else:
                old='87d4df53fd91304be5bac391fb204643c36b7df2023c04a0953bcbc7d4fdf634'
                f.policy['tools']['python_sha256']=old;f.rows['tools_before']['python_sha256']=old
                policy_sha=f.json(f.roles['policy'],f.policy)
                f.request['policy']['sha256']=policy_sha;f.opts['expected-policy-sha256']=policy_sha
                f.request['argv']=['qualify',*[x for n,v in f.opts.items() for x in ('--'+n,v)]]
            f.request_sha=f.json(f.roles.get('execution_request','execution_request.json'),f.request)
            with self.subTest(role=role),self.assertRaises(ValueError):C.check_raw_commands(f.root,f.index,f.rows)

    def test_SYNTHETIC_unrelated_programs_cannot_replace_any_owned_command(self):
        for label,argv in [('initial-new-config-stage',['/SYNTHETIC/unrelated','-o','package']),
                           ('private-maven-package',['/SYNTHETIC/unrelated','-o','package']),
                           ('whole-artifact-api',['/SYNTHETIC/unrelated','-o','package'])]:
            f=SYNTHETICCommandFixture(self.root/label)
            f.coherently_replace_epoch_argv(label,argv)
            with self.subTest(label=label),self.assertRaises(ValueError):
                C.check_raw_commands(f.root,f.index,f.rows)

    def test_SYNTHETIC_exact_stage_Maven_and_worker_operands_reject_coherent_mutants(self):
        cases=[('initial-new-config-stage',0,'/SYNTHETIC/other-python'),
            ('initial-new-config-stage',1,'-O'),('initial-new-config-stage',3,'/SYNTHETIC/other-script'),
            ('initial-new-config-stage',4,'publish'),('initial-new-config-stage',6,'/SYNTHETIC/other-stage'),
            ('initial-new-config-stage',8,'/SYNTHETIC/other-cache'),('initial-new-config-stage',10,'/SYNTHETIC/other-runtime'),
            ('initial-new-config-stage',12,'/SYNTHETIC/other-jdk'),('initial-new-config-stage',14,'/SYNTHETIC/other-evidence'),
            ('private-maven-package',0,'/SYNTHETIC/other-maven/bin/mvn'),('private-maven-package',1,'-X'),
            ('private-maven-package',4,'/SYNTHETIC/other-settings.xml'),('private-maven-package',6,'/SYNTHETIC/other-global.xml'),
            ('private-maven-package',7,'-Dmaven.repo.local=/SYNTHETIC/ambient/.m2'),
            ('private-maven-package',9,'microproxy'),('private-maven-package',10,'-N'),
            ('private-maven-package',11,'-Dmaven.test.skip=true'),('private-maven-package',12,'install'),
            ('whole-artifact-api',0,'/SYNTHETIC/other-python'),('whole-artifact-api',2,'-O'),
            ('whole-artifact-api',3,'/SYNTHETIC/other-worker.py'),('whole-artifact-api',4,'qualify'),
            ('whole-artifact-api',6,'/SYNTHETIC/other-request.json'),('whole-artifact-api',8,sha(b'wrong request'))]
        for i,(label,offset,value) in enumerate(cases):
            f=SYNTHETICCommandFixture(self.root/str(i));argv=list(f.argvs[label]);argv[offset]=value
            f.coherently_replace_epoch_argv(label,argv)
            with self.subTest(label=label,offset=offset),self.assertRaises(ValueError):
                C.check_raw_commands(f.root,f.index,f.rows)

    def test_SYNTHETIC_API_invocations_runtime_tools_and_environment_reject_mutants(self):
        for i,(label,offset) in enumerate([('jdk-0-version',0),('jdk-1-version',0),('delivery-check',1),
                ('delivery-check',4),('delivery-check',6),('delivery-check',8),('delivery-check',10),
                ('delivery-check',12),('bundle-check',1),('bundle-check',3),('bundle-check',5),
                ('bundle-check',7),('bundle-check',9),('bundle-check',11),('bundle-check',13),('bundle-check',15)]):
            f=SYNTHETICCommandFixture(self.root/('api'+str(i)))
            row=next(r for r in f.api['commands'] if r['label']==label)
            row['argv'][offset]='/SYNTHETIC/wrong-operand'
            with self.subTest(label=label,offset=offset),self.assertRaises(ValueError):
                C.check_raw_commands(f.root,f.index,f.rows)
        for key in ('JAVA_HOME','PATH','MAVEN_USER_HOME','JAVA_TOOL_OPTIONS'):
            f=SYNTHETICCommandFixture(self.root/key);row=f.report['commands'][1]
            name='logs/private-maven-package.raw-execution.json';raw=json.loads((f.root/name).read_bytes())
            raw['environment'][key]='SYNTHETIC unselected value';row['raw_execution_sha256']=f.json(name,raw)
            with self.subTest(environment=key),self.assertRaises(ValueError):
                C.check_raw_commands(f.root,f.index,f.rows)
        for key in ('delivery_manifest_sha256',):
            f=SYNTHETICCommandFixture(self.root/key);f.api['inputs'][key]=sha(b'wrong config')
            with self.assertRaises(ValueError):C.check_raw_commands(f.root,f.index,f.rows)
        for key in ('api','config'):
            f=SYNTHETICCommandFixture(self.root/('entry-'+key))
            if key=='api':
                f.policy['delivery']['api']={'path':'SYNTHETIC-unrelated-api.py','sha256':sha(b'unrelated')}
            else:
                f.policy['candidate']['inputs']['formal/crypto/delivery.json']=sha(b'wrong canonical config')
            with self.subTest(entry=key),self.assertRaises(ValueError):
                C.check_raw_commands(f.root,f.index,f.rows)


class SYNTHETICFullFlowTests(unittest.TestCase):
    setUp=DataTests.setUp

    def test_SYNTHETIC_full_check_positive_real_cross_function_admission(self):
        f=SYNTHETICFullFlowFixture(self.root)
        with f.external_boundary_mocks():
            result=C.check(f.args)
        self.assertEqual(result['status'],'complete')
        self.assertFalse(result['qualification'])
        self.assertFalse(result['fresh_Linux_proof_or_API'])
        self.assertFalse(result['globalV7'])
        self.assertEqual(result['production_classes'],468)
        self.assertEqual(result['actual_test_outputs'],190)

    def test_SYNTHETIC_full_check_different_qualified_child_spelling_passes(self):
        f=SYNTHETICFullFlowFixture(self.root)
        launch=f.rt['python']
        observed='/SYNTHETIC-DARWIN/observed-alias/bin/python3.13'
        f.bind_SYNTHETIC_python(launch,observed,launch)
        api_sha=f.json(f.roles['api_report'],f.api)
        f.report['artifact_report_sha256']=api_sha
        f.checkout['api_report_sha256']=api_sha
        f.selection['retained'].update(execution_request_sha256=f.request_sha,
            qualified_python_sha256=f.pins[f.roles['qualified_python']])
        f.reseal_SYNTHETIC_unit_mutation(report_changed=True)
        with f.external_boundary_mocks():result=C.check(f.args)
        self.assertEqual(result['status'],'complete')
        self.assertNotEqual(launch,observed)
        self.assertFalse(result['qualification'])

    def test_SYNTHETIC_full_check_rejects_changed_independent_Python_observation(self):
        f=SYNTHETICFullFlowFixture(self.root)
        f.qualified_python['actual_sys_executable']='/SYNTHETIC-DARWIN/unqualified-alias'
        f.json(f.roles['qualified_python'],f.qualified_python)
        f.reseal_SYNTHETIC_unit_mutation()
        with f.external_boundary_mocks(),self.assertRaisesRegex(ValueError,'Python observation not externally selected'):
            C.check(f.args)

    def test_SYNTHETIC_full_check_negative_extra_current_source(self):
        f=SYNTHETICFullFlowFixture(self.root)
        write(f.current_project/'.mvn/extensions.xml',b'SYNTHETIC unauthorized addition')
        with f.external_boundary_mocks(),self.assertRaises(ValueError):
            C.check(f.args)

    def test_SYNTHETIC_full_check_rejects_coherently_rehashed_unrelated_command(self):
        f=SYNTHETICFullFlowFixture(self.root)
        f.coherently_replace_epoch_argv('private-maven-package',['/SYNTHETIC/unrelated','-o','package'])
        f.reseal_SYNTHETIC_unit_mutation(report_changed=True)
        with f.external_boundary_mocks(),self.assertRaisesRegex(ValueError,'execution/owned drain incomplete'):
            C.check(f.args)

    def test_SYNTHETIC_full_check_rejects_changed_189_overlap_in_selected_output_map(self):
        f=SYNTHETICFullFlowFixture(self.root)
        name=next(iter(f.test_inputs))
        f.checkout['test_outputs'][name]=sha(b'SYNTHETIC unauthorized changed test bytes')
        f.reseal_SYNTHETIC_unit_mutation()
        with f.external_boundary_mocks(),self.assertRaisesRegex(ValueError,'immutable'):
            C.check(f.args)

    def test_SYNTHETIC_full_check_rejects_rehashed_unselected_execution_request(self):
        f=SYNTHETICFullFlowFixture(self.root)
        f.request['execution_window']='SYNTHETIC altered request authority'
        f.json(f.roles['execution_request'],f.request)
        f.reseal_SYNTHETIC_unit_mutation()
        with f.external_boundary_mocks(),self.assertRaisesRegex(ValueError,'execution request not externally selected'):
            C.check(f.args)


if __name__ == '__main__':
    unittest.main(verbosity=2)

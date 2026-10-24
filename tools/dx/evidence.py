#!/usr/bin/env python3
"""Capture and check local Rust evidence. Does not generate or install website files."""
from guards import require
import argparse,copy,datetime,hashlib,json,os,re,shutil,subprocess,tempfile
from pathlib import Path
EXAMPLES = ('minimal_activity', 'independent_participant', 'rule_interpretation',
            'accountable_exception', 'independent_recipient', 'durable_effect')
ROOT=Path(__file__).resolve().parents[2]
KERNEL=ROOT.parent/'ConstitutiveActionKernel'
CARGO=shutil.which('cargo') or str(Path.home()/'.cargo/bin/cargo')
BIN=ROOT/'target/release/tgc-demo'

def command(args,cwd=ROOT,env=None,allowed=(0,)):
 p=subprocess.run([str(a) for a in args],cwd=cwd,env=env,capture_output=True,text=True)
 if p.returncode not in allowed:raise RuntimeError(f'{args}: exit {p.returncode}\n{p.stderr}\n{p.stdout[-3000:]}')
 return p

def read(path):return json.loads(Path(path).read_text())
def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,ensure_ascii=False,separators=(',',':'))+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical_hash(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def no_private(value):
 if isinstance(value,dict):
  require(not set(value)&{'secret','credentials','credential_secret','raw_handle'},'private fixture material in export')
  for v in value.values():no_private(v)
 elif isinstance(value,list):
  for v in value:no_private(v)

def record_snapshot(path):
 state=read(path/'primary/state.json')['value'];r=state['records']['ordinary']
 rail=read(path/'primary/adapter.json')['value'] if (path/'primary/adapter.json').exists() else {}
 return {'record':r,'order':state['order'],'revocations':state['revocations'],'occurrences':len(rail),'replay_occurrence_present':r['ticket']['replay_id'] in rail}


def local_output(path):
 path=path.absolute()
 # No website location, existing symlink or symlinked parent is an output target.
 for parent in [path, *path.parents]:
  # macOS exposes the system temporary roots through these fixed aliases.
  if str(parent) in ('/tmp','/var') and parent.resolve()==Path('/private')/parent.name:
   continue
  require(not parent.is_symlink(), f'Symlink output refused: {parent}')
 resolved=path.resolve()
 website=ROOT.parent/'TheGenerativeCommons'
 require(not resolved.is_relative_to(website.resolve()) and 'www' not in resolved.parts,
         'Evidence output must be outside the website')
 return resolved

def prepare(runs):
 runs=local_output(runs)
 require(not runs.exists(), 'Preparation requires a new run directory; recorded runs are never replaced')
 inputs=preparation_inputs()
 command([CARGO,'build','--offline','--locked','--release','--examples','--bins'])
 command([BIN,'matrix','--out',runs])
 lessons=runs/'lessons';lessons.mkdir()
 for name in EXAMPLES:
  result=command([ROOT/'target/release/examples'/name]);write(lessons/f'{name}.json',json.loads(result.stdout))
 # Test exact source, including the example compilation and host conformance probe.
 test_env=os.environ.copy();test_env['TGC_COVERAGE_EVIDENCE']=str(runs/'coverage-cases')
 tests=command([CARGO,'test','--locked','--offline','--release','--workspace','--all-targets','--no-fail-fast'],env=test_env)
 (runs/'test-results.txt').write_text(tests.stdout+'\n'+tests.stderr)
 kernel_tests=command([CARGO,'test','--locked','--offline','--release','--all-targets','--no-fail-fast'],cwd=KERNEL)
 (runs/'kernel-test-results.txt').write_text(kernel_tests.stdout+'\n'+kernel_tests.stderr)
 command([CARGO,'fmt','--package','tgc-demo','--','--check'])
 k=command([CARGO,'run','--offline','--locked','--example','v1_task_reassignment','--','--demo-json'],cwd=KERNEL)
 write(runs/'kernel-demo.json',json.loads(k.stdout))
 (runs/'kernel-demo-transcript.txt').write_text(command([KERNEL/'target/debug/examples/v1_task_reassignment'],cwd=KERNEL).stdout)
 host=read(lessons/'durable_effect.json')
 for point in ['after-reservation','after-external']:
  path=runs/('crash-'+point);env=os.environ.copy();env['TGC_DEMO_CRASH_AT']=point+':ordinary'
  interrupted=command([BIN,'run','--out',path],env=env,allowed=(86,))
  before=record_snapshot(path);require(before['record']['receipt'] is None, 'Crash fixture already has a receipt')
  command([BIN,'recover',path]);after=record_snapshot(path)
  command([BIN,'recover',path]);again=record_snapshot(path)
  require(after==again and after['record']['ticket']==before['record']['ticket'], 'Recovery changed the reserved attempt')
  require(after['record']['receipt']['outcome'].get('confirmed'), 'Recovery did not confirm the effect')
  require(after['occurrences']==before['occurrences']+int(point=='after-reservation'), 'Unexpected recovered effect count')
  host['cases'].append({'id':point,'title':{'after-reservation':'Process stops after reservation','after-external':'Process stops after external success'}[point],'exit_code':interrupted.returncode,'before':before,'after':after,'after_second_recovery':again,'scope':'Counts include earlier constitution and confirmation effects in this run.'})
 write(runs/'host.json',host)
 seal_preparation(runs,inputs)
 print('Prepared twelve runs, six examples, test transcript and two actual crash recoveries.',flush=True)

def export_run(path,out):
 command([BIN,'verify',path]);report=read(path/'report.json');discovery=read(path/'discovery.json')
 objects={};events=[];actions=[];queues={}
 target=out/'runs'/path.name;target.mkdir(parents=True,exist_ok=True)
 for stream,file in [('primary','events.jsonl'),('peer','peer-events.jsonl')]:
  state=read(path/stream/'state.json')['value'];objects.update(state['objects']);queues[stream]=state['queue']
  raw=[json.loads(line) for line in (path/file).read_text().splitlines()]
  no_private(raw);shutil.copyfile(path/file,target/file)
  for e in raw:
   display=copy.deepcopy(e);display['stream']=stream
   if e['kind']=='decision':
    d=e['data'];objects.update(d['evidence_objects'])
    for field in ['rulebooks','interpretations']:objects.update(d['governance_material'][field])
    display['data'].pop('evidence_objects',None);display['data'].pop('governance_material',None)
    intent=d['intent'];objects[canonical_hash(intent)]=intent;stored=state['records'][intent['proposal_id']]
    # A proposal can have earlier pending decisions. Never attach a later receipt
    # just because its proposal ID matches.
    receipt=next((x['data']['receipt'] for x in raw if x['kind']=='receipt' and x['data']['receipt']['proposal_id']==intent['proposal_id'] and x['data']['receipt']['decision']==d['decision']),None)
    ticket=stored['ticket'] if receipt and stored['decision']==d['decision'] else None
    payload=json.loads(bytes(intent['effect']['canonical_payload']).decode())
    actions.append({'id':f'{stream}:{e["sequence"]}','stream':stream,'sequence':e['sequence'],'beat':e['beat'],'event_hash':e['hash'],'intent':intent,'payload':payload,'decision':d['decision'],'snapshot':d['snapshot'],'proof':d['proof'],'accountable_proof':d['accountable_proof'],'ticket':ticket,'receipt':receipt})
    display['data']={'action_id':actions[-1]['id']}
   events.append(display)
 for field in ['rulebooks','interpretations','commitments','seats']:objects.update(discovery[field])
 for moderator in discovery['moderators']:
  objects[moderator['urn']]=moderator
  objects.setdefault(moderator['lead_urn'],{'lead_urn':moderator['lead_urn'],'published_moderators':[m['urn'] for m in discovery['moderators'] if m['lead_urn']==moderator['lead_urn']],'note':'The activity accepts moderators under its selected Lead. This is a discovery index, not a cryptographic certificate.'})
 objects[discovery['revocation_ref']]={'revocation_epoch':discovery['revocation_epoch'],'revocation_ref':discovery['revocation_ref'],'note':'Simulated Proof of Honesty revocation reference for the recorded issuer epoch.'}
 bundle={'schema_version':1,'id':path.name,'report':report,'discovery':discovery,'objects':objects,'events':events,'actions':actions,'queues_at_completion':queues}
 no_private(bundle);write(target/'run.json',bundle)
 for filename in ['report.json','discovery.json','semantic.json']:shutil.copyfile(path/filename,target/filename)
 a=next(a for a in actions if a['intent']['proposal_id']=='path-accept');promotion=next((a for a in actions if a['intent']['effect']['operation']=='promote'),None)
 return {'id':path.name,'topology':report['config']['topology'],'composition':report['config']['composition'],'downstream':report['config']['downstream'],'semantic_hash':report['semantic_hash'],'constitution_acceptances':len(a['snapshot']['profile']['required_acceptances']),'promotion_acceptances':len(promotion['snapshot']['profile']['required_acceptances']) if promotion else None,'discretionary_onboarding_events':report['primary_metrics']['discretionary_onboarding_events'],'composition_latency_ns':report['primary_metrics']['composition_latency_ns'][0],'sha256':sha(target/'run.json')}

def source_files(root):
 for name in ['.gitignore','Cargo.toml','Cargo.lock','README.md','MANIFEST.md','LICENSE','demo','check']:
  if (root/name).is_file():yield root/name
 for folder in ['src','tests','examples','docs','vendor']:
  if (root/folder).exists():
   for p in sorted((root/folder).rglob('*')):
    if p.is_file() and p.suffix in ['.rs','.md','.json','.toml'] or p.is_file() and p.name=='LICENSE':yield p

def tool_files():
 return [ROOT/'tools/verify.py']+[ROOT/'tools/dx'/name for name in ['evidence.py', 'check_evidence.py', 'guards.py']]

PREPARATION_RECORD='preparation.json'

def preparation_inputs():
 inputs={f'demo/{p.relative_to(ROOT)}':sha(p) for p in set(source_files(ROOT))|set(tool_files())}
 inputs.update({f'kernel/{p.relative_to(KERNEL)}':sha(p) for p in source_files(KERNEL)})
 return inputs

def preparation_binaries():
 binaries={'demo':BIN}
 binaries.update({f'example/{name}':ROOT/'target/release/examples'/name for name in EXAMPLES})
 binaries['kernel-example']=KERNEL/'target/debug/examples/v1_task_reassignment'
 return {name:sha(file) for name,file in binaries.items()}

def preparation_outputs(runs):
 return {p.relative_to(runs).as_posix():sha(p) for p in sorted(runs.rglob('*'))
         if p.is_file() and p != runs/PREPARATION_RECORD}

def seal_preparation(runs, inputs):
 require(preparation_inputs()==inputs, 'Sources changed during preparation; create a fresh run')
 record={'schema_version':1,'prepared_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'inputs':inputs,'binaries':preparation_binaries(),'outputs':preparation_outputs(runs)}
 # A preparation record is created once, never retrofitted to an older run.
 with (runs/PREPARATION_RECORD).open('x') as target:
  json.dump(record,target,sort_keys=True)
 require(preparation_inputs()==inputs, 'Sources changed while sealing preparation')
 return record

def verify_preparation(runs):
 file=runs/PREPARATION_RECORD
 require(file.is_file(), 'Run has no preparation provenance; prepare a new run with the prepare command')
 record=read(file)
 require(record.get('schema_version')==1, 'Unsupported preparation provenance')
 require(record.get('inputs')==preparation_inputs(), 'Prepared run sources differ; prepare a fresh run')
 require(record.get('binaries')==preparation_binaries(), 'Prepared run executables differ; prepare a fresh run')
 require(record.get('outputs')==preparation_outputs(runs), 'Prepared run outputs changed')
 return record

def public_text(text):return text.replace(str(ROOT.parent),'workspace')

def collect_regressions(out,runs):
 # Public test records only. Never publish an issuer registry or input archive.
 data=out
 with tempfile.TemporaryDirectory(prefix='tgc-public-evidence-') as temporary:
  payload=Path(temporary)
  for file in (runs/'coverage-cases').rglob('*'):
   if not file.is_file() or file.suffix not in ['.json','.stdout','.stderr']:continue
   if file.suffix=='.json':no_private(read(file))
   dest=payload/'cases'/file.relative_to(runs/'coverage-cases');dest.parent.mkdir(parents=True,exist_ok=True)
   # JSON records are preserved byte-for-byte; diagnostic text omits machine paths.
   if file.suffix=='.json':shutil.copyfile(file,dest)
   else:dest.write_text(public_text(file.read_text()))
  for filename in ['test-results.txt','kernel-test-results.txt']:
   text=public_text((runs/filename).read_text());(payload/filename).write_text(text);(data/filename).write_text(text)
  (payload/'README.txt').write_text('Recorded regression evidence for the captured Rust implementation. This demo supplies identity and standing through simulated Proof of Honesty. JSON records are unchanged; absolute workspace paths in diagnostic text are normalized. Lock files and private issuer material are excluded. Reproduce with the demo and kernel checkouts beside one another: cargo fetch --locked in each, then python3 tools/verify.py --out /tmp/tgc-regressions-new from TGC-Demo. Workspace and standalone kernel suites overlap. Read docs/validation.md for the current coverage map.\n')
  inventory={str(f.relative_to(payload)):sha(f) for f in sorted(payload.rglob('*')) if f.is_file()}
  index={'schema_version':1,'source':'Local evidence preparation run','case_directories':len(list((runs/'coverage-cases').iterdir())),'governance_crash_cases':len(list((runs/'coverage-cases').glob('crash-*'))),'files':inventory,'policy':'Public JSON unchanged; diagnostic paths normalized; private fixture material and lock files excluded.'}
  write(data/'evidence-index.json',index);write(payload/'evidence-index.json',index)
  shutil.copytree(payload,data/'evidence',dirs_exist_ok=True)
 return index

def collect(runs,out):
 out=local_output(out)
 require(not out.exists(), 'Collection requires a new output directory; existing evidence is never replaced')
 require(not out.is_relative_to(runs.resolve()) and not runs.resolve().is_relative_to(out),
         'Prepared runs and collected evidence must be separate')
 prepared=verify_preparation(runs)
 out.mkdir(parents=True,exist_ok=False)
 data=out
 records=[]
 for topology in ['control','constitutive']:
  for composition in ['reuse','fork']:
   for downstream in ['refuse','honour','unresolved']:
    records.append(export_run(runs/f'{topology}-{composition}-{downstream}',out))
 print('Verified every branch and assembled public records.',flush=True)
 outputs={name:read(runs/'lessons'/f'{name}.json') for name in EXAMPLES}
 for name,value in outputs.items():no_private(value);write(data/'examples'/f'{name}.json',value)
 host=read(runs/'host.json');no_private(host);write(data/'host.json',host)
 evidence=collect_regressions(out,runs)
 transcript=(runs/'test-results.txt').read_text();passed=sum(map(int,re.findall(r'test result: ok\. (\d+) passed',transcript)))
 require('FAILED' not in transcript and passed>0, 'Workspace transcript has no passing suite or contains failures')
 kernel_transcript=(runs/'kernel-test-results.txt').read_text();kernel_passed=sum(map(int,re.findall(r'test result: ok\. (\d+) passed',kernel_transcript)))
 require('FAILED' not in kernel_transcript and kernel_passed>0, 'Kernel transcript has no passing suite or contains failures')
 all_sources={name.removeprefix('demo/'):digest for name,digest in prepared['inputs'].items() if name.startswith('demo/')}
 manifest={'schema_version':1,'validation':{'workspace_passed':passed,'kernel_passed':kernel_passed,'case_directories':evidence['case_directories'],'governance_crash_cases':evidence['governance_crash_cases']},'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runs':records,'tests':{'summary':f'{passed} tests passed; six asserted examples executed; two process crash gaps recovered','transcript_sha256':sha(data/'test-results.txt')},'kernel':read(ROOT/'vendor/kernel-source.json'),'source_sha256':all_sources,'private_fixture_policy':'Only explicit event/discovery/report fields are exported. No private issuer files or credential registry.','execution':'Recorded native Rust. Browser code only selects and presents results.'}
 manifest['prepared_at']=prepared['prepared_at']
 manifest['preparation_sha256']=sha(runs/PREPARATION_RECORD)

 manifest['downloads']={}
 write(data/'manifest.json',manifest)
 for filename in ['kernel-demo.json','kernel-demo-transcript.txt']:
  shutil.copyfile(runs/filename,out/filename)
 require(verify_preparation(runs)==prepared, 'Preparation changed during collection')
 from check_evidence import check
 check(out)
 print(f'Evidence collected at {out}; no website files generated.',flush=True)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 sub=parser.add_subparsers(dest='command',required=True)
 prepare_cmd=sub.add_parser('prepare',help='Capture fresh runs, tests, examples and crash recovery')
 prepare_cmd.add_argument('--runs',type=Path,required=True)
 collect_cmd=sub.add_parser('collect',help='Verify preparation and assemble individual public evidence')
 collect_cmd.add_argument('--runs',type=Path,required=True)
 collect_cmd.add_argument('--out',type=Path,required=True)
 args=parser.parse_args()
 if args.command=='prepare':prepare(args.runs.absolute())
 else:collect(args.runs.resolve(),args.out.absolute())

if __name__=='__main__':main()

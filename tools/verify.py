#!/usr/bin/env python3
"""Capture the current container and kernel validation with retained test case stores.
All commands must pass. Place the demo and Kernel checkouts beside one another.
"""
import argparse,hashlib,json,os,re,subprocess,tarfile
from pathlib import Path
from dx.guards import require
HERE=Path(__file__).resolve().parent; ROOT=HERE.parent; KERNEL=ROOT.parent/'ConstitutiveActionKernel'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
env=dict(os.environ);env['PATH']=str(Path.home()/'.cargo/bin')+os.pathsep+env.get('PATH','')
for key in ['TGC_DEMO_CRASH_AT','TGC_COVERAGE_CHILD_ROOT','TGC_ASSERT_LEGACY_POLICY']:env.pop(key,None)
env['TGC_COVERAGE_EVIDENCE']=str(out/'cases')
files={}
for base,label in [(ROOT,'demo'),(KERNEL,'kernel')]:
 for folder in ['src','tests','vendor','examples','docs']:
  for f in (base/folder).rglob('*'):
   if f.is_file() and 'target' not in f.parts:files[f'{label}/{f.relative_to(base)}']=f
 for name in ['Cargo.toml','Cargo.lock','README.md','check']:
  if (base/name).exists():files[f'{label}/{name}']=base/name
fingerprints=lambda:{k:hashlib.sha256(f.read_bytes()).hexdigest() for k,f in sorted(files.items())}
before=fingerprints();(out/'inputs.sha256.json').write_text(json.dumps(before,indent=2)+'\n')
with tarfile.open(out/'inputs.tar.gz','w:gz') as archive:
 for name,f in files.items():archive.add(f,arcname=name)
commands=[]
def run(name,cmd,cwd=ROOT):
 r=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True)
 (out/(name+'.stdout')).write_text(r.stdout);(out/(name+'.stderr')).write_text(r.stderr)
 counts=[tuple(map(int,c)) for c in re.findall(r'test result: .*? (\d+) passed; (\d+) failed; (\d+) ignored;',r.stdout)]
 item={'name':name,'command':list(map(str,cmd)),'cwd':str(cwd),'exit_code':r.returncode,'passed':sum(c[0] for c in counts),'failed':sum(c[1] for c in counts),'ignored':sum(c[2] for c in counts)}
 commands.append(item);(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');print(json.dumps(item),flush=True)
 return r.returncode
run('format',['cargo','fmt','--all','--','--check'])
run('kernel-format',['cargo','fmt','--all','--','--check'],KERNEL)
run('workspace',['cargo','test','--locked','--offline','--release','--workspace','--all-targets','--no-fail-fast','--','--nocapture'])
run('kernel',['cargo','test','--locked','--offline','--release','--all-targets','--no-fail-fast','--','--nocapture'],KERNEL)
for example in ['minimal_activity','accountable_exception','independent_participant','independent_recipient','rule_interpretation','durable_effect']:
 run('example-'+example,['cargo','run','--locked','--offline','--release','--example',example])
summary={'all_commands_pass':all(c['exit_code']==0 for c in commands),'inputs_unchanged_during_run':before==fingerprints(),'kernel_sources_match':all((ROOT/'vendor/constitutive-action/src'/f).read_bytes()==(KERNEL/'src'/f).read_bytes() for f in ['lib.rs','v1.rs','host_conformance.rs']),'case_directories':len(list((out/'cases').glob('*'))),'commands':commands}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
require(summary['all_commands_pass'] and summary['inputs_unchanged_during_run'] and summary['kernel_sources_match'],summary)
